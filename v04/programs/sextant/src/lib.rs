//! sextant_lc on LEZ v0.4 (the actor model): an Ethereum light client inside
//! a LEZ program, and the consumer check against what it verified.
//!
//! The light client is the one `programs/sextant` runs on LEZ v0.3: the same
//! sextant-core checks, the same three-step update (decision D2), the same
//! accounts and the same `E72xx` refusal codes. What changes is the shell.
//! v0.3 ran a `plan` over a list of account rows and an `apply` per effect;
//! v0.4 runs **one message to one actor** (an account paired with this
//! program), which may change only that actor's state and reaches any other
//! state by sending it a message (docs/V04.md).
//!
//! Actors (all PDAs of this program, the same derivations as v0.3):
//!
//! - **instance** `[instance_id]`: the chain configuration fixed at `Init`
//!   and the tracked store. It reads its own state, so `Begin` no longer
//!   carries the instance: it carries only the digest the operator built
//!   against (`E7293` if the instance moved on).
//! - **job** `sha256("job" ‖ instance_id ‖ job_id)`: one update's
//!   verification in progress. It now holds the instance the update leads to,
//!   so `Finish` carries nothing but the job's address.
//! - **header** `sha256("header" ‖ instance_id ‖ slot)`: an immutable record
//!   of each finalized header. `Attest` is a message to it.
//!
//! Message flow (`→` a synchronous message: same transaction, a refusal
//! anywhere fails the whole transaction):
//!
//! ```text
//! Init    root → instance(Init)   → header(Record)
//! Begin   root → instance(Begin)  → job(Open)          every check but the pairing
//! Miller  root → job(Miller)                           the two Miller loops
//! Finish  root → job(Finish)      → instance(Advance) → header(Record)
//!                  final exponentiation; the job is spent
//! Attest  root or a consumer → header(Attest)
//! ```
//!
//! `Open`, `Advance` and `Record` are accepted only from another actor of
//! this program (`ReceiveInput::from_own_program`): no transaction and no
//! other program can write an instance, a job or a record directly.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, Actor},
    program::{PdaSeed, ProgramEvent, ReceiveInput, Response, SyncMessage},
};
use risc0_zkvm::sha::{Impl, Sha256 as _};
use sextant_core::lc::{self, Prepared};
use sextant_core::statement::{self, HeaderRecord, Query};
use sextant_core::{bl, ChainConfig, Error, KeyWitness, LcHeader, Store, SyncCommittee, Update};

pub const E_BASE: u32 = 7200;
pub const E_ACCOUNTS: u32 = 7290;
pub const E_EXISTS: u32 = 7291;
pub const E_NO_INSTANCE: u32 = 7292;
pub const E_STALE: u32 = 7293;
pub const E_NO_JOB: u32 = 7294;
pub const E_JOB_STEP: u32 = 7295;

#[track_caller]
pub fn refuse(code: u32, why: &str) -> ! {
    panic!("E{code}: {why}")
}

#[track_caller]
fn refuse_unless(ok: bool, code: u32, why: &str) {
    if !ok {
        refuse(code, why);
    }
}

/// A verification refusal from sextant-core, as `E72xx`.
#[track_caller]
pub fn refuse_with(e: Error) -> ! {
    refuse(E_BASE + e as u32, message(e))
}

/// The actionable text of every typed refusal (U.5), as on v0.3.
pub fn message(e: Error) -> &'static str {
    match e {
        Error::Malformed => "malformed input: re-fetch the update or proof and rebuild the message",
        Error::NotFinalized => "header not finalized: the finality branch does not place it in the attested state; wait for finality and fetch a newer update",
        Error::BadSignature => "sync-committee signature invalid for this header, domain and participation bits",
        Error::HandoffNotVerified => "committee handoff not verified: submit the update of the missing period first",
        Error::BelowParticipation => "sync-committee participation below the instance's floor; wait for a better-signed update",
        Error::CheckpointStale => "checkpoint stale or outside the weak-subjectivity period: initialise a fresh instance",
        Error::BadInclusion => "inclusion proof invalid against the recorded header's root",
        Error::PredicateFalse => "predicate not satisfied by the attested state",
        Error::ChainMismatch => "chain-ID mismatch: the record belongs to another chain's instance",
        Error::AlreadyApplied => "update already applied: another operator was first, nothing to do",
        Error::BadExecutionBranch => "execution payload header does not match the beacon body root",
        Error::BadCommitteeBranch => "sync committee not in the attested state",
        Error::CommitteeMismatch => "the supplied committee is not the one the instance tracks",
        Error::BadKey => "a committee key witness does not match the committed key",
        Error::CheckpointMismatch => "the bootstrap header does not hash to the checkpoint",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Instance {
    pub checkpoint: [u8; 32],
    pub cfg: ChainConfig,
    pub store: Store,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Job {
    pub instance_id: [u8; 32],
    /// Digest of the instance the update starts from.
    pub prev: [u8; 32],
    /// The instance it leads to (v0.3 kept only its digest; Finish carried it).
    pub next: Instance,
    pub pk: Vec<u8>,
    pub hm: Vec<u8>,
    pub sig: Vec<u8>,
    /// The Miller-loop product, once step 2 has run.
    pub f: Option<Vec<u8>>,
}

/// What a transaction (or another program) may send.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Message {
    /// To the header actor of `(instance_id, slot)`: refuses unless `query`
    /// holds against the record. Variant 0, so a consumer can encode it with
    /// a one-variant enum of its own.
    Attest { instance_id: [u8; 32], slot: u64, query: Query },
    /// To the instance actor. Anyone; writes once.
    Init { instance_id: [u8; 32], checkpoint: [u8; 32], cfg: ChainConfig, header: LcHeader, committee: SyncCommittee, branch: Vec<[u8; 32]> },
    /// To the instance actor. `current` is the digest of the instance the
    /// operator built the update against.
    Begin { instance_id: [u8; 32], current: [u8; 32], update: Update, committee: SyncCommittee, witness: KeyWitness },
    /// To the job actor.
    Miller { instance_id: [u8; 32], job_id: [u8; 32] },
    /// To the job actor.
    Finish { instance_id: [u8; 32], job_id: [u8; 32] },
}

/// What only this program's own actors send each other.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Internal {
    /// Instance to job.
    Open { job_id: [u8; 32], job: Job },
    /// Job to instance: the job verified the transition `prev` to `next`.
    Advance { instance_id: [u8; 32], prev: [u8; 32], next: Instance },
    /// Instance to header.
    Record { instance_id: [u8; 32], record: HeaderRecord },
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    Impl::hash_bytes(&buf).as_bytes().try_into().expect("32 bytes")
}

pub fn digest<T: BorshSerialize>(t: &T) -> [u8; 32] {
    sha256(&[&borsh::to_vec(t).expect("infallible")])
}

pub fn instance_seed(instance_id: &[u8; 32]) -> PdaSeed {
    PdaSeed::new(*instance_id)
}

pub fn job_seed(instance_id: &[u8; 32], job_id: &[u8; 32]) -> PdaSeed {
    PdaSeed::new(sha256(&[b"job", instance_id, job_id]))
}

pub fn header_seed(instance_id: &[u8; 32], slot: u64) -> PdaSeed {
    PdaSeed::new(sha256(&[b"header", instance_id, &slot.to_le_bytes()]))
}

pub fn instance_account(me: &AccountId, instance_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(me, &instance_seed(instance_id))
}

/// The job of an update, keyed by the instance it starts from and the update
/// (as on v0.3: `sha256(digest(current) ‖ digest(update))`).
pub fn job_id_of(current: &[u8; 32], update: &Update) -> [u8; 32] {
    sha256(&[current, &digest(update)])
}

pub fn job_id(current: &Instance, update: &Update) -> [u8; 32] {
    job_id_of(&digest(current), update)
}

pub fn job_account(me: &AccountId, instance_id: &[u8; 32], job_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(me, &job_seed(instance_id, job_id))
}

pub fn header_account(me: &AccountId, instance_id: &[u8; 32], slot: u64) -> AccountId {
    AccountId::for_public_pda(me, &header_seed(instance_id, slot))
}

pub fn record(cfg: &ChainConfig, s: &Store) -> HeaderRecord {
    HeaderRecord {
        chain_id: cfg.chain_id,
        slot: s.finalized.slot,
        beacon_root: sextant_core::ssz::beacon_header_root(&s.finalized),
        block_number: s.finalized_block_number,
        state_root: s.finalized_execution_state_root,
        receipts_root: s.finalized_receipts_root,
    }
}

// ---- events ----

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Advanced {
    pub instance_id: [u8; 32],
    pub slot: u64,
    pub period: u64,
    pub block_number: u64,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct JobStep {
    pub instance_id: [u8; 32],
    pub job_id: [u8; 32],
    pub step: u8,
}

pub fn event<T: BorshSerialize>(name: &str, body: &T) -> ProgramEvent {
    let sel = sha256(&[b"sextant_lc::", name.as_bytes()]);
    ProgramEvent { selector: sel[..8].try_into().expect("8 bytes"), data: borsh::to_vec(body).expect("infallible") }
}

// ---- the actor ----

fn put<T: BorshSerialize>(t: &T) -> Vec<u8> {
    borsh::to_vec(t).expect("infallible")
}

fn at(input: &ReceiveInput, id: AccountId, what: &str) {
    refuse_unless(input.receiver.account_id == id, E_ACCOUNTS, what);
}

fn to_header(me: AccountId, instance_id: [u8; 32], r: HeaderRecord) -> SyncMessage {
    let slot = r.slot;
    SyncMessage::new(Actor::new(header_account(&me, &instance_id, slot), me), &Internal::Record { instance_id, record: r }).with_pda_seeds([header_seed(&instance_id, slot)])
}

/// The whole program: one message to one actor.
pub fn handle_message(input: &ReceiveInput) -> Response {
    let me = input.receiver.program_account_id;
    if input.from_own_program() {
        let m: Internal = borsh::from_slice(&input.message).expect("an internal message");
        return internal(input, me, m);
    }
    let m: Message = borsh::from_slice(&input.message).unwrap_or_else(|_| refuse_with(Error::Malformed));
    let pre: &[u8] = &input.pre_state;
    match m {
        Message::Init { instance_id, checkpoint, cfg, header, committee, branch } => {
            at(input, instance_account(&me, &instance_id), "Init goes to the instance PDA of this id");
            refuse_unless(pre.is_empty(), E_EXISTS, "an instance already exists at this id; choose another id");
            let store = lc::bootstrap(&cfg, &checkpoint, &header, &committee, &branch).unwrap_or_else(|e| refuse_with(e));
            refuse_unless(cfg.min_participants as usize * 3 >= 512 * 2 && cfg.min_participants <= 512, E_BASE + Error::Malformed as u32, "the participation floor must be at least two thirds of 512");
            refuse_unless(cfg.max_checkpoint_age > 0, E_BASE + Error::Malformed as u32, "the weak-subjectivity bound must be positive");
            let r = record(&cfg, &store);
            // A checkpoint already older than the bound is refused by the sequencer's clock.
            let stale = lc::stale_from_ms(&cfg, store.finalized.slot);
            Response::set_state(put(&Instance { checkpoint, cfg, store })).timestamp_window(..stale).send(to_header(me, instance_id, r))
        }
        Message::Begin { instance_id, current, update, committee, witness } => {
            at(input, instance_account(&me, &instance_id), "Begin goes to the instance PDA of this id");
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no instance at this id");
            refuse_unless(sha256(&[pre]) == current, E_STALE, "the instance moved on since this update was built: rebuild it against the current store");
            let inst: Instance = borsh::from_slice(pre).expect("an instance");
            let p: Prepared = lc::prepare(&inst.cfg, &inst.store, &update, &committee, &witness, lc::FAST, &mut |_| {}).unwrap_or_else(|e| refuse_with(e));
            let jid = job_id_of(&current, &update);
            let stale = lc::stale_from_ms(&inst.cfg, inst.store.finalized.slot);
            let next = Instance { store: p.next, ..inst };
            let job = Job { instance_id, prev: current, next, pk: p.pk, hm: p.hm, sig: p.sig, f: None };
            let to = Actor::new(job_account(&me, &instance_id, &jid), me);
            Response::keep_state()
                .timestamp_window(..stale)
                .send(SyncMessage::new(to, &Internal::Open { job_id: jid, job }).with_pda_seeds([job_seed(&instance_id, &jid)]))
                .event(event("JobStep", &JobStep { instance_id, job_id: jid, step: 1 }))
        }
        Message::Miller { instance_id, job_id } => {
            at(input, job_account(&me, &instance_id, &job_id), "Miller goes to the job PDA");
            refuse_unless(!pre.is_empty(), E_NO_JOB, "no such job: send Begin first");
            let mut j: Job = borsh::from_slice(pre).expect("a job");
            refuse_unless(j.f.is_none(), E_JOB_STEP, "the Miller step of this job is done: send Finish");
            let f = bl::miller(j.pk.as_slice().try_into().unwrap(), j.hm.as_slice().try_into().unwrap(), j.sig.as_slice().try_into().unwrap())
                .unwrap_or_else(|| refuse_with(Error::Malformed));
            j.f = Some(f.to_vec());
            Response::set_state(put(&j)).event(event("JobStep", &JobStep { instance_id, job_id, step: 2 }))
        }
        Message::Finish { instance_id, job_id } => {
            at(input, job_account(&me, &instance_id, &job_id), "Finish goes to the job PDA");
            refuse_unless(!pre.is_empty(), E_NO_JOB, "no such job: send Begin first");
            let j: Job = borsh::from_slice(pre).expect("a job");
            let f = j.f.as_ref().unwrap_or_else(|| refuse(E_JOB_STEP, "the Miller step of this job has not run: send Miller"));
            if !bl::final_is_one(f.as_slice().try_into().unwrap()) {
                refuse_with(Error::BadSignature);
            }
            let to = Actor::new(instance_account(&me, &instance_id), me);
            // The job is spent; its storage is released.
            Response::set_state(Vec::<u8>::new()).send(SyncMessage::new(to, &Internal::Advance { instance_id, prev: j.prev, next: j.next }).with_pda_seeds([instance_seed(&instance_id)]))
        }
        Message::Attest { instance_id, slot, query } => {
            at(input, header_account(&me, &instance_id, slot), "Attest goes to the header PDA of this instance and slot");
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no header recorded at this slot");
            let r: HeaderRecord = borsh::from_slice(pre).expect("a header record");
            // No event: the statement is the consumer's to expose (F.8).
            statement::evaluate(&r, &query).unwrap_or_else(|e| refuse_with(e));
            Response::keep_state()
        }
    }
}

fn internal(input: &ReceiveInput, me: AccountId, m: Internal) -> Response {
    let pre: &[u8] = &input.pre_state;
    match m {
        Internal::Open { job_id, job: j } => {
            at(input, job_account(&me, &j.instance_id, &job_id), "a job goes to the job PDA of its id");
            let new = put(&j);
            refuse_unless(pre.is_empty() || pre == new.as_slice(), E_EXISTS, "this job is already open: continue it with Miller and Finish");
            if pre.is_empty() { Response::set_state(new) } else { Response::keep_state() }
        }
        Internal::Advance { instance_id, prev, next } => {
            at(input, instance_account(&me, &instance_id), "Advance goes to the instance PDA of this id");
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no instance at this id");
            refuse_unless(sha256(&[pre]) == prev, E_STALE, "the instance moved on: another operator applied an update first");
            let current: Instance = borsh::from_slice(pre).expect("an instance");
            let stale = lc::stale_from_ms(&current.cfg, current.store.finalized.slot);
            let r = record(&next.cfg, &next.store);
            let ev = Advanced { instance_id, slot: r.slot, period: lc::period(r.slot), block_number: r.block_number };
            Response::set_state(put(&next)).timestamp_window(..stale).send(to_header(me, instance_id, r)).event(event("Advanced", &ev))
        }
        Internal::Record { instance_id, record } => {
            at(input, header_account(&me, &instance_id, record.slot), "a record goes to the header PDA of its slot");
            let new = put(&record);
            refuse_unless(pre.is_empty() || pre == new.as_slice(), E_EXISTS, "a different record exists for this slot");
            Response::set_state(new)
        }
    }
}
