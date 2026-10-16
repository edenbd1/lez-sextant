//! sextant_lc on LEZ v0.3: an Ethereum light client inside a LEZ program,
//! and the consumer check against what it verified.
//!
//! Accounts (all PDAs of this program):
//!
//! - **instance** `[instance_id]`: the chain configuration fixed at `Init`
//!   (checkpoint, chain id, genesis validators root, fork schedule,
//!   participation floor) and the tracked store. No instruction rewrites the
//!   configuration (F.9, F.13); `Advance` replaces only the store.
//! - **job** `sha256("job" ‖ instance_id ‖ job_id)`: one update's
//!   verification in progress. A sync-committee update costs 11 to 13 million
//!   cycles, more than one transaction may use, so it is verified in three
//!   transactions (decision D2): `Begin` runs every check but the pairing and
//!   opens the job; `Miller` runs the two Miller loops; `Finish` runs the final
//!   exponentiation and, in the same transaction, advances the store. Anyone
//!   can send any step (F.11); a job is keyed by the store it starts from and
//!   the update, so a stale job can never land (R.8).
//! - **header** `sha256("header" ‖ instance_id ‖ slot)`: an immutable record
//!   of each finalized header, its execution state root and receipts root.
//!   Consumers read only these (`Attest`), so a consumer's proof is never
//!   invalidated by a later update (R.3, R.11).
//!
//! A v0.3 `plan` cannot read accounts, so it does the pure work on what the
//! instruction carries and hands `apply` digests to check against stored
//! bytes; any mismatch panics, which fails the whole transaction.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::AccountId,
    program::{AccountMeta, PdaSeed, Plan, PlanInput, ProgramEvent},
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

/// The actionable text of every typed refusal (U.5).
pub fn message(e: Error) -> &'static str {
    match e {
        Error::Malformed => "malformed input: re-fetch the update or proof and rebuild the instruction",
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
    /// Digest of the instance the update starts from.
    pub prev: [u8; 32],
    /// Digest of the instance it leads to.
    pub next: [u8; 32],
    pub pk: Vec<u8>,
    pub hm: Vec<u8>,
    pub sig: Vec<u8>,
    /// The Miller-loop product, once step 2 has run.
    pub f: Option<Vec<u8>>,
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Rows: [instance, header]. Anyone; writes once.
    Init { instance_id: [u8; 32], checkpoint: [u8; 32], cfg: ChainConfig, header: LcHeader, committee: SyncCommittee, branch: Vec<[u8; 32]> },
    /// Rows: [instance, job].
    Begin { instance_id: [u8; 32], current: Instance, update: Update, committee: SyncCommittee, witness: KeyWitness },
    /// Rows: [job].
    Miller { instance_id: [u8; 32], job_id: [u8; 32] },
    /// Rows: [instance, job, header].
    Finish { instance_id: [u8; 32], job_id: [u8; 32], current: Instance, next: Store },
    /// Rows: [header]. The consumer check: refuses unless `query` holds.
    Attest { instance_id: [u8; 32], slot: u64, query: Query },
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    Create(Instance),
    Record(HeaderRecord),
    /// The account holds exactly the instance with this digest.
    Expect([u8; 32]),
    Open(Job),
    Miller,
    /// Final exponentiation is one, and the job runs `prev` to `next`.
    Close { prev: [u8; 32], next: [u8; 32] },
    Advance { prev: [u8; 32], next: Instance },
    Check(Query),
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

pub fn instance_account(me: &AccountId, instance_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(me, &PdaSeed::new(*instance_id))
}

pub fn job_id(current: &Instance, update: &Update) -> [u8; 32] {
    sha256(&[&digest(current), &digest(update)])
}

pub fn job_account(me: &AccountId, instance_id: &[u8; 32], job_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(me, &PdaSeed::new(sha256(&[b"job", instance_id, job_id])))
}

pub fn header_account(me: &AccountId, instance_id: &[u8; 32], slot: u64) -> AccountId {
    AccountId::for_public_pda(me, &PdaSeed::new(sha256(&[b"header", instance_id, &slot.to_le_bytes()])))
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

// ---- events (LP-0012) ----

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

fn event<T: BorshSerialize>(name: &str, body: &T) -> ProgramEvent {
    let sel = sha256(&[b"sextant_lc::", name.as_bytes()]);
    ProgramEvent { selector: sel[..8].try_into().expect("8 bytes"), data: borsh::to_vec(body).expect("infallible") }
}

// ---- plan ----

fn rows<const N: usize>(input: &PlanInput) -> [AccountMeta; N] {
    <[AccountMeta; N]>::try_from(input.accounts.clone()).unwrap_or_else(|_| refuse(E_ACCOUNTS, "wrong number of accounts for this instruction"))
}

fn expect_own(row: &AccountMeta, me: &AccountId, id: AccountId, what: &str) {
    refuse_unless(row.account_id == id && row.program_account_id == *me, E_ACCOUNTS, what);
}

#[must_use]
pub fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let me = input.self_account_id;
    let mut plan = Plan::new(input);
    match ix {
        Instruction::Init { instance_id, checkpoint, cfg, header, committee, branch } => {
            let [inst, hdr] = rows::<2>(input);
            expect_own(&inst, &me, instance_account(&me, &instance_id), "the first row is the instance PDA");
            let store = lc::bootstrap(&cfg, &checkpoint, &header, &committee, &branch).unwrap_or_else(|e| refuse_with(e));
            refuse_unless(cfg.min_participants as usize * 3 >= 512 * 2 && cfg.min_participants <= 512, E_BASE + Error::Malformed as u32, "the participation floor must be at least two thirds of 512");
            let r = record(&cfg, &store);
            expect_own(&hdr, &me, header_account(&me, &instance_id, r.slot), "the second row is the checkpoint's header PDA");
            plan.effect(&inst, &Effect::Create(Instance { checkpoint, cfg, store }));
            plan.effect(&hdr, &Effect::Record(r));
        }
        Instruction::Begin { instance_id, current, update, committee, witness } => {
            let [inst, job] = rows::<2>(input);
            expect_own(&inst, &me, instance_account(&me, &instance_id), "the first row is the instance PDA");
            let id = job_id(&current, &update);
            expect_own(&job, &me, job_account(&me, &instance_id, &id), "the second row is this update's job PDA");
            let p: Prepared = lc::prepare(&current.cfg, &current.store, &update, &committee, &witness, lc::FAST, &mut |_| {}).unwrap_or_else(|e| refuse_with(e));
            let next = Instance { store: p.next, ..current.clone() };
            plan.effect(&inst, &Effect::Expect(digest(&current)));
            plan.effect(&job, &Effect::Open(Job { prev: digest(&current), next: digest(&next), pk: p.pk, hm: p.hm, sig: p.sig, f: None }));
            plan.event(event("JobStep", &JobStep { instance_id, job_id: id, step: 1 }));
        }
        Instruction::Miller { instance_id, job_id } => {
            let [job] = rows::<1>(input);
            expect_own(&job, &me, job_account(&me, &instance_id, &job_id), "the row is the job PDA");
            plan.effect(&job, &Effect::Miller);
            plan.event(event("JobStep", &JobStep { instance_id, job_id, step: 2 }));
        }
        Instruction::Finish { instance_id, job_id, current, next } => {
            let [inst, job, hdr] = rows::<3>(input);
            expect_own(&inst, &me, instance_account(&me, &instance_id), "the first row is the instance PDA");
            expect_own(&job, &me, job_account(&me, &instance_id, &job_id), "the second row is the job PDA");
            let next = Instance { store: next, ..current.clone() };
            let r = record(&next.cfg, &next.store);
            expect_own(&hdr, &me, header_account(&me, &instance_id, r.slot), "the third row is the new header's PDA");
            plan.effect(&job, &Effect::Close { prev: digest(&current), next: digest(&next) });
            plan.effect(&inst, &Effect::Advance { prev: digest(&current), next: next.clone() });
            plan.effect(&hdr, &Effect::Record(r.clone()));
            plan.event(event(
                "Advanced",
                &Advanced { instance_id, slot: r.slot, period: lc::period(r.slot), block_number: r.block_number },
            ));
        }
        Instruction::Attest { instance_id, slot, query } => {
            let [hdr] = rows::<1>(input);
            expect_own(&hdr, &me, header_account(&me, &instance_id, slot), "the row is the header PDA");
            // No event: the statement is the consumer's to expose (F.8).
            plan.effect(&hdr, &Effect::Check(query));
        }
    }
    plan
}

// ---- apply ----

fn put<T: BorshSerialize>(t: &T) -> Vec<u8> {
    borsh::to_vec(t).expect("infallible")
}

#[must_use]
pub fn apply(effect: Effect, pre: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::Create(i) => {
            refuse_unless(pre.is_empty(), E_EXISTS, "an instance already exists at this id; choose another id");
            Some(put(&i))
        }
        Effect::Record(r) => {
            let new = put(&r);
            refuse_unless(pre.is_empty() || pre == new.as_slice(), E_EXISTS, "a different record exists for this slot");
            Some(new)
        }
        Effect::Expect(d) => {
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no instance at this id");
            refuse_unless(sha256(&[pre]) == d, E_STALE, "the instance moved on since this update was built: rebuild it against the current store");
            None
        }
        Effect::Open(j) => {
            let new = put(&j);
            refuse_unless(pre.is_empty() || pre == new.as_slice(), E_EXISTS, "this job is already open: continue it with Miller and Finish");
            if pre.is_empty() { Some(new) } else { None }
        }
        Effect::Miller => {
            refuse_unless(!pre.is_empty(), E_NO_JOB, "no such job: send Begin first");
            let mut j: Job = borsh::from_slice(pre).expect("a job");
            refuse_unless(j.f.is_none(), E_JOB_STEP, "the Miller step of this job is done: send Finish");
            let f = bl::miller(j.pk.as_slice().try_into().unwrap(), j.hm.as_slice().try_into().unwrap(), j.sig.as_slice().try_into().unwrap())
                .unwrap_or_else(|| refuse_with(Error::Malformed));
            j.f = Some(f.to_vec());
            Some(put(&j))
        }
        Effect::Close { prev, next } => {
            refuse_unless(!pre.is_empty(), E_NO_JOB, "no such job: send Begin first");
            let j: Job = borsh::from_slice(pre).expect("a job");
            let f = j.f.as_ref().unwrap_or_else(|| refuse(E_JOB_STEP, "the Miller step of this job has not run: send Miller"));
            refuse_unless(j.prev == prev && j.next == next, E_STALE, "this job verifies another transition");
            if !bl::final_is_one(f.as_slice().try_into().unwrap()) {
                refuse_with(Error::BadSignature);
            }
            Some(vec![]) // the job is spent; its storage is released
        }
        Effect::Advance { prev, next } => {
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no instance at this id");
            refuse_unless(sha256(&[pre]) == prev, E_STALE, "the instance moved on: another operator applied an update first");
            Some(put(&next))
        }
        Effect::Check(q) => {
            refuse_unless(!pre.is_empty(), E_NO_INSTANCE, "no header recorded at this slot");
            let r: HeaderRecord = borsh::from_slice(pre).expect("a header record");
            statement::evaluate(&r, &q).unwrap_or_else(|e| refuse_with(e));
            None
        }
    }
}
