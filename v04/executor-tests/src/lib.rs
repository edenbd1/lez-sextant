//! A one-node LEZ v0.4.0-rc3 chain in memory, for the v0.4 sextant_lc binary.
//!
//! Transactions are signed `PublicTransaction`s and go through
//! `ValidatedStateDiff::from_public_transaction_metered`, the call the
//! sequencer's settlement makes for a charged transaction
//! (`lez/chain_state/src/apply.rs`, `settle_charged_transaction`), then
//! `V03State::apply_state_diff`. Every actor run is a RISC Zero executor
//! session; the transaction is charged their cycles. A refusal is a
//! *revert*: the transaction stays, its effects do not.

use std::path::{Path, PathBuf};

use borsh::BorshSerialize;
use lee::{
    program::Program,
    public_transaction::{Message, WitnessSet},
    AccountId, Actor, PrivateKey, PublicAccountEvidence, PublicKey, PublicTransaction, V03State, ValidatedStateDiff,
};
use lee_core::program::{PdaSeed, TransactionEvent};
use sextant_core::lc::{self, AggMode};
use sextant_core::{SyncCommittee, Update};
use sextant_host::{witness, Mainnet};
use sextant_program_v04::{
    digest, header_account, instance_account, instance_seed, job_account, job_id_of, Instance, Job, Message as M,
};

/// `MAX_GAS_EXEC`, the most execution gas one block (so one transaction) may use.
pub const GAS_CAP: u64 = 10_000_000;

/// The header account the tests deploy the program at.
pub const LC: AccountId = AccountId::new(*b"sextant_lc/v0.4/test/header/0001");

pub fn root_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

pub fn bin_path() -> PathBuf {
    std::env::var("SEXTANT_BIN").map(PathBuf::from).unwrap_or_else(|_| root_dir().join("v04/artifacts/sextant_lc.bin"))
}

pub fn bin() -> Vec<u8> {
    let p = bin_path();
    std::fs::read(&p).unwrap_or_else(|_| panic!("missing {}: v04/scripts/build-guests.sh", p.display()))
}

/// A key with no prior relationship to anything.
pub struct Key {
    pub sk: PrivateKey,
    pub pk: PublicKey,
    pub id: AccountId,
}

impl Key {
    #[must_use]
    pub fn new(seed: u16) -> Self {
        let mut b = [0x5a; 32];
        b[..2].copy_from_slice(&seed.to_le_bytes());
        let sk = PrivateKey::try_new(b).expect("a valid secp256k1 scalar");
        let pk = PublicKey::new_from_private_key(&sk);
        let id = AccountId::from(&pk);
        Self { sk, pk, id }
    }
}

/// One transaction's charge and events.
#[derive(Debug)]
pub struct Outcome {
    pub cycles: u64,
    pub events: Vec<TransactionEvent>,
}

pub struct Chain {
    pub state: V03State,
    pub block: u64,
    pub now: u64,
    /// (label, cycles charged, applied)
    pub log: Vec<(String, u64, bool)>,
    next_key: u16,
}

impl Chain {
    #[must_use]
    pub fn new() -> Self {
        let program = Program::new(bin().into()).expect("a RISC0 program binary");
        let state = V03State::new().with_named_programs([(LC, program)]);
        Self { state, block: 10, now: 1_760_000_000_000, log: vec![], next_key: 1 }
    }

    /// Deploy another program binary at `id` (a consumer).
    #[must_use]
    pub fn with_program(mut self, id: AccountId, bin: Vec<u8>) -> Self {
        self.state = self.state.with_named_programs([(id, Program::new(bin.into()).expect("a RISC0 program binary"))]);
        self
    }

    /// A brand-new key: a relayer with no role (F.11).
    pub fn fresh(&mut self) -> Key {
        self.next_key += 1;
        Key::new(self.next_key)
    }

    /// Send `message` to `to`, declaring `actors`, with admission evidence for
    /// fresh PDAs addressed by the root call (`pdas`), signed by a brand-new
    /// account.
    pub fn send(&mut self, what: &str, to: Actor, actors: &[Actor], pdas: &[(AccountId, PdaSeed)], message: &impl BorshSerialize) -> Result<Outcome, String> {
        let k = self.fresh();
        self.send_signed(what, to, actors, &[&k], pdas, message)
    }

    pub fn send_signed(&mut self, what: &str, to: Actor, actors: &[Actor], signers: &[&Key], pdas: &[(AccountId, PdaSeed)], message: &impl BorshSerialize) -> Result<Outcome, String> {
        let nonces = signers.iter().map(|k| (k.id, self.state.get_account_by_id(k.id).nonce)).collect();
        let evidence: Vec<PublicAccountEvidence> = pdas.iter().map(|(program, seed)| PublicAccountEvidence::Pda { program: *program, seed: *seed }).collect();
        let data = Program::serialize_message(message).map_err(|e| e.to_string())?;
        let mut all = actors.to_vec();
        all.push(to);
        let msg = Message::new(to, data, all, nonces, None, evidence);
        let sks: Vec<&PrivateKey> = signers.iter().map(|k| &k.sk).collect();
        let tx = PublicTransaction::new(msg.clone(), WitnessSet::for_message(&msg, &sks));
        self.submit(what, &tx)
    }

    pub fn submit(&mut self, what: &str, tx: &PublicTransaction) -> Result<Outcome, String> {
        let (charge, r) = ValidatedStateDiff::from_public_transaction_metered(tx, &self.state, self.block, self.now, GAS_CAP);
        self.block += 1;
        self.now += 12_000;
        let diff = r.map_err(|e| format!("not includable: {e}"))?;
        let events = self.state.apply_state_diff(diff).map_err(|e| format!("apply: {e}"))?;
        self.log.push((what.to_string(), charge.cycles, charge.revert.is_none()));
        match charge.revert {
            None => Ok(Outcome { cycles: charge.cycles, events }),
            Some(e) => Err(e),
        }
    }

    /// The state this program holds in account `id`.
    #[must_use]
    pub fn state_of(&self, id: AccountId) -> Vec<u8> {
        self.actor_state(id, LC)
    }

    #[must_use]
    pub fn actor_state(&self, id: AccountId, program: AccountId) -> Vec<u8> {
        self.state.get_account_by_id(id).data.actor_state(program).to_vec()
    }

    #[must_use]
    pub fn instance(&self, instance_id: &[u8; 32]) -> Instance {
        borsh::from_slice(&self.state_of(instance_account(&LC, instance_id))).expect("an instance")
    }

    #[must_use]
    pub fn job(&self, instance_id: &[u8; 32], job_id: &[u8; 32]) -> Option<Job> {
        let s = self.state_of(job_account(&LC, instance_id, job_id));
        (!s.is_empty()).then(|| borsh::from_slice(&s).expect("a job"))
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

pub fn lc(id: AccountId) -> Actor {
    Actor::new(id, LC)
}

pub const ID: [u8; 32] = *b"mainnet/test/instance/0000000001";

pub fn init_message(m: &Mainnet, id: [u8; 32]) -> M {
    M::Init {
        instance_id: id,
        checkpoint: m.checkpoint,
        cfg: m.cfg.clone(),
        header: m.boot_header.clone(),
        committee: m.boot_committee.clone(),
        branch: m.boot_branch.clone(),
    }
}

/// `Init` from the checkpoint of `m`: a root call to the fresh instance PDA,
/// which records the checkpoint's header.
pub fn init(c: &mut Chain, m: &Mainnet, id: [u8; 32]) -> Result<Outcome, String> {
    let slot = m.boot_header.beacon.slot;
    c.send("Init", lc(instance_account(&LC, &id)), &[lc(header_account(&LC, &id, slot))], &[(LC, instance_seed(&id))], &init_message(m, id))
}

pub fn begin_message(current: &Instance, id: [u8; 32], u: &Update, committee: &SyncCommittee) -> M {
    let w = witness(committee, &u.bits, AggMode::Subtract);
    M::Begin { instance_id: id, current: digest(current), update: u.clone(), committee: committee.clone(), witness: w }
}

pub fn begin(c: &mut Chain, id: [u8; 32], current: &Instance, u: &Update, committee: &SyncCommittee) -> Result<(Outcome, [u8; 32]), String> {
    let jid = job_id_of(&digest(current), u);
    let o = c.send("Begin", lc(instance_account(&LC, &id)), &[lc(job_account(&LC, &id, &jid))], &[], &begin_message(current, id, u, committee))?;
    Ok((o, jid))
}

pub fn miller(c: &mut Chain, id: [u8; 32], jid: [u8; 32]) -> Result<Outcome, String> {
    c.send("Miller", lc(job_account(&LC, &id, &jid)), &[], &[], &M::Miller { instance_id: id, job_id: jid })
}

/// `Finish`: declares the instance and the header the job's update records.
pub fn finish(c: &mut Chain, id: [u8; 32], jid: [u8; 32], next_slot: u64) -> Result<Outcome, String> {
    let actors = [lc(instance_account(&LC, &id)), lc(header_account(&LC, &id, next_slot))];
    c.send("Finish", lc(job_account(&LC, &id, &jid)), &actors, &[], &M::Finish { instance_id: id, job_id: jid })
}

/// The three transactions of one update; returns their cycles.
pub fn advance(c: &mut Chain, id: [u8; 32], u: &Update, committee: &SyncCommittee) -> Result<[u64; 3], String> {
    let current = c.instance(&id);
    let (g1, jid) = begin(c, id, &current, u, committee)?;
    let next_slot = c.job(&id, &jid).expect("Begin opened the job").next.store.finalized.slot;
    let g2 = miller(c, id, jid)?;
    let g3 = finish(c, id, jid, next_slot)?;
    Ok([g1.cycles, g2.cycles, g3.cycles])
}

pub fn attest(c: &mut Chain, id: [u8; 32], slot: u64, q: sextant_core::statement::Query) -> Result<Outcome, String> {
    c.send("Attest", lc(header_account(&LC, &id, slot)), &[], &[], &M::Attest { instance_id: id, slot, query: q })
}

/// The first typed refusal `E72xx` in a revert message.
pub fn refusal(e: &str) -> Option<u32> {
    let i = e.match_indices('E').map(|(i, _)| i).find(|&i| e.get(i + 1..i + 5).is_some_and(|d| d.bytes().all(|b| b.is_ascii_digit()) && d.starts_with("72")))?;
    e[i + 1..i + 5].parse().ok()
}

/// The native verifier's store after every update of `m`, for comparison.
pub fn native_final(m: &Mainnet) -> Option<sextant_core::Store> {
    sextant_host::mainnet_steps(m).last().map(|(s, u, k)| {
        let w = witness(k, &u.bits, AggMode::Subtract);
        lc::apply_update(&m.cfg, s, u, k, &w, lc::FAST, &mut |_| {}).unwrap()
    })
}

/// Privacy-preserving transactions to sextant_lc on rc3's state machine:
/// a private actor's keys, and one root call to a fresh private actor of a
/// program proven (`lee::execute_and_prove`) and settled with
/// `V03State::transition_from_privacy_preserving_transaction`, the
/// verification a sequencer runs. No fee leg: the state machine does not
/// classify fees (the sequencer does; `seq_drive private` builds it).
pub mod private {
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    use lee::{
        privacy_preserving_transaction::{circuit::ProgramCatalog, message::Message as PMessage, witness_set::WitnessSet as PWitness},
        program::Program,
        AccountId, Actor, PrivacyPreservingTransaction, ProvingInput, PublicExecutionContext, SenderPresentation, Simulation,
    };
    use lee_core::{
        encryption::ViewingPublicKey, execution_state::TransactionEntry, program::MessageBody, AuthorizationSecretKey, NullifierPublicKey, NullifierSecretKey,
        NullifierWitness, PrivateWitness, RecipientEncryption, RegularKey, RootCall, WitnessKind, DUMMY_COMMITMENT_HASH,
    };

    use super::Chain;

    /// A private account's keys (lee's `test_utils::TestPrivateKeys`, which
    /// only a debug build may enable).
    pub struct Keys {
        pub ask: AuthorizationSecretKey,
        pub d: [u8; 32],
        pub z: [u8; 32],
    }

    impl Keys {
        #[must_use]
        pub fn new(seed: u8) -> Self {
            Self { ask: AuthorizationSecretKey([seed; 32]), d: [seed.wrapping_add(1); 32], z: [seed.wrapping_add(2); 32] }
        }
        #[must_use]
        pub fn nsk(&self) -> NullifierSecretKey {
            NullifierSecretKey::from(&self.ask)
        }
        #[must_use]
        pub fn npk(&self) -> NullifierPublicKey {
            NullifierPublicKey::from(&self.nsk())
        }
        #[must_use]
        pub fn vpk(&self) -> ViewingPublicKey {
            ViewingPublicKey::from_seed(&self.d, &self.z)
        }
        #[must_use]
        pub fn account_id(&self) -> AccountId {
            AccountId::for_regular_private_account(&self.npk(), &self.vpk())
        }
        /// A fresh private account: no commitment yet, so no membership proof.
        #[must_use]
        pub fn init_witness(&self) -> PrivateWitness {
            PrivateWitness {
                vpk: self.vpk(),
                random_seed: [0; 32],
                kind: WitnessKind::Regular(RegularKey::Authorized(self.ask.clone())),
                nullifier: NullifierWitness::Init { commitment_root: DUMMY_COMMITMENT_HASH },
                address_openings: BTreeSet::new(),
            }
        }
    }

    pub fn no_seal(body: &MessageBody) -> Result<RecipientEncryption, lee::error::LeeError> {
        Err(lee::error::LeeError::InvalidInput(format!("no seal for an async message to {:?}", body.to)))
    }

    /// Prove `message` to the private actor of `program` at `keys`' fresh
    /// account, the public part reaching `public_actors` (their states read
    /// from `c`), and return the transaction (not settled).
    pub fn prove(c: &Chain, program: AccountId, keys: &Keys, message: Vec<u8>, public_actors: &[Actor]) -> Result<PrivacyPreservingTransaction, lee::error::LeeError> {
        let me = Actor::new(keys.account_id(), program);
        let input = ProvingInput {
            root: TransactionEntry::Sync(RootCall { to: me, message }),
            claims: vec![],
            fee: None,
            public_context: PublicExecutionContext::new(public_actors.iter().copied(), []),
            private_witnesses: vec![keys.init_witness()],
            dummy_inputs: vec![],
            ciphertext_padding: None,
            recoveries: vec![],
            private_promotions: BTreeSet::new(),
        };
        let states: HashMap<Actor, lee_core::account::ActorState> =
            public_actors.iter().map(|a| (*a, c.state.get_account_by_id(a.account_id).data.actor_state(a.program_account_id).clone())).collect();
        let sim = Simulation { public_actor_states: states, admitted_accounts: None };
        let catalog = ProgramCatalog::from([(program, Program::new(super::bin().into()).expect("a program"))]);
        let (output, proof) = lee::execute_and_prove(input, &sim, &catalog, |_| SenderPresentation::Canonical, |_, _| false, no_seal)?;
        let message = PMessage::from_circuit_output(BTreeMap::new(), output);
        Ok(PrivacyPreservingTransaction::new(message.clone(), PWitness::for_message(&message, proof, &[])))
    }

    /// Settle a proven transaction on `c` (one block).
    pub fn settle(c: &mut Chain, tx: &PrivacyPreservingTransaction) -> Result<(), String> {
        let r = c.state.transition_from_privacy_preserving_transaction(tx, c.block, c.now).map(|_| ()).map_err(|e| e.to_string());
        c.block += 1;
        c.now += 12_000;
        r
    }

    /// Fake proofs for the executor tests (the circuit still runs in full;
    /// the receipt is not a STARK). Real proving: `--bin private_update`, `seq_drive private`.
    pub fn dev_mode() {
        std::env::set_var("RISC0_DEV_MODE", "1");
    }
}
