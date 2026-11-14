//! The private-proof update on LEZ v0.4.0-rc3: a whole sync-committee update
//! proven client-side as ONE privacy-preserving transaction, with one public
//! effect.
//!
//! A fresh private account's actor of sextant_lc runs `Update` (the full
//! verification, pairing included, about 13M cycles, over a public
//! transaction's 10M cap but not a proof's) inside the privacy-preserving
//! circuit (`lee::execute_and_prove`), and sends `Advance` across the
//! private/public boundary to the public instance actor, which the state
//! machine runs at settlement: it checks the message came from this program
//! and the digest of its own state, writes the next store and records the
//! header, exactly as after `Finish`. The transaction is then settled with
//! `V03State::transition_from_privacy_preserving_transaction`, the
//! verification a sequencer runs.
//!
//! Not included: the fee, which only a sequencer classifies (lez/chain_state
//! `classify`). `seq_drive private` (v04/scripts/e2e-seq.sh) builds the same
//! transaction with its in-proof fee and submits it to a local rc3 sequencer.
//!
//! `RISC0_DEV_MODE=0 cargo run --release --bin private_update` (real proof;
//! `RISC0_DEV_MODE=1` for a fake one, to check the flow).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::time::Instant;

use lee::{
    privacy_preserving_transaction::{circuit::ProgramCatalog, message::Message as PMessage, witness_set::WitnessSet as PWitness, PrivacyPreservingTransaction},
    program::Program,
    Actor, ProvingInput, PublicExecutionContext, SenderPresentation, Simulation,
};
use lee_core::{
    encryption::ViewingPublicKey, execution_state::TransactionEntry, program::MessageBody, AuthorizationSecretKey, NullifierPublicKey, NullifierSecretKey,
    NullifierWitness, PrivateWitness, RecipientEncryption, RegularKey, RootCall, WitnessKind, DUMMY_COMMITMENT_HASH,
};

/// A private account's keys (lee's `test_utils::TestPrivateKeys`, which only a
/// debug build may enable).
struct Keys {
    ask: AuthorizationSecretKey,
    d: [u8; 32],
    z: [u8; 32],
}

impl Keys {
    fn npk(&self) -> NullifierPublicKey {
        NullifierPublicKey::from(&NullifierSecretKey::from(&self.ask))
    }
    fn vpk(&self) -> ViewingPublicKey {
        ViewingPublicKey::from_seed(&self.d, &self.z)
    }
    fn account_id(&self) -> lee::AccountId {
        lee::AccountId::for_regular_private_account(&self.npk(), &self.vpk())
    }
    /// A fresh private account: no commitment yet, so no membership proof.
    fn init_witness(&self) -> PrivateWitness {
        PrivateWitness {
            vpk: self.vpk(),
            random_seed: [0; 32],
            kind: WitnessKind::Regular(RegularKey::Authorized(self.ask.clone())),
            nullifier: NullifierWitness::Init { commitment_root: DUMMY_COMMITMENT_HASH },
            address_openings: BTreeSet::new(),
        }
    }
}

fn no_seal(body: &MessageBody) -> Result<RecipientEncryption, lee::error::LeeError> {
    Err(lee::error::LeeError::InvalidInput(format!("no seal for an async message to {:?}", body.to)))
}
use sextant_core::lc::{self, AggMode};
use sextant_executor_tests_v04::*;
use sextant_host::{mainnet, mainnet_steps, witness};
use sextant_program_v04::{header_account, instance_account, Message as M};

fn main() {
    let dev = std::env::var("RISC0_DEV_MODE").unwrap_or_default();
    println!("RISC0_DEV_MODE={dev:?} ({})", if dev == "1" || dev == "true" { "FAKE proof" } else { "real proof" });
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).expect("Init");
    let (_, u, committee) = mainnet_steps(&m)[0].clone(); // period 1881, with handoff
    let current = c.instance(&ID);
    let w = witness(&committee, &u.bits, AggMode::Subtract);
    let next = lc::apply_update(&current.cfg, &current.store, &u, &committee, &w, lc::FAST, &mut |_| {}).unwrap();

    let keys = Keys { ask: AuthorizationSecretKey([71; 32]), d: [72; 32], z: [73; 32] };
    let me = Actor::new(keys.account_id(), LC);
    let inst = Actor::new(instance_account(&LC, &ID), LC);
    let hdr = Actor::new(header_account(&LC, &ID, next.finalized.slot), LC);
    let msg = M::Update { instance_id: ID, current: current.clone(), update: u.clone(), committee, witness: w };
    let msg_bytes = borsh::to_vec(&msg).unwrap();
    let public_actors = vec![inst, hdr];
    let input = ProvingInput {
        root: TransactionEntry::Sync(RootCall { to: me, message: msg_bytes.clone() }),
        claims: vec![],
        fee: None,
        public_context: PublicExecutionContext::new(public_actors.clone(), []),
        private_witnesses: vec![keys.init_witness()],
        dummy_inputs: vec![],
        ciphertext_padding: None,
        recoveries: vec![],
        private_promotions: BTreeSet::new(),
    };
    let states: HashMap<Actor, lee_core::account::ActorState> =
        public_actors.iter().map(|a| (*a, c.state.get_account_by_id(a.account_id).data.actor_state(LC).clone())).collect();
    let sim = Simulation { public_actor_states: states, admitted_accounts: None };
    let catalog = ProgramCatalog::from([(LC, Program::new(bin().into()).unwrap())]);

    // The private run's cycles: the same session in the executor.
    let rin = lee_core::program::ReceiveInput { receiver: me, from: None, is_authorized: true, pre_state: Vec::<u8>::new().into(), message: msg_bytes.clone() };
    let mut stdin = (borsh::to_vec(&rin).unwrap().len() as u32).to_le_bytes().to_vec();
    stdin.extend(borsh::to_vec(&rin).unwrap());
    let env = risc0_zkvm::ExecutorEnv::builder().write_slice(&stdin).build().unwrap();
    let exec = risc0_zkvm::default_executor().execute(env, &bin()).expect("the private run executes");
    let total: u64 = exec.segments.iter().map(|s| 1u64 << s.po2).sum();
    println!("private run (Update at a private actor): {} user cycles, {} total, {} segments", exec.cycles(), total, exec.segments.len());

    let t = Instant::now();
    let (output, proof) = lee::execute_and_prove(input, &sim, &catalog, |_| SenderPresentation::Canonical, |_, _| false, no_seal).expect("execute_and_prove");
    let secs = t.elapsed().as_secs_f64();
    let message = PMessage::from_circuit_output(BTreeMap::new(), output);
    let tx = PrivacyPreservingTransaction::new(message.clone(), PWitness::for_message(&message, proof, &[]));
    let size = borsh::to_vec(&tx).unwrap().len();
    println!("proved in {secs:.1} s (wall, whole transaction: the program run and the privacy circuit); transaction {size} bytes, message {msg} bytes", msg = msg_bytes.len());

    let t = Instant::now();
    c.state.transition_from_privacy_preserving_transaction(&tx, c.block, c.now).expect("the transaction settles");
    println!("verified and settled in {:.2} s", t.elapsed().as_secs_f64());
    let after = c.instance(&ID);
    assert_eq!(after.store, next, "the public instance holds the verified store");
    assert!(!c.state_of(hdr.account_id).is_empty(), "the header is recorded");
    println!("instance advanced to slot {} (period {}), execution block {}; header recorded", next.finalized.slot, lc::period(next.finalized.slot), next.finalized_block_number);

    // A replay of the same proven transaction: the instance moved on (E7293 at Advance).
    let e = c.state.transition_from_privacy_preserving_transaction(&tx, c.block + 1, c.now + 12_000);
    println!("replay of the same transaction: {}", match &e { Ok(_) => "applied (UNEXPECTED)".to_string(), Err(e) => format!("refused: {e}") });
    assert!(e.is_err() || c.instance(&ID) == after);
}
