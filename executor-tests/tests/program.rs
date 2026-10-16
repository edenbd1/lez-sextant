//! The committed sextant_lc binary through `lee::V03State`, on real mainnet
//! data: the lifecycle, and every refusal the RFP's Verification Security
//! section names, each as the typed code the program panics with.

use sextant_core::lc::{self, AggMode};
use sextant_core::statement::{Cmp, Field, Predicate, Proof, Query};
use sextant_core::Error;
use sextant_executor_tests::*;
use sextant_host::{mainnet, mainnet_steps, receipt_proof, receipt_proof_from, weth_proof, weth_proof_from, witness};
use sextant_program::*;

fn code(e: Error) -> u32 {
    E_BASE + e as u32
}

fn refused(r: Result<u64, String>) -> u32 {
    let e = r.expect_err("the transaction must be refused");
    refusal(&e).unwrap_or_else(|| panic!("no typed refusal in: {e}"))
}

#[test]
fn the_real_chain_advances_through_three_handoffs_each_step_under_the_cap() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    for (_, u, committee) in mainnet_steps(&m) {
        let gas = advance(&mut c, ID, &u, &committee).unwrap();
        assert!(gas.iter().all(|g| *g < GAS_CAP / 100 * 55), "{gas:?}");
    }
    let s = c.instance(&ID).store;
    assert_eq!(lc::period(s.finalized.slot), 1884);
    assert_eq!(s.finalized_block_number, 26_197_200);
    // Every step was signed by an account the chain had never seen (F.11).
}

#[test]
fn the_configuration_is_written_once() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let before = c.instance(&ID);
    // A second Init at the same id, even with the same checkpoint, is refused (F.9, F.13).
    assert_eq!(refused(init(&mut c, &m, ID)), E_EXISTS);
    assert_eq!(c.instance(&ID), before);
    // Another instance with another chain configuration coexists (F.14, F.15).
    let mut m2 = mainnet();
    m2.cfg.chain_id = 11_155_111;
    let other = *b"sepolia/test/instance/0000000001";
    init(&mut c, &m2, other).unwrap();
    assert_eq!(c.instance(&ID), before);
    assert_eq!(c.instance(&other).cfg.chain_id, 11_155_111);
}

#[test]
fn a_bad_signature_is_refused_at_finish_and_nothing_moves() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let steps = mainnet_steps(&m);
    let (_, mut u, committee) = steps[0].clone();
    u.signature = steps[1].1.signature; // a real signature, over another header
    let current = c.instance(&ID);
    let w = witness(&committee, &u.bits, AggMode::Subtract);
    let p = lc::prepare(&current.cfg, &current.store, &u, &committee, &w, lc::FAST, &mut |_| {}).unwrap();
    let jid = job_id(&current, &u);
    let job = job_account(&LC, &ID, &jid);
    let begin = Instruction::Begin { instance_id: ID, current: current.clone(), update: u.clone(), committee, witness: w };
    c.send(&begin, vec![instance_account(&LC, &ID), job]).unwrap();
    c.send(&Instruction::Miller { instance_id: ID, job_id: jid }, vec![job]).unwrap();
    let fin = Instruction::Finish { instance_id: ID, job_id: jid, current: current.clone(), next: p.next.clone() };
    let hdr = header_account(&LC, &ID, p.next.finalized.slot);
    let (job_before, hdr_before) = (c.shard(job), c.shard(hdr));
    assert_eq!(refused(c.send(&fin, vec![instance_account(&LC, &ID), job, hdr])), code(Error::BadSignature));
    assert_eq!(c.instance(&ID), current, "a rejected update consumes nothing (R.2)");
    assert_eq!((c.shard(job), c.shard(hdr)), (job_before, hdr_before));
}

#[test]
fn a_fabricated_update_never_gets_a_job() {
    // Below participation, a committee never handed off, a header not in the
    // attested state: all refused at Begin, in the plan, before any job exists.
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let steps = mainnet_steps(&m);
    let current = c.instance(&ID);
    let try_begin = |c: &mut Chain, u: &sextant_core::Update, committee: &sextant_core::SyncCommittee| {
        let w = witness(committee, &u.bits, AggMode::Subtract);
        let ix = Instruction::Begin { instance_id: ID, current: current.clone(), update: u.clone(), committee: committee.clone(), witness: w };
        c.send(&ix, vec![instance_account(&LC, &ID), job_account(&LC, &ID, &job_id(&current, u))])
    };
    let (_, u, committee) = steps[0].clone();
    let mut low = u.clone();
    for i in 341..512 {
        low.bits[i / 8] &= !(1 << (i % 8));
    }
    assert_eq!(refused(try_begin(&mut c, &low, &committee)), code(Error::BelowParticipation));
    let (_, u2, c2) = steps[2].clone();
    assert_eq!(refused(try_begin(&mut c, &u2, &c2)), code(Error::HandoffNotVerified));
    let mut moved = u.clone();
    moved.finalized.beacon.slot += 32;
    assert_eq!(refused(try_begin(&mut c, &moved, &committee)), code(Error::NotFinalized));
    let mut root = u.clone();
    root.finalized.execution.state_root[0] ^= 1;
    assert_eq!(refused(try_begin(&mut c, &root, &committee)), code(Error::BadExecutionBranch));
    assert_eq!(c.instance(&ID), current);
}

#[test]
fn a_competing_operator_is_refused_cleanly() {
    // Two operators race the same update (R.8): the second's steps refuse with
    // a code that says there is nothing left to do, and nothing is applied twice.
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, committee) = mainnet_steps(&m)[0].clone();
    let current = c.instance(&ID);
    advance(&mut c, ID, &u, &committee).unwrap();
    let after = c.instance(&ID);
    // The latecomer built its Begin against the old store.
    let w = witness(&committee, &u.bits, AggMode::Subtract);
    let jid = job_id(&current, &u);
    let ix = Instruction::Begin { instance_id: ID, current: current.clone(), update: u.clone(), committee, witness: w };
    assert_eq!(refused(c.send(&ix, vec![instance_account(&LC, &ID), job_account(&LC, &ID, &jid)])), E_STALE);
    assert_eq!(refused(c.send(&Instruction::Miller { instance_id: ID, job_id: jid }, vec![job_account(&LC, &ID, &jid)])), E_NO_JOB);
    assert_eq!(c.instance(&ID), after);
}

#[test]
fn a_stalled_instance_resumes_without_repair() {
    // R.7: nobody submits for three periods; the first party who does catches up
    // period by period, and attestations against the old header keep verifying.
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let steps = mainnet_steps(&m);
    advance(&mut c, ID, &steps[0].1, &steps[0].2).unwrap();
    let old_slot = c.instance(&ID).store.finalized.slot;
    c.block += 30_000; // a long silence
    for (_, u, committee) in &steps[1..] {
        advance(&mut c, ID, u, committee).unwrap();
    }
    assert!(!c.shard(header_account(&LC, &ID, old_slot)).is_empty(), "old header records stay (R.3)");
}

fn attest(c: &mut Chain, slot: u64, q: Query) -> Result<u64, String> {
    c.send(&Instruction::Attest { instance_id: ID, slot, query: q }, vec![header_account(&LC, &ID, slot)])
}

#[test]
fn attestations_verify_and_refuse_with_typed_codes() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    for (_, u, committee) in mainnet_steps(&m) {
        advance(&mut c, ID, &u, &committee).unwrap();
    }
    let slot = c.instance(&ID).store.finalized.slot;
    let transfer = sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"));
    let log = |cmp, value| Query { chain_id: 1, proof: Proof::Log(receipt_proof(2)), predicates: vec![Predicate { field: Field::LogTopic(0), cmp, value }] };
    attest(&mut c, slot, log(Cmp::Eq, transfer)).unwrap();
    assert_eq!(refused(attest(&mut c, slot, log(Cmp::Ne, transfer))), code(Error::PredicateFalse));
    let mut q = log(Cmp::Eq, transfer);
    q.chain_id = 11_155_111;
    assert_eq!(refused(attest(&mut c, slot, q)), code(Error::ChainMismatch));
    let mut p = weth_proof();
    p.slot[0] ^= 1; // a slot the proof does not cover
    let q = Query { chain_id: 1, proof: Proof::Storage(p), predicates: vec![] };
    assert_eq!(refused(attest(&mut c, slot, q)), code(Error::BadInclusion));
    // Against a header the instance never recorded.
    assert_eq!(refused(attest(&mut c, slot + 1, log(Cmp::Eq, transfer))), E_NO_INSTANCE);
}

#[test]
fn attestations_verify_against_the_checkpoint_header() {
    // Init records the checkpoint's header, so a consumer can attest against it
    // before any update: execution block 26,170,219 (vectors/mainnet/block-26170219).
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let slot = c.instance(&ID).store.finalized.slot;
    let transfer = sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"));
    let log = |p| Query { chain_id: 1, proof: Proof::Log(p), predicates: vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer }] };
    attest(&mut c, slot, log(receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16))).unwrap();
    let mut one = [0u8; 32];
    one[31] = 1;
    let wp = weth_proof_from("vectors/mainnet/block-26170219/getproof-weth.json");
    let q = Query { chain_id: 1, proof: Proof::Storage(wp), predicates: vec![Predicate { field: Field::SlotValue, cmp: Cmp::Ge, value: one }] };
    attest(&mut c, slot, q).unwrap();
    // A proof from another block does not verify against this header's roots.
    assert_eq!(refused(attest(&mut c, slot, log(receipt_proof(2)))), code(Error::BadInclusion));
}

#[test]
fn a_store_past_the_weak_subjectivity_bound_refuses_updates_with_e7206() {
    // F.10, against the chain itself: the first real update was signed some
    // hours after the checkpoint; an instance whose bound is shorter than that
    // refuses it at Begin with the typed code, and nothing moves.
    let mut m = mainnet();
    let steps = mainnet_steps(&m);
    let (_, u, committee) = steps[0].clone();
    let gap = lc::slot_time(&m.cfg, u.signature_slot) - lc::slot_time(&m.cfg, m.boot_header.beacon.slot);
    m.cfg.max_checkpoint_age = gap - 1;
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let before = c.instance(&ID);
    // Begin built without the client-side check, as a careless operator would.
    let w = witness(&committee, &u.bits, AggMode::Subtract);
    let jid = job_id(&before, &u);
    let ix = Instruction::Begin { instance_id: ID, current: before.clone(), update: u.clone(), committee: committee.clone(), witness: w };
    let e = c.send(&ix, vec![instance_account(&LC, &ID), job_account(&LC, &ID, &jid)]).expect_err("stale");
    assert_eq!(refusal(&e), Some(code(Error::CheckpointStale)), "{e}");
    assert_eq!(c.instance(&ID), before);
    assert!(c.shard(job_account(&LC, &ID, &jid)).is_empty(), "no job was opened");
    // At exactly the bound, the same update is accepted.
    m.cfg.max_checkpoint_age = gap;
    let other = *b"mainnet/test/instance/0000000002";
    init(&mut c, &m, other).unwrap();
    advance(&mut c, other, &u, &committee).unwrap();
}

#[test]
fn the_sequencer_clock_refuses_a_stale_store_and_records_stay_attestable() {
    // F.10, against LEZ time: Init, Begin and Finish declare a timestamp
    // validity window that closes `max_checkpoint_age` after the store's
    // finalized header, so the sequencer refuses them once it has passed.
    let m = mainnet();
    let stale = lc::stale_from_ms(&m.cfg, m.boot_header.beacon.slot);
    let mut c = Chain::new();
    c.now = stale;
    let e = init(&mut c, &m, ID).expect_err("a checkpoint past the bound");
    assert!(e.contains("validity window"), "{e}");
    c.now = stale - 1;
    init(&mut c, &m, ID).unwrap();
    let slot = c.instance(&ID).store.finalized.slot;
    c.now = stale;
    let (_, u, committee) = mainnet_steps(&m)[0].clone();
    let e = advance(&mut c, ID, &u, &committee).expect_err("a stale store");
    assert!(e.contains("validity window"), "{e}");
    // Header records are immutable and stay usable after the instance went
    // stale: a consumer's proof against them still verifies (R.3).
    let transfer = sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"));
    let q = Query {
        chain_id: 1,
        proof: Proof::Log(receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16)),
        predicates: vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer }],
    };
    attest(&mut c, slot, q).unwrap();
}
