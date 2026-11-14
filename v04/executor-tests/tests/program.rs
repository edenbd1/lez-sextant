//! The v0.4 sextant_lc binary through `lee::V03State` at LEZ v0.4.0-rc3, on
//! real mainnet data: the lifecycle, and every refusal the RFP's Verification
//! Security section names, each as the typed code the program panics with
//! (the same codes as on v0.3: executor-tests/tests/program.rs).

use sextant_core::lc::{self, AggMode};
use sextant_core::statement::{Cmp, Field, Predicate, Proof, Query};
use sextant_core::Error;
use sextant_executor_tests_v04::*;
use sextant_host::{mainnet, mainnet_steps, receipt_proof, receipt_proof_from, weth_proof, weth_proof_from, witness};
use sextant_program_v04::*;

fn code(e: Error) -> u32 {
    E_BASE + e as u32
}

fn refused<T: std::fmt::Debug>(r: Result<T, String>) -> u32 {
    let e = r.expect_err("the transaction must be refused");
    refusal(&e).unwrap_or_else(|| panic!("no typed refusal in: {e}"))
}

fn transfer() -> [u8; 32] {
    sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"))
}

#[test]
fn the_real_chain_advances_through_three_handoffs_each_step_under_the_cap() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    for (_, u, committee) in mainnet_steps(&m) {
        let gas = advance(&mut c, ID, &u, &committee).unwrap();
        assert!(gas.iter().all(|g| *g < GAS_CAP / 100 * 60), "{gas:?}");
    }
    let s = c.instance(&ID).store;
    assert_eq!(lc::period(s.finalized.slot), 1884);
    assert_eq!(s.finalized_block_number, 26_197_200);
    assert_eq!(Some(s), native_final(&m), "the program ends where the native verifier ends");
}

#[test]
fn finish_records_the_header_spends_the_job_and_emits_advanced() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, committee) = mainnet_steps(&m)[0].clone();
    let current = c.instance(&ID);
    let (o, jid) = begin(&mut c, ID, &current, &u, &committee).unwrap();
    assert_eq!(o.events.len(), 1, "JobStep 1");
    let job = c.job(&ID, &jid).expect("Begin opened the job");
    assert_eq!((job.prev, job.f.is_none()), (digest(&current), true));
    miller(&mut c, ID, jid).unwrap();
    assert!(c.job(&ID, &jid).unwrap().f.is_some());
    let slot = job.next.store.finalized.slot;
    let o = finish(&mut c, ID, jid, slot).unwrap();
    assert!(c.job(&ID, &jid).is_none(), "the job is spent");
    assert_eq!(c.instance(&ID), job.next);
    let rec: sextant_core::statement::HeaderRecord = borsh::from_slice(&c.state_of(header_account(&LC, &ID, slot))).unwrap();
    assert_eq!(rec, record(&job.next.cfg, &job.next.store));
    let adv = o.events.iter().find(|e| e.event.selector == event("Advanced", &()).selector).expect("Advanced");
    // v0.4 attributes an actor's events to its program's account.
    assert_eq!(adv.account_id, LC);
    let body: Advanced = borsh::from_slice(&adv.event.data).unwrap();
    assert_eq!((body.instance_id, body.slot), (ID, slot));
    // Finish again: the job is gone.
    assert_eq!(refused(finish(&mut c, ID, jid, slot)), E_NO_JOB);
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
fn init_refuses_a_checkpoint_that_is_not_the_bootstrap_header() {
    let mut m = mainnet();
    m.checkpoint[0] ^= 1;
    let mut c = Chain::new();
    assert_eq!(refused(init(&mut c, &m, ID)), code(Error::CheckpointMismatch));
    let mut m = mainnet();
    m.boot_committee.pubkeys[7][5] ^= 1; // a committee not in the checkpoint's state
    assert_eq!(refused(init(&mut c, &m, ID)), code(Error::BadCommitteeBranch));
    let mut m = mainnet();
    m.cfg.min_participants = 300; // below two thirds
    assert_eq!(refused(init(&mut c, &m, ID)), code(Error::Malformed));
    assert!(c.state_of(instance_account(&LC, &ID)).is_empty());
}

#[test]
fn internal_messages_are_refused_from_a_transaction_and_an_instance_lives_only_at_its_pda() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    // A transaction cannot write a header record: `Record` is only decoded
    // from another actor of this program, so from a transaction it is not a
    // `Message` at all.
    let r = record(&m.cfg, &c.instance(&ID).store);
    let mut forged = r.clone();
    forged.slot += 1;
    forged.state_root = [0x42; 32];
    let hdr = header_account(&LC, &ID, forged.slot);
    let internal = Internal::Record { instance_id: ID, record: forged.clone() };
    let e = c.send("forged Record", lc(hdr), &[], &[(LC, header_seed(&ID, forged.slot))], &internal);
    assert_eq!(refused(e), code(Error::Malformed), "a transaction cannot record a header");
    assert!(c.state_of(hdr).is_empty());
    // Init addressed to any account but the PDA of its id is refused.
    let k = c.fresh();
    let e = c.send_signed("Init at a key", lc(k.id), &[lc(header_account(&LC, &ID, m.boot_header.beacon.slot))], &[&k], &[], &init_message(&m, ID));
    assert_eq!(refusal(&e.unwrap_err()), Some(E_ACCOUNTS));
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
    let (_, jid) = begin(&mut c, ID, &current, &u, &committee).unwrap();
    miller(&mut c, ID, jid).unwrap();
    let job = c.job(&ID, &jid).unwrap();
    let slot = job.next.store.finalized.slot;
    let hdr = header_account(&LC, &ID, slot);
    let hdr_before = c.state_of(hdr);
    assert_eq!(refused(finish(&mut c, ID, jid, slot)), code(Error::BadSignature));
    assert_eq!(c.instance(&ID), current, "a rejected update consumes nothing (R.2)");
    assert_eq!(c.job(&ID, &jid), Some(job));
    assert_eq!(c.state_of(hdr), hdr_before);
}

#[test]
fn a_fabricated_update_never_gets_a_job() {
    // Below participation, a committee never handed off, a header not in the
    // attested state, an execution root not under the body: all refused at
    // Begin, before any job exists.
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let steps = mainnet_steps(&m);
    let current = c.instance(&ID);
    let (_, u, committee) = steps[0].clone();
    let mut low = u.clone();
    for i in 341..512 {
        low.bits[i / 8] &= !(1 << (i % 8));
    }
    assert_eq!(refused(begin(&mut c, ID, &current, &low, &committee)), code(Error::BelowParticipation));
    let (_, u2, c2) = steps[2].clone();
    assert_eq!(refused(begin(&mut c, ID, &current, &u2, &c2)), code(Error::HandoffNotVerified));
    let mut moved = u.clone();
    moved.finalized.beacon.slot += 32;
    assert_eq!(refused(begin(&mut c, ID, &current, &moved, &committee)), code(Error::NotFinalized));
    let mut root = u.clone();
    root.finalized.execution.state_root[0] ^= 1;
    assert_eq!(refused(begin(&mut c, ID, &current, &root, &committee)), code(Error::BadExecutionBranch));
    let mut other = committee.clone();
    other.pubkeys.swap(0, 1);
    assert_eq!(refused(begin(&mut c, ID, &current, &u, &other)), code(Error::CommitteeMismatch));
    assert_eq!(c.instance(&ID), current);
    for bad in [&low, &u2, &moved, &root] {
        assert!(c.job(&ID, &job_id(&current, bad)).is_none());
    }
}

#[test]
fn a_tampered_key_witness_is_refused() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, committee) = mainnet_steps(&m)[0].clone();
    let current = c.instance(&ID);
    let mut w = witness(&committee, &u.bits, AggMode::Subtract);
    w.aggregate[10] ^= 1;
    let jid = job_id(&current, &u);
    let ix = Message::Begin { instance_id: ID, current: digest(&current), update: u, committee, witness: w };
    let e = c.send("Begin", lc(instance_account(&LC, &ID)), &[lc(job_account(&LC, &ID, &jid))], &[], &ix);
    let code_ = refused(e);
    assert!(code_ == code(Error::BadKey) || code_ == code(Error::Malformed), "E{code_}");
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
    assert_eq!(refused(begin(&mut c, ID, &current, &u, &committee)), E_STALE);
    let jid = job_id(&current, &u);
    assert_eq!(refused(miller(&mut c, ID, jid)), E_NO_JOB);
    // Built against the new store, the same update is already applied.
    assert_eq!(refused(begin(&mut c, ID, &after, &u, &committee)), code(Error::AlreadyApplied));
    assert_eq!(c.instance(&ID), after);
}

#[test]
fn two_jobs_racing_from_one_store_land_once() {
    // Two operators each open a job for an update from the same store; the
    // first Finish advances the instance, the second is refused at Advance
    // (E7293) and the instance is not moved twice (R.8).
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, committee) = steps[0].clone();
    let current = c.instance(&ID);
    let (_, j1) = begin(&mut c, ID, &current, &u, &committee).unwrap();
    // The same signed update with a later signature slot in the same epoch:
    // the same signing domain, so the same valid signature, but another job.
    let mut u2 = u.clone();
    u2.signature_slot += 1;
    let (_, j2) = begin(&mut c, ID, &current, &u2, &committee).unwrap();
    assert_ne!(j1, j2);
    miller(&mut c, ID, j1).unwrap();
    miller(&mut c, ID, j2).unwrap();
    let slot = c.job(&ID, &j1).unwrap().next.store.finalized.slot;
    finish(&mut c, ID, j1, slot).unwrap();
    let after = c.instance(&ID);
    // j2 verifies, but the instance moved on: refused at Advance.
    assert_eq!(refused(finish(&mut c, ID, j2, slot)), E_STALE);
    assert_eq!(c.instance(&ID), after);
}

#[test]
fn steps_out_of_order_are_refused() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, committee) = mainnet_steps(&m)[0].clone();
    let current = c.instance(&ID);
    let jid = job_id(&current, &u);
    // A job that was never opened is an account that does not exist: not
    // admitted unless the transaction backs it with PDA evidence, and then E7294.
    assert!(finish(&mut c, ID, jid, 0).is_err());
    let e = c.send("Finish", lc(job_account(&LC, &ID, &jid)), &[], &[(LC, job_seed(&ID, &jid))], &Message::Finish { instance_id: ID, job_id: jid });
    assert_eq!(refused(e), E_NO_JOB);
    begin(&mut c, ID, &current, &u, &committee).unwrap();
    let slot = c.job(&ID, &jid).unwrap().next.store.finalized.slot;
    assert_eq!(refused(finish(&mut c, ID, jid, slot)), E_JOB_STEP);
    // Begin again before Miller is a no-op; after Miller it is refused.
    begin(&mut c, ID, &current, &u, &committee).unwrap();
    miller(&mut c, ID, jid).unwrap();
    assert_eq!(refused(miller(&mut c, ID, jid)), E_JOB_STEP);
    assert_eq!(refused(begin(&mut c, ID, &current, &u, &committee)), E_EXISTS);
    finish(&mut c, ID, jid, slot).unwrap();
}

#[test]
fn a_stalled_instance_resumes_without_repair() {
    // R.7: nobody submits for three periods; the first party who does catches
    // up period by period, and attestations against the old header keep verifying.
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
    assert!(!c.state_of(header_account(&LC, &ID, old_slot)).is_empty(), "old header records stay (R.3)");
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
    let log = |cmp, value| Query { chain_id: 1, proof: Proof::Log(receipt_proof(2)), predicates: vec![Predicate { field: Field::LogTopic(0), cmp, value }] };
    attest(&mut c, ID, slot, log(Cmp::Eq, transfer())).unwrap();
    assert_eq!(refused(attest(&mut c, ID, slot, log(Cmp::Ne, transfer()))), code(Error::PredicateFalse));
    let mut q = log(Cmp::Eq, transfer());
    q.chain_id = 11_155_111;
    assert_eq!(refused(attest(&mut c, ID, slot, q)), code(Error::ChainMismatch));
    let mut p = weth_proof();
    p.slot[0] ^= 1; // a slot the proof does not cover
    let q = Query { chain_id: 1, proof: Proof::Storage(p), predicates: vec![] };
    assert_eq!(refused(attest(&mut c, ID, slot, q)), code(Error::BadInclusion));
    // Against a header the instance never recorded: the account does not
    // exist, so the actor is not admitted (a consumer's Attest fails its
    // transaction); backed by PDA evidence, the empty record refuses E7292.
    assert!(attest(&mut c, ID, slot + 1, log(Cmp::Eq, transfer())).is_err());
    let e = c.send("Attest", lc(header_account(&LC, &ID, slot + 1)), &[], &[(LC, header_seed(&ID, slot + 1))], &Message::Attest { instance_id: ID, slot: slot + 1, query: log(Cmp::Eq, transfer()) });
    assert_eq!(refused(e), E_NO_INSTANCE);
    // Attest addressed to another slot's record is refused.
    let e = c.send("Attest", lc(header_account(&LC, &ID, slot)), &[], &[], &Message::Attest { instance_id: ID, slot: slot + 1, query: log(Cmp::Eq, transfer()) });
    assert_eq!(refusal(&e.unwrap_err()), Some(E_ACCOUNTS));
}

#[test]
fn attestations_verify_against_the_checkpoint_header() {
    // Init records the checkpoint's header, so a consumer can attest against it
    // before any update: execution block 26,170,219 (vectors/mainnet/block-26170219).
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let slot = c.instance(&ID).store.finalized.slot;
    let log = |p| Query { chain_id: 1, proof: Proof::Log(p), predicates: vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer() }] };
    attest(&mut c, ID, slot, log(receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16))).unwrap();
    let mut one = [0u8; 32];
    one[31] = 1;
    let wp = weth_proof_from("vectors/mainnet/block-26170219/getproof-weth.json");
    let q = Query { chain_id: 1, proof: Proof::Storage(wp), predicates: vec![Predicate { field: Field::SlotValue, cmp: Cmp::Ge, value: one }] };
    attest(&mut c, ID, slot, q).unwrap();
    // A proof from another block does not verify against this header's roots.
    assert_eq!(refused(attest(&mut c, ID, slot, log(receipt_proof(2)))), code(Error::BadInclusion));
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
    let e = begin(&mut c, ID, &before, &u, &committee).expect_err("stale");
    assert_eq!(refusal(&e), Some(code(Error::CheckpointStale)), "{e}");
    assert_eq!(c.instance(&ID), before);
    assert!(c.job(&ID, &job_id(&before, &u)).is_none(), "no job was opened");
    // At exactly the bound, the same update is accepted.
    m.cfg.max_checkpoint_age = gap;
    let other = *b"mainnet/test/instance/0000000002";
    init(&mut c, &m, other).unwrap();
    advance(&mut c, other, &u, &committee).unwrap();
}

#[test]
fn the_sequencer_clock_refuses_a_stale_store_and_records_stay_attestable() {
    // F.10, against LEZ time: Init, Begin and Finish's Advance declare a
    // timestamp validity window that closes `max_checkpoint_age` after the
    // store's finalized header, so the sequencer refuses them once it has passed.
    let m = mainnet();
    let stale = lc::stale_from_ms(&m.cfg, m.boot_header.beacon.slot);
    let mut c = Chain::new();
    c.now = stale;
    let e = init(&mut c, &m, ID).expect_err("a checkpoint past the bound");
    assert!(e.to_lowercase().contains("validity window") || e.to_lowercase().contains("window"), "{e}");
    c.now = stale - 1;
    init(&mut c, &m, ID).unwrap();
    let slot = c.instance(&ID).store.finalized.slot;
    let (_, u, committee) = mainnet_steps(&m)[0].clone();
    // Begin and Miller before the bound, Finish after it: refused at Advance.
    c.now = stale - 30_000;
    let current = c.instance(&ID);
    let (_, jid) = begin(&mut c, ID, &current, &u, &committee).unwrap();
    miller(&mut c, ID, jid).unwrap();
    c.now = stale;
    let next_slot = c.job(&ID, &jid).unwrap().next.store.finalized.slot;
    let e = finish(&mut c, ID, jid, next_slot).expect_err("a stale store");
    assert!(e.to_lowercase().contains("window"), "{e}");
    assert_eq!(c.instance(&ID), current);
    let e = advance(&mut c, ID, &u, &committee).expect_err("a stale store");
    assert!(e.to_lowercase().contains("window") || refusal(&e) == Some(E_EXISTS), "{e}");
    // Header records are immutable and stay usable after the instance went
    // stale: a consumer's proof against them still verifies (R.3).
    let q = Query {
        chain_id: 1,
        proof: Proof::Log(receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16)),
        predicates: vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer() }],
    };
    attest(&mut c, ID, slot, q).unwrap();
}
