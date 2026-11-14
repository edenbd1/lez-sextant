//! Privacy-preserving transactions to sextant_lc on rc3's state machine
//! (fake receipts: `RISC0_DEV_MODE=1`, the circuit still runs in full; the
//! real proofs are `--bin private_update` and `seq_drive private`):
//!
//! - **the private consumer path**: a statement about a header record proven
//!   inside a privacy-preserving transaction against the instance's record
//!   index (`AttestPrivate`), whose public part is one `CheckRoot` naming the
//!   instance and a root it holds, never the record, its slot or the query;
//! - **private updates racing**: two whole-update proofs from one store land
//!   once, and a private update overtaking a public job leaves the job's
//!   `Finish` refused (`E7293`).

use lee_core::execution_state::BoundaryStep;
use sextant_core::lc::{self, AggMode};
use sextant_core::statement::{Cmp, Field, HeaderRecord, Predicate, Proof, Query};
use sextant_core::Error;
use sextant_executor_tests_v04::private::{dev_mode, prove, settle, Keys};
use sextant_executor_tests_v04::*;
use sextant_host::{mainnet, mainnet_steps, receipt_proof_from, witness, Mainnet};
use sextant_program_v04::*;

fn transfer() -> [u8; 32] {
    sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"))
}

/// A log of tx 16 of the checkpoint's execution block (26,170,219).
fn checkpoint_log(topic: [u8; 32]) -> Query {
    Query {
        chain_id: 1,
        proof: Proof::Log(receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16)),
        predicates: vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: topic }],
    }
}

/// Every record the instance wrote, in order: what a consumer rebuilds the
/// index from (the `Record` messages of the instance's transactions).
fn records(m: &Mainnet, upto: usize) -> Vec<HeaderRecord> {
    let boot = lc::bootstrap(&m.cfg, &m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).unwrap();
    let mut out = vec![record(&m.cfg, &boot)];
    for (s, u, k) in mainnet_steps(m).iter().take(upto) {
        let next = lc::apply_update(&m.cfg, s, u, k, &witness(k, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap();
        let r = record(&m.cfg, &next);
        if out.last().map(|l| l.slot) != Some(r.slot) {
            out.push(r);
        }
    }
    out
}

fn attest_private(instance_id: [u8; 32], root: [u8; 32], recs: &[HeaderRecord], position: usize, query: Query) -> Vec<u8> {
    let leaves: Vec<[u8; 32]> = recs.iter().map(record_leaf).collect();
    let msg = Message::AttestPrivate { instance_id, root, position: position as u64, record: recs[position].clone(), path: index_path(&leaves, position), query };
    borsh::to_vec(&msg).unwrap()
}

fn code_of(e: &str) -> Option<u32> {
    refusal(e)
}

#[test]
fn the_record_index_is_the_instances_own_and_follows_every_new_header() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let steps = mainnet_steps(&m);
    let mut roots = vec![c.instance(&ID).index.root()];
    for (n, (_, u, k)) in steps.iter().enumerate() {
        advance(&mut c, ID, u, k).unwrap();
        let recs = records(&m, n + 1);
        let leaves: Vec<[u8; 32]> = recs.iter().map(record_leaf).collect();
        let inst = c.instance(&ID);
        assert_eq!(inst.index.count as usize, leaves.len(), "one leaf per recorded header");
        // The root the instance holds is the root of the records it wrote; every path verifies.
        for (i, l) in leaves.iter().enumerate() {
            assert_eq!(index_root_of(*l, i as u64, &index_path(&leaves, i)), inst.index.root());
        }
        if roots.last() != Some(&inst.index.root()) {
            roots.push(inst.index.root());
        }
        assert_eq!(inst.index.roots, roots, "the latest roots, newest last");
        // Every record it wrote is the header account's.
        for r in &recs {
            assert_eq!(borsh::from_slice::<HeaderRecord>(&c.state_of(header_account(&LC, &ID, r.slot))).unwrap(), *r);
        }
    }
}

#[test]
fn a_private_attestation_reveals_the_instance_and_a_root_not_the_record() {
    dev_mode();
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let steps = mainnet_steps(&m);
    advance(&mut c, ID, &steps[0].1, &steps[0].2).unwrap();
    advance(&mut c, ID, &steps[1].1, &steps[1].2).unwrap();
    let inst = c.instance(&ID);
    let root = inst.index.root();
    let recs = records(&m, 2);
    assert!(recs.len() > 1);
    let inst_actor = lc(instance_account(&LC, &ID));
    // The checkpoint's record (position 0), read under the current root.
    let tx = prove(&c, LC, &Keys::new(41), attest_private(ID, root, &recs, 0, checkpoint_log(transfer())), &[inst_actor]).expect("proves");
    // What the transaction makes public: one message, CheckRoot to the instance.
    let msg = tx.message();
    let crossings: Vec<_> = msg.execution.boundary.iter().filter_map(|s| if let BoundaryStep::PrivateToPublic(d) = s { Some(d) } else { None }).collect();
    assert_eq!(crossings.len(), 1);
    assert_eq!(crossings[0].envelope.to, inst_actor);
    match borsh::from_slice::<Internal>(&crossings[0].envelope.message).unwrap() {
        Internal::CheckRoot { instance_id, root: r } => assert_eq!((instance_id, r), (ID, root)),
        other => panic!("unexpected {other:?}"),
    }
    assert_eq!(msg.public_context.actors.iter().copied().collect::<Vec<_>>(), vec![inst_actor], "no header record is declared");
    let bytes = borsh::to_vec(&tx).unwrap();
    for secret in [recs[0].receipts_root, recs[0].state_root, recs[0].beacon_root, record_leaf(&recs[0])] {
        assert!(!bytes.windows(32).any(|w| w == secret), "the record's roots are not in the transaction");
    }
    for slot in recs.iter().map(|r| r.slot) {
        assert!(!bytes.windows(32).any(|w| w == header_account(&LC, &ID, slot).value()), "no header account is named");
    }
    settle(&mut c, &tx).expect("settles");
    assert_eq!(c.instance(&ID), inst, "read-only");

    // A record recorded later than the checkpoint, under the same root.
    let pos = recs.len() - 1;
    let q = Query { chain_id: 1, proof: Proof::Log(receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16)), predicates: vec![] };
    let e = prove(&c, LC, &Keys::new(42), attest_private(ID, root, &recs, pos, q), &[inst_actor]).map(|_| ()).unwrap_err().to_string();
    assert_eq!(code_of(&e), Some(E_BASE + Error::BadInclusion as u32), "another block's receipt against that record: {e}");
}

#[test]
fn private_attestations_refuse_with_typed_codes() {
    dev_mode();
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let recs = records(&m, 0);
    let inst_actor = lc(instance_account(&LC, &ID));
    let root = c.instance(&ID).index.root();
    let try_prove = |c: &Chain, seed, msg| prove(c, LC, &Keys::new(seed), msg, &[inst_actor]).map(|_| ()).map_err(|e| e.to_string());
    // The predicate does not hold: refused inside the proof, nothing to submit.
    let e = try_prove(&c, 51, attest_private(ID, root, &recs, 0, checkpoint_log([7; 32]))).unwrap_err();
    assert_eq!(code_of(&e), Some(E_BASE + Error::PredicateFalse as u32), "{e}");
    // Another chain's statement.
    let mut q = checkpoint_log(transfer());
    q.chain_id = 11_155_111;
    let e = try_prove(&c, 52, attest_private(ID, root, &recs, 0, q)).unwrap_err();
    assert_eq!(code_of(&e), Some(E_BASE + Error::ChainMismatch as u32), "{e}");
    // A record the instance never wrote: not under the root (E7297).
    let mut forged = recs.clone();
    forged[0].beacon_root[0] ^= 1; // a header the instance never verified
    let leaves: Vec<[u8; 32]> = recs.iter().map(record_leaf).collect();
    let msg = Message::AttestPrivate { instance_id: ID, root, position: 0, record: forged[0].clone(), path: index_path(&leaves, 0), query: checkpoint_log(transfer()) };
    let e = try_prove(&c, 53, borsh::to_vec(&msg).unwrap()).unwrap_err();
    assert_eq!(code_of(&e), Some(E_NOT_INDEXED), "{e}");
    // A self-consistent tree over a forged record: proves, but the root is not the instance's (E7296).
    let fake_root = index_root_of(record_leaf(&forged[0]), 0, &index_path(&[record_leaf(&forged[0])], 0));
    let msg = Message::AttestPrivate { instance_id: ID, root: fake_root, position: 0, record: forged[0].clone(), path: index_path(&[record_leaf(&forged[0])], 0), query: Query { chain_id: 1, proof: Proof::Log(receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16)), predicates: vec![] } };
    let e = try_prove(&c, 54, borsh::to_vec(&msg).unwrap());
    match e {
        // The simulation runs the public part against the instance's state: refused before any proof.
        Err(e) => assert_eq!(code_of(&e), Some(E_UNKNOWN_ROOT), "{e}"),
        Ok(()) => panic!("a root the instance never held must be refused"),
    }
}

#[test]
fn two_private_updates_from_one_store_land_once() {
    // Two operators each prove the whole update 1 from the same store (keys
    // of their own); the first settles, the second reaches Advance with a
    // digest the instance no longer has (E7293) and settles nothing.
    dev_mode();
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, k) = mainnet_steps(&m)[0].clone();
    let current = c.instance(&ID);
    let w = witness(&k, &u.bits, AggMode::Subtract);
    let next = lc::apply_update(&current.cfg, &current.store, &u, &k, &w, lc::FAST, &mut |_| {}).unwrap();
    let msg = borsh::to_vec(&Message::Update { instance_id: ID, current: current.clone(), update: u.clone(), committee: k.clone(), witness: w }).unwrap();
    let actors = [lc(instance_account(&LC, &ID)), lc(header_account(&LC, &ID, next.finalized.slot))];
    let a = prove(&c, LC, &Keys::new(71), msg.clone(), &actors).expect("operator A proves");
    let b = prove(&c, LC, &Keys::new(81), msg, &actors).expect("operator B proves");
    settle(&mut c, &a).expect("A lands");
    let after = c.instance(&ID);
    assert_eq!(after.store, next);
    let e = settle(&mut c, &b).unwrap_err();
    println!("B: {e}");
    assert_eq!(c.instance(&ID), after, "the instance moved once");
}

#[test]
fn a_private_update_overtaking_a_public_job_leaves_its_finish_refused() {
    dev_mode();
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, k) = mainnet_steps(&m)[0].clone();
    let current = c.instance(&ID);
    // A public operator opens the job and runs Miller.
    let (_, jid) = begin(&mut c, ID, &current, &u, &k).unwrap();
    miller(&mut c, ID, jid).unwrap();
    let slot = c.job(&ID, &jid).unwrap().next.store.finalized.slot;
    // A private operator's proof of the same update lands first.
    let w = witness(&k, &u.bits, AggMode::Subtract);
    let msg = borsh::to_vec(&Message::Update { instance_id: ID, current: current.clone(), update: u.clone(), committee: k.clone(), witness: w }).unwrap();
    let tx = prove(&c, LC, &Keys::new(91), msg, &[lc(instance_account(&LC, &ID)), lc(header_account(&LC, &ID, slot))]).unwrap();
    settle(&mut c, &tx).unwrap();
    let after = c.instance(&ID);
    // The public Finish verifies, then Advance finds the instance moved on.
    let e = finish(&mut c, ID, jid, slot).unwrap_err();
    assert_eq!(refusal(&e), Some(E_STALE), "{e}");
    assert_eq!(c.instance(&ID), after);
    // Same store, same update: the two paths agree on the result.
    assert_eq!(after, {
        let mut j = c.job(&ID, &jid).expect("the refused Finish left the job").next;
        j.index = after.index.clone();
        j
    });
}

