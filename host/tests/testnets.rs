//! Public Ethereum testnets (Supportability #1), natively, with the same
//! verification core as mainnet: each chain from its checkpoint through three
//! sync-committee handoffs and a finality update, the execution block that
//! update finalizes, a storage slot and a receipt log under it, and the chain
//! binding: an instance of one chain refuses another chain's updates and
//! statements (F.5, F.14).

use sextant_core::lc::{self, AggMode};
use sextant_core::mpt::{self, AccountSlot, Log};
use sextant_core::statement::{self, Field, HeaderRecord, Proof, Query};
use sextant_core::{ssz, Error, Store};
use sextant_host::*;

fn run(m: &Vectors) -> Store {
    let steps = mainnet_steps(m);
    assert_eq!(steps.len(), 4, "three handoffs and a finality update");
    let (s, u, c) = steps.last().unwrap();
    let w = witness(c, &u.bits, AggMode::Subtract);
    lc::apply_update(&m.cfg, s, u, c, &w, lc::FAST, &mut |_| {}).unwrap()
}

/// The finalized store of `m` is the block in `dir/block.json`, whose RLP
/// header (`dir/header.rlp`) hashes to it.
fn finalized_block_matches(dir: &str, s: &Store) {
    let b = &json(&format!("{dir}/block.json"))["result"];
    assert_eq!(s.finalized_execution_state_root, h::<32>(&b["stateRoot"]));
    assert_eq!(s.finalized_receipts_root, h::<32>(&b["receiptsRoot"]));
    assert_eq!(format!("{:#x}", s.finalized_block_number), b["number"].as_str().unwrap());
    let rlp = hexv(std::fs::read_to_string(root_dir().join(format!("{dir}/header.rlp"))).unwrap().trim());
    assert_eq!(mpt::keccak(&rlp), h::<32>(&b["hash"]));
}

/// The EIP-2935 history contract holds block N-1's hash in slot (N-1) mod
/// 8191 of block N's state: a storage fact every post-Prague chain has, and
/// one the vectors can check against the block itself.
fn history_slot_is_parent_hash(dir: &str, s: &Store) {
    let p = weth_proof_from(&format!("{dir}/getproof-history.json"));
    let out: AccountSlot = borsh::from_slice(&mpt::verify_account_storage(&s.finalized_execution_state_root, &p).unwrap()).unwrap();
    let b = &json(&format!("{dir}/block.json"))["result"];
    assert_eq!(out.slot_value, h::<32>(&b["parentHash"]));
}

/// Every committed receipt proof opens to its log under the receipts root.
fn receipts_verify(dir: &str, s: &Store) -> usize {
    let r = json(&format!("{dir}/receipts.json"));
    let mut n = 0;
    for e in std::fs::read_dir(root_dir().join(dir)).unwrap() {
        let f = e.unwrap().file_name().into_string().unwrap();
        let Some(tx) = f.strip_prefix("receipt-proof-tx").and_then(|x| x.strip_suffix(".json")) else { continue };
        let tx: u64 = tx.parse().unwrap();
        let out: Log = borsh::from_slice(&mpt::verify_receipt_log(&s.finalized_receipts_root, &receipt_proof_from(&format!("{dir}/{f}"), tx)).unwrap()).unwrap();
        let l = &r["result"][tx as usize]["logs"][0];
        assert_eq!(out.address, h::<20>(&l["address"]));
        assert_eq!(out.data, hexv(l["data"].as_str().unwrap()));
        n += 1;
    }
    n
}

fn record(cfg_chain: u64, s: &Store) -> HeaderRecord {
    HeaderRecord {
        chain_id: cfg_chain,
        slot: s.finalized.slot,
        beacon_root: ssz::beacon_header_root(&s.finalized),
        block_number: s.finalized_block_number,
        state_root: s.finalized_execution_state_root,
        receipts_root: s.finalized_receipts_root,
    }
}

// ---- Hoodi (Fulu): the core as deployed, unchanged ----

const HOODI: &str = "vectors/hoodi";

#[test]
fn hoodi_verifies_from_the_checkpoint_through_three_handoffs() {
    let m = hoodi();
    assert_eq!(lc::period(m.boot_header.beacon.slot), 505);
    let s = run(&m);
    assert_eq!(lc::period(s.finalized.slot), 508);
    assert_eq!(s.current_committee, ssz::sync_committee_root(&m.updates[2].next_committee.as_ref().unwrap().0));
    finalized_block_matches(HOODI, &s);
}

#[test]
fn hoodi_state_and_receipts_verify_under_the_finalized_block() {
    let s = run(&hoodi());
    history_slot_is_parent_hash(HOODI, &s);
    assert_eq!(receipts_verify(HOODI, &s), 2);
}

#[test]
fn hoodi_and_mainnet_instances_refuse_each_other() {
    let (hd, mn) = (hoodi(), mainnet());
    let (hs, ms) = (mainnet_steps(&hd), mainnet_steps(&mn));
    let verdict = |cfg: &sextant_core::ChainConfig, (s, u, c): &(Store, sextant_core::Update, sextant_core::SyncCommittee)| {
        lc::apply_update(cfg, s, u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {})
    };
    // A mainnet update, with its own committee and store, checked under a
    // Hoodi instance's configuration: the signing domain differs.
    assert_eq!(verdict(&hd.cfg, &ms[1]).unwrap_err(), Error::BadSignature);
    // And the reverse.
    assert_eq!(verdict(&mn.cfg, &hs[1]).unwrap_err(), Error::BadSignature);
    // A mainnet update submitted to a Hoodi instance's store: refused before
    // any signature work, its committee was never handed off there.
    let (s, _, _) = &hs[1];
    let (_, u, c) = &ms[1];
    assert_eq!(lc::apply_update(&hd.cfg, s, u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap_err(), Error::HandoffNotVerified);
}

#[test]
fn a_hoodi_statement_is_refused_by_a_mainnet_consumer() {
    let s = run(&hoodi());
    let r = record(560048, &s);
    let q = |chain_id| Query {
        chain_id,
        proof: Proof::Storage(weth_proof_from(&format!("{HOODI}/getproof-history.json"))),
        predicates: vec![statement::Predicate { field: Field::SlotValue, cmp: statement::Cmp::Ne, value: [0; 32] }],
    };
    assert!(statement::evaluate(&r, &q(560048)).is_ok());
    assert_eq!(statement::evaluate(&r, &q(1)).unwrap_err(), Error::ChainMismatch);
}
