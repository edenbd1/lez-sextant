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
    // Hoodi instance's configuration. Mainnet's slots are past Hoodi's Gloas
    // epoch, so its Fulu-shaped headers fail the Gloas checks; without the
    // Gloas epoch, the signing domain still differs.
    assert_eq!(verdict(&hd.cfg, &ms[1]).unwrap_err(), Error::BadExecutionBranch);
    let mut cfg = hd.cfg.clone();
    cfg.gloas_epoch = u64::MAX;
    assert_eq!(verdict(&cfg, &ms[1]).unwrap_err(), Error::BadSignature);
    // And the reverse.
    assert_eq!(verdict(&mn.cfg, &hs[1]).unwrap_err(), Error::BadSignature);
    // A mainnet update submitted to a Hoodi instance's store: refused before
    // any signature work. Its signature slot, read on Hoodi's clock, lies
    // years after the store's finalized header (E7206); with that bound
    // lifted, its committee was never handed off there.
    let (s, _, _) = &hs[1];
    let (_, u, c) = &ms[1];
    assert_eq!(lc::apply_update(&hd.cfg, s, u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap_err(), Error::CheckpointStale);
    let mut cfg = hd.cfg.clone();
    cfg.max_checkpoint_age = u64::MAX;
    assert_eq!(lc::apply_update(&cfg, s, u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap_err(), Error::HandoffNotVerified);
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

// ---- Sepolia (Gloas): the core with Gloas light-client headers ----

const SEPOLIA: &str = "vectors/sepolia";

#[test]
fn sepolia_verifies_from_the_checkpoint_through_three_handoffs() {
    let m = sepolia();
    assert!(lc::is_gloas(&m.cfg, m.boot_header.beacon.slot), "every header of these vectors is Gloas");
    assert_eq!(lc::period(m.boot_header.beacon.slot), 1385);
    let s = run(&m);
    assert_eq!(lc::period(s.finalized.slot), 1388);
    assert_eq!(s.current_committee, ssz::sync_committee_root(&m.updates[2].next_committee.as_ref().unwrap().0));
    // The finalized beacon block commits to the execution block by hash;
    // its RLP header gives the roots, and they are the block's.
    finalized_block_matches(SEPOLIA, &s);
    assert_eq!(m.finality.finalized.execution.block_hash, h::<32>(&json(&format!("{SEPOLIA}/block.json"))["result"]["hash"]));
}

#[test]
fn sepolia_state_and_receipts_verify_under_the_finalized_block() {
    let s = run(&sepolia());
    history_slot_is_parent_hash(SEPOLIA, &s);
    // WETH9 balanceOf[a recent depositor], as on mainnet.
    let p = weth_proof_from(&format!("{SEPOLIA}/getproof-weth.json"));
    let out: AccountSlot = borsh::from_slice(&mpt::verify_account_storage(&s.finalized_execution_state_root, &p).unwrap()).unwrap();
    let j = json(&format!("{SEPOLIA}/getproof-weth.json"));
    let want = hexv(j["result"]["storageProof"][0]["value"].as_str().unwrap());
    assert_eq!(out.slot_value[32 - want.len()..], want[..]);
    assert_eq!(receipts_verify(SEPOLIA, &s), 2);
}

#[test]
fn the_gloas_fork_is_crossed_by_one_instance() {
    // Checkpoint and first two updates in Fulu, the last two in Gloas: one
    // store, its configuration fixed at Init, follows the chain across.
    let m = sepolia_gloas_fork();
    let steps = mainnet_steps(&m);
    let forks: Vec<bool> = steps.iter().map(|(_, u, _)| lc::is_gloas(&m.cfg, u.attested.beacon.slot)).collect();
    assert_eq!(forks, [false, false, true, true]);
    let s = run(&m);
    assert_eq!(lc::period(s.finalized.slot), 1380);
}

#[test]
fn an_instance_that_does_not_know_gloas_refuses_sepolia() {
    // The deployed program's view (no Gloas epoch in its configuration):
    // every Gloas header shape fails its Merkle checks.
    let mut m = sepolia();
    m.cfg.gloas_epoch = u64::MAX;
    m.boot_header.execution_rlp.clear();
    assert_eq!(lc::bootstrap(&m.cfg, &m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).unwrap_err(), Error::BadExecutionBranch);
    let m = sepolia();
    let steps = mainnet_steps(&m);
    let (s, u, c) = &steps[1];
    let mut cfg = m.cfg.clone();
    cfg.gloas_epoch = u64::MAX;
    let mut u = u.clone();
    u.finalized.execution_rlp.clear();
    assert_eq!(lc::apply_update(&cfg, s, &u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap_err(), Error::BadExecutionBranch);
}

#[test]
fn a_gloas_header_needs_the_execution_header_that_hashes_to_it() {
    let m = sepolia();
    let steps = mainnet_steps(&m);
    let (s, u, c) = &steps[1];
    let verdict = |u: &sextant_core::Update| lc::apply_update(&m.cfg, s, u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {});
    assert!(verdict(u).is_ok());
    // Missing.
    let mut v = u.clone();
    v.finalized.execution_rlp.clear();
    assert_eq!(verdict(&v).unwrap_err(), Error::BadExecutionBranch);
    // Another block's header (the next update's), valid RLP, wrong hash.
    let mut v = u.clone();
    v.finalized.execution_rlp = steps[2].1.finalized.execution_rlp.clone();
    assert_eq!(verdict(&v).unwrap_err(), Error::BadExecutionBranch);
    // A state root of the submitter's choosing: the hash no longer matches.
    let mut v = u.clone();
    let (root, _, _) = mpt::execution_header_roots(&u.finalized.execution.block_hash, &u.finalized.execution_rlp).unwrap();
    let pos = v.finalized.execution_rlp.windows(32).position(|w| w == root).unwrap();
    v.finalized.execution_rlp[pos] ^= 1;
    assert_eq!(verdict(&v).unwrap_err(), Error::BadExecutionBranch);
    // And a block hash that is not the one the beacon block committed to.
    let mut v = u.clone();
    v.finalized.execution.block_hash[0] ^= 1;
    assert_eq!(verdict(&v).unwrap_err(), Error::BadExecutionBranch);
}

#[test]
fn sepolia_and_mainnet_instances_refuse_each_other() {
    let (sp, mn) = (sepolia(), mainnet());
    let (ss, ms) = (mainnet_steps(&sp), mainnet_steps(&mn));
    let verdict = |cfg: &sextant_core::ChainConfig, (s, u, c): &(Store, sextant_core::Update, sextant_core::SyncCommittee)| {
        lc::apply_update(cfg, s, u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {})
    };
    // A mainnet update under a Sepolia instance's configuration. Mainnet
    // slots are past Sepolia's Gloas epoch, so the Electra-shaped update
    // fails the Gloas branch checks before the signature is even looked at.
    assert_eq!(verdict(&sp.cfg, &ms[1]).unwrap_err(), Error::BadExecutionBranch);
    // With the shapes out of the way (Sepolia's configuration without its
    // Gloas epoch), the signing domain still refuses it.
    let mut cfg = sp.cfg.clone();
    cfg.gloas_epoch = u64::MAX;
    assert_eq!(verdict(&cfg, &ms[1]).unwrap_err(), Error::BadSignature);
    // A Sepolia update under mainnet's configuration (no Gloas): a Gloas
    // header is not a Fulu one.
    assert_eq!(verdict(&mn.cfg, &ss[1]).unwrap_err(), Error::Malformed);
    let mut u = ss[1].clone();
    u.1.finalized.execution_rlp.clear();
    assert_eq!(verdict(&mn.cfg, &u).unwrap_err(), Error::BadExecutionBranch);
    // A mainnet update submitted to a Sepolia instance's store: stale on
    // Sepolia's clock (E7206), and with that bound lifted, its committee was
    // never handed off there.
    let (s, _, _) = &ss[1];
    let (_, u, c) = &ms[1];
    assert_eq!(lc::apply_update(&sp.cfg, s, u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap_err(), Error::CheckpointStale);
    let mut cfg = sp.cfg.clone();
    cfg.max_checkpoint_age = u64::MAX;
    assert_eq!(lc::apply_update(&cfg, s, u, c, &witness(c, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap_err(), Error::HandoffNotVerified);
    // And a Sepolia statement offered to a mainnet consumer.
    let r = record(11155111, &run(&sp));
    let q = Query {
        chain_id: 1,
        proof: Proof::Storage(weth_proof_from(&format!("{SEPOLIA}/getproof-weth.json"))),
        predicates: vec![],
    };
    assert_eq!(statement::evaluate(&r, &q).unwrap_err(), Error::ChainMismatch);
}
