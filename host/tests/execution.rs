//! Inclusion under a finalized header (F.3), natively, on real mainnet data:
//! from the checkpoint to the finalized block of `finality_update.json`, then
//! an account, a storage slot and a receipt log under that block's roots.

use sextant_core::mpt::{self, AccountSlot, Log};
use sextant_core::Error;
use sextant_host::*;

fn finalized_store() -> sextant_core::Store {
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let (s, u, c) = steps.last().unwrap();
    let w = witness(c, &u.bits, sextant_core::lc::AggMode::Subtract);
    sextant_core::lc::apply_update(&m.cfg, s, u, c, &w, sextant_core::lc::FAST, &mut |_| {}).unwrap()
}

#[test]
fn the_finalized_block_is_the_one_the_proofs_are_for() {
    let s = finalized_store();
    let b = json("vectors/mainnet/block.json");
    assert_eq!(s.finalized_execution_state_root, h::<32>(&b["result"]["stateRoot"]));
    assert_eq!(s.finalized_receipts_root, h::<32>(&b["result"]["receiptsRoot"]));
    assert_eq!(format!("{:#x}", s.finalized_block_number), b["result"]["number"].as_str().unwrap());
}

#[test]
fn an_account_and_a_storage_slot_verify_under_the_finalized_state_root() {
    let s = finalized_store();
    let p = weth_proof();
    let out: AccountSlot = borsh::from_slice(&mpt::verify_account_storage(&s.finalized_execution_state_root, &p).unwrap()).unwrap();
    let j = json("vectors/mainnet/getproof-weth.json");
    let want = hexv(j["result"]["storageProof"][0]["value"].as_str().unwrap());
    let mut want32 = [0u8; 32];
    want32[32 - want.len()..].copy_from_slice(&want);
    assert_eq!(out.slot_value, want32, "the pool's WETH balance");
    assert_eq!(out.storage_root, h::<32>(&j["result"]["storageHash"]));
}

#[test]
fn a_receipt_log_verifies_under_the_finalized_receipts_root() {
    let s = finalized_store();
    let out: Log = borsh::from_slice(&mpt::verify_receipt_log(&s.finalized_receipts_root, &receipt_proof(2)).unwrap()).unwrap();
    let r = json("vectors/mainnet/receipts.json");
    let l = &r["result"][2]["logs"][0];
    assert_eq!(out.status, 1);
    assert_eq!(out.address, h::<20>(&l["address"]));
    assert_eq!(out.topics[0], h::<32>(&l["topics"][0]), "ERC-20 Transfer");
    assert_eq!(out.data, hexv(l["data"].as_str().unwrap()));
    // A busy receipt too (tx 0, many logs).
    assert!(mpt::verify_receipt_log(&s.finalized_receipts_root, &receipt_proof(0)).is_ok());
}

#[test]
fn a_tampered_or_misrooted_proof_is_refused() {
    let s = finalized_store();
    let mut p = weth_proof();
    let n = p.storage_proof.len() - 1;
    let last = p.storage_proof[n].len() - 1;
    p.storage_proof[n][last] ^= 1;
    assert_eq!(mpt::verify_account_storage(&s.finalized_execution_state_root, &p).unwrap_err(), Error::BadInclusion);
    // A valid proof against a root that is not the finalized one.
    let mut root = s.finalized_execution_state_root;
    root[0] ^= 1;
    assert_eq!(mpt::verify_account_storage(&root, &weth_proof()).unwrap_err(), Error::BadInclusion);
    // A receipt proof presented as another transaction's.
    let mut r = receipt_proof(2);
    r.tx_index = 3;
    assert_eq!(mpt::verify_receipt_log(&s.finalized_receipts_root, &r).unwrap_err(), Error::BadInclusion);
}
