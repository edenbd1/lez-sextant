//! F.6, the statement identifier (`sextant_core::statement::evaluate`,
//! decision D6), on real mainnet proofs: identical for the same header and
//! statement, different for different state. A consumer keys its nullifier
//! on it (programs/erc20_receiver), so both directions matter: a repeat must
//! collide, and two different facts must not.

use sextant_core::mpt::ReceiptProof;
use sextant_core::statement::{evaluate, Cmp, Field, HeaderRecord, Predicate, Proof, Query};
use sextant_host::*;

/// What sextant_lc records for a finalized header, from the block itself.
fn header(dir: &str) -> HeaderRecord {
    let b = json(&format!("{dir}/block.json"));
    let r = &b["result"];
    HeaderRecord {
        chain_id: 1,
        slot: 0, // the beacon slot does not enter the identifier
        beacon_root: [0; 32],
        block_number: u64::from_str_radix(r["number"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
        state_root: h(&r["stateRoot"]),
        receipts_root: h(&r["receiptsRoot"]),
    }
}

const LATER: &str = "vectors/mainnet";
const CHECKPOINT: &str = "vectors/mainnet/block-26170219";

fn transfer_topic() -> [u8; 32] {
    h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"))
}

fn log(p: ReceiptProof, predicates: Vec<Predicate>) -> Query {
    Query { chain_id: 1, proof: Proof::Log(p), predicates }
}

fn id(r: &HeaderRecord, q: &Query) -> [u8; 32] {
    evaluate(r, q).unwrap().id
}

#[test]
fn f6_the_statement_identifier_is_identical_for_the_same_header_and_statement() {
    let r = header(LATER);
    let is_transfer = Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer_topic() };
    let q = log(receipt_proof(2), vec![is_transfer.clone()]);
    // Twice, and from an independently rebuilt header record and proof.
    assert_eq!(id(&r, &q), id(&header(LATER), &log(receipt_proof(2), vec![is_transfer.clone()])));
    // It names the proven fact, not the question asked about it: the same log
    // with no predicate, or a different one that also holds, is the same statement.
    let not_zero = Predicate { field: Field::LogDataWord(0), cmp: Cmp::Gt, value: [0; 32] };
    assert_eq!(id(&r, &q), id(&r, &log(receipt_proof(2), vec![])));
    assert_eq!(id(&r, &q), id(&r, &log(receipt_proof(2), vec![not_zero, is_transfer])));
    // Under the same header the beacon slot and root do not enter it, so two
    // light-client instances recording that header agree on it.
    let mut elsewhere = r.clone();
    elsewhere.slot = 13_201_312;
    elsewhere.beacon_root = [7; 32];
    assert_eq!(id(&r, &q), id(&elsewhere, &q));
    // A storage fact is the same statement whichever finalized block it is
    // read at, as long as the state is the same (D6): same proof, header
    // records that differ only in block number and slot.
    let s = Query { chain_id: 1, proof: Proof::Storage(weth_proof()), predicates: vec![] };
    let mut later_block = r.clone();
    later_block.block_number += 1;
    later_block.slot += 1;
    assert_eq!(id(&r, &s), id(&later_block, &s));
}

#[test]
fn f6_the_statement_identifier_differs_for_different_state() {
    let (later, checkpoint) = (header(LATER), header(CHECKPOINT));
    // Two different Transfer logs, in two blocks.
    let a = id(&later, &log(receipt_proof(2), vec![]));
    let b = id(&checkpoint, &log(receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16), vec![]));
    assert_ne!(a, b);
    // Two logs of one receipt (tx 0 of block 26,197,200 has several).
    let first = receipt_proof(0);
    let mut second = first.clone();
    second.log_index = 1;
    assert_ne!(id(&later, &log(first, vec![])), id(&later, &log(second, vec![])));
    // The same log under a header of another block number: an event is unique
    // to its block, so it is another statement.
    let mut renumbered = later.clone();
    renumbered.block_number -= 1;
    assert_ne!(a, id(&renumbered, &log(receipt_proof(2), vec![])));
    // The same roots on another chain.
    let mut sepolia = later.clone();
    sepolia.chain_id = 11_155_111;
    let mut q = log(receipt_proof(2), vec![]);
    q.chain_id = 11_155_111;
    assert_ne!(a, id(&sepolia, &q));
    // The same storage slot at two blocks where it holds different values.
    let s_later = Query { chain_id: 1, proof: Proof::Storage(weth_proof()), predicates: vec![] };
    let s_then = Query { chain_id: 1, proof: Proof::Storage(weth_proof_from("vectors/mainnet/block-26170219/getproof-weth.json")), predicates: vec![] };
    let value = |dir: &str| json(&format!("{dir}/getproof-weth.json"))["result"]["storageProof"][0]["value"].clone();
    assert_ne!(value(LATER), value(CHECKPOINT), "the pool's WETH balance moved between the two blocks");
    assert_ne!(id(&later, &s_later), id(&checkpoint, &s_then));
}
