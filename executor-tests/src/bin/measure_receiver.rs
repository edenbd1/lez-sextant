//! Gas of the erc20_receiver consumer through `lee::V03State`, next to the
//! committed sextant_lc binary: one `Claim` (the consumer's plan and applies
//! plus sextant_lc's `Attest` as a chained call, one transaction), against
//! the same `Attest` sent on its own, for a `Transfer` under the checkpoint's
//! header and one under the header four updates later.
//!
//! `cargo run --release --bin measure_receiver`

use erc20_receiver::{nullifier_account, query, receiver_account, statement_id, word, Instruction as Rx, Receiver, TRANSFER};
use lee::ProgramShardSelector;
use sextant_core::mpt::ReceiptProof;
use sextant_executor_tests::*;
use sextant_host::{h, hexv, json, mainnet, mainnet_steps, receipt_proof, receipt_proof_from};
use sextant_program::{header_account, Instruction};

fn pct(c: u64) -> String {
    format!("{:.1}%", c as f64 * 100.0 / GAS_CAP as f64)
}

struct T {
    what: &'static str,
    block_number: u64,
    token: [u8; 20],
    from: [u8; 20],
    to: [u8; 20],
    amount: [u8; 32],
    proof: ReceiptProof,
}

fn transfer(what: &'static str, receipts: &str, proof: ReceiptProof) -> T {
    let r = json(receipts);
    let rc = &r["result"][proof.tx_index as usize];
    let l = &rc["logs"][proof.log_index as usize];
    let topic = |i: usize| -> [u8; 20] { h::<32>(&l["topics"][i])[12..].try_into().unwrap() };
    T {
        what,
        block_number: u64::from_str_radix(rc["blockNumber"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
        token: h(&l["address"]),
        from: topic(1),
        to: topic(2),
        amount: hexv(l["data"].as_str().unwrap()).try_into().unwrap(),
        proof,
    }
}

fn row(c: &mut Chain, t: &T, slot: u64) -> (usize, usize) {
    let r = Receiver { sextant: LC, instance_id: ID, chain_id: 1, token: t.token, recipient: t.to };
    let q = query(&r, &t.from, &t.amount, t.proof.clone());
    let attest = c.send(&Instruction::Attest { instance_id: ID, slot, query: q }, vec![header_account(&LC, &ID, slot)]).expect("attest");
    let topics = [TRANSFER, word(&t.from), word(&t.to)];
    let id = statement_id(1, t.block_number, &t.proof, &t.token, &topics, &t.amount);
    let rid = receiver_account(&RX, &r);
    let nul = nullifier_account(&RX, &rid, &id);
    let ix = Rx::Claim { receiver: r.clone(), slot, block_number: t.block_number, from: t.from, amount: t.amount, proof: t.proof.clone() };
    let rows = vec![ProgramShardSelector::new(header_account(&LC, &ID, slot), LC), ProgramShardSelector::new(rid, RX), ProgramShardSelector::new(nul, RX)];
    let claim = c.send_to(RX, &ix, rows.clone()).expect("claim");
    let replay = c.send_to(RX, &ix, rows).expect_err("replay");
    assert!(replay.contains("E7391"), "{replay}");
    println!("| {} | {claim} | {} | {attest} | {} | {} |", t.what, pct(claim), claim - attest, borsh::to_vec(&ix).unwrap().len());
    (c.shard_of(nul, RX).len(), c.shard_of(rid, RX).len())
}

fn main() {
    let m = mainnet();
    let mut c = Chain::new().with_receiver();
    init(&mut c, &m, ID).expect("init");
    println!("# erc20_receiver through lee::V03State (LEZ v0.3.0), gas cap {GAS_CAP} per transaction\n");
    println!("| transfer claimed | `Claim` gas (cycles, with the chained `Attest`) | share of the cap | the same `Attest` alone | consumer's own share | `Claim` instruction (bytes) |");
    println!("|---|---:|---:|---:|---:|---:|");
    let slot = c.instance(&ID).store.finalized.slot;
    let a = transfer(
        "USDC `Transfer`, tx 16 of block 26170219 (checkpoint header)",
        "vectors/mainnet/block-26170219/receipts.json",
        receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16),
    );
    let (nul, rcv) = row(&mut c, &a, slot);
    for (_, u, committee) in mainnet_steps(&m) {
        advance(&mut c, ID, &u, &committee).expect("advance");
    }
    let slot = c.instance(&ID).store.finalized.slot;
    let b = transfer("USDC `Transfer`, tx 2 of block 26197200 (after four updates)", "vectors/mainnet/receipts.json", receipt_proof(2));
    let _ = row(&mut c, &b, slot);
    println!("\nA replay of each claim was refused with E7391 (the nullifier is spent).");
    println!("account sizes (borsh): nullifier {nul} bytes (one per claimed transfer), receiver {rcv} bytes (one per receiver)");
}
