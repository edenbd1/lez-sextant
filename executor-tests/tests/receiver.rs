//! erc20_receiver, a consumer program, through `lee::V03State` next to the
//! committed sextant_lc binary, on real mainnet data (F.7): a claim calls
//! sextant_lc's `Attest` as a chained call in the same transaction, and a
//! nullifier keyed by the statement identifier makes each transfer claimable
//! once.

use erc20_receiver::{nullifier_account, receiver_account, Claimed, Instruction as Rx, Receiver, Totals, E_CLAIMED, E_HEADER, E_NO_HEADER};
use lee::ProgramShardSelector;
use sextant_core::mpt::ReceiptProof;
use sextant_core::statement::{self, HeaderRecord};
use sextant_core::Error;
use sextant_executor_tests::*;
use sextant_host::{h, hexv, json, mainnet, mainnet_steps, receipt_proof, receipt_proof_from};
use sextant_program::{header_account, E_BASE};

fn code(e: Error) -> u32 {
    E_BASE + e as u32
}

fn refused(r: Result<u64, String>) -> u32 {
    let e = r.expect_err("the claim must be refused");
    any_refusal(&e).unwrap_or_else(|| panic!("no typed refusal in: {e}"))
}

/// One ERC-20 `Transfer` from the vectors: the log, as Ethereum's RPC reports it.
struct Transfer {
    block_number: u64,
    token: [u8; 20],
    from: [u8; 20],
    to: [u8; 20],
    amount: [u8; 32],
    proof: ReceiptProof,
}

fn transfer(receipts: &str, proof: ReceiptProof) -> Transfer {
    let r = json(receipts);
    let rc = &r["result"][proof.tx_index as usize];
    let l = &rc["logs"][proof.log_index as usize];
    let topic = |i: usize| -> [u8; 20] { h::<32>(&l["topics"][i])[12..].try_into().unwrap() };
    Transfer {
        block_number: u64::from_str_radix(rc["blockNumber"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap(),
        token: h(&l["address"]),
        from: topic(1),
        to: topic(2),
        amount: hexv(l["data"].as_str().unwrap()).try_into().unwrap(),
        proof,
    }
}

/// USDC to 0x0658…80c7, tx 16 of block 26,170,219: under the checkpoint's own header.
fn at_checkpoint() -> Transfer {
    transfer("vectors/mainnet/block-26170219/receipts.json", receipt_proof_from("vectors/mainnet/block-26170219/receipt-proof-tx16.json", 16))
}

/// USDC to 0x3e0e…4a58, tx 2 of block 26,197,200: under the header four updates later.
fn at_finality() -> Transfer {
    transfer("vectors/mainnet/receipts.json", receipt_proof(2))
}

fn receiver(instance_id: [u8; 32], t: &Transfer) -> Receiver {
    Receiver { sextant: LC, instance_id, chain_id: 1, token: t.token, recipient: t.to }
}

fn claim(c: &mut Chain, r: &Receiver, slot: u64, t: &Transfer) -> Result<u64, String> {
    claim_as(c, r, slot, t.block_number, t.amount, t)
}

fn claim_as(c: &mut Chain, r: &Receiver, slot: u64, block_number: u64, amount: [u8; 32], t: &Transfer) -> Result<u64, String> {
    let topics = [erc20_receiver::TRANSFER, erc20_receiver::word(&t.from), erc20_receiver::word(&r.recipient)];
    let id = erc20_receiver::statement_id(r.chain_id, block_number, &t.proof, &r.token, &topics, &amount);
    let rid = receiver_account(&RX, r);
    let ix = Rx::Claim { receiver: r.clone(), slot, block_number, from: t.from, amount, proof: t.proof.clone() };
    let rows = vec![
        ProgramShardSelector::new(header_account(&LC, &r.instance_id, slot), LC),
        ProgramShardSelector::new(rid, RX),
        ProgramShardSelector::new(nullifier_account(&RX, &rid, &id), RX),
    ];
    c.send_to(RX, &ix, rows)
}

fn totals(c: &Chain, r: &Receiver) -> Option<Totals> {
    let d = c.shard_of(receiver_account(&RX, r), RX);
    (!d.is_empty()).then(|| borsh::from_slice(&d).unwrap())
}

fn record(c: &Chain, instance_id: &[u8; 32], slot: u64) -> HeaderRecord {
    borsh::from_slice(&c.shard_of(header_account(&LC, instance_id, slot), LC)).unwrap()
}

#[test]
fn a_transfer_is_credited_once_and_its_replay_is_refused() {
    let m = mainnet();
    let mut c = Chain::new().with_receiver();
    init(&mut c, &m, ID).unwrap();
    let slot = c.instance(&ID).store.finalized.slot;
    let t = at_checkpoint();
    let r = receiver(ID, &t);
    let gas = claim(&mut c, &r, slot, &t).unwrap();
    assert!(gas < GAS_CAP, "{gas}");
    assert_eq!(totals(&c, &r), Some(Totals { claims: 1, total: t.amount }));

    // The nullifier holds sextant's own statement identifier for this log.
    let q = erc20_receiver::query(&r, &t.from, &t.amount, t.proof.clone());
    let st = statement::evaluate(&record(&c, &ID, slot), &q).unwrap();
    let rid = receiver_account(&RX, &r);
    let n: Claimed = borsh::from_slice(&c.shard_of(nullifier_account(&RX, &rid, &st.id), RX)).unwrap();
    assert_eq!(n.statement_id, st.id);
    assert_eq!((n.block_number, n.tx_index, n.amount), (26_170_219, 16, t.amount));

    // The same transfer again, by another fresh account: refused, nothing credited.
    assert_eq!(refused(claim(&mut c, &r, slot, &t)), E_CLAIMED);
    assert_eq!(totals(&c, &r), Some(Totals { claims: 1, total: t.amount }));

    // A second light-client instance of the same chain records the same header:
    // the statement identifier is the same there (F.6), so a receiver bound to
    // that instance has its own nullifier for it, and the first stays spent.
    let other = *b"mainnet/test/instance/0000000002";
    init(&mut c, &m, other).unwrap();
    assert_eq!(statement::evaluate(&record(&c, &other, slot), &q).unwrap().id, st.id);
    let r2 = receiver(other, &t);
    claim(&mut c, &r2, slot, &t).unwrap();
    assert_eq!(refused(claim(&mut c, &r2, slot, &t)), E_CLAIMED);
    assert_eq!(refused(claim(&mut c, &r, slot, &t)), E_CLAIMED);
}

#[test]
fn a_wrong_predicate_is_refused_by_attest_and_nothing_is_credited() {
    let m = mainnet();
    let mut c = Chain::new().with_receiver();
    init(&mut c, &m, ID).unwrap();
    let slot = c.instance(&ID).store.finalized.slot;
    let t = at_checkpoint();
    let r = receiver(ID, &t);
    // A larger amount than the log carries.
    let mut more = t.amount;
    more[31] = more[31].wrapping_add(1);
    assert_eq!(refused(claim_as(&mut c, &r, slot, t.block_number, more, &t)), code(Error::PredicateFalse));
    // Another recipient: a receiver for an address the log does not pay.
    let mut thief = r.clone();
    thief.recipient[19] ^= 1;
    assert_eq!(refused(claim(&mut c, &thief, slot, &t)), code(Error::PredicateFalse));
    // Another token contract.
    let mut token = r.clone();
    token.token[0] ^= 1;
    assert_eq!(refused(claim(&mut c, &token, slot, &t)), code(Error::PredicateFalse));
    // Another chain's id in the receiver.
    let mut chain = r.clone();
    chain.chain_id = 11_155_111;
    assert_eq!(refused(claim(&mut c, &chain, slot, &t)), E_HEADER);
    assert_eq!((totals(&c, &r), totals(&c, &thief), totals(&c, &token)), (None, None, None));
    // The genuine claim still lands afterwards: the refusals spent nothing.
    claim(&mut c, &r, slot, &t).unwrap();
}

#[test]
fn a_claim_against_an_unrecorded_header_is_refused() {
    let m = mainnet();
    let mut c = Chain::new().with_receiver();
    init(&mut c, &m, ID).unwrap();
    let slot = c.instance(&ID).store.finalized.slot;
    // The later transfer, before the updates that finalize its block have run.
    let later = at_finality();
    let r = receiver(ID, &later);
    let final_slot = mainnet_steps(&m).last().unwrap().1.finalized.beacon.slot;
    assert_eq!(refused(claim(&mut c, &r, final_slot, &later)), E_NO_HEADER);
    // Presented under the checkpoint's header instead: the block number is not that header's...
    assert_eq!(refused(claim(&mut c, &r, slot, &later)), E_HEADER);
    // ...and with the header's block number, the proof is not under its receipts root.
    assert_eq!(refused(claim_as(&mut c, &r, slot, 26_170_219, later.amount, &later)), code(Error::BadInclusion));
    assert_eq!(totals(&c, &r), None);
    // Once the light client has advanced to that block, the same claim lands.
    for (_, u, committee) in mainnet_steps(&m) {
        advance(&mut c, ID, &u, &committee).unwrap();
    }
    assert_eq!(c.instance(&ID).store.finalized.slot, final_slot);
    claim(&mut c, &r, final_slot, &later).unwrap();
    assert_eq!(totals(&c, &r), Some(Totals { claims: 1, total: later.amount }));
    assert_eq!(refused(claim(&mut c, &r, final_slot, &later)), E_CLAIMED);
}
