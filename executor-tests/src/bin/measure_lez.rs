//! Gas of every sextant_lc instruction through `lee::V03State`, the state
//! machine the LEZ v0.3 sequencer applies, under the 10,000,000 cap: the real
//! mainnet chain from the checkpoint through three sync-committee handoffs
//! and a finality update, then consumer attestations against the last header.
//!
//! `cargo run --release --bin measure_lez`

use sextant_core::lc;
use sextant_core::statement::{Cmp, Field, Predicate, Proof, Query};
use sextant_executor_tests::*;
use sextant_host::{mainnet, mainnet_steps, receipt_proof, weth_proof};
use sextant_program::{header_account, Instruction};

fn pct(c: u64) -> String {
    format!("{:.1}%", c as f64 * 100.0 / GAS_CAP as f64)
}

fn main() {
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let mut c = Chain::new();
    println!("# sextant_lc through lee::V03State (LEZ v0.3.0), gas cap {GAS_CAP} per transaction\n");
    println!("| transaction | gas (cycles) | share of the cap | signer |");
    println!("|---|---:|---:|---|");
    let g = init(&mut c, &m, ID).expect("init");
    println!("| `Init` from the mainnet checkpoint (slot {}) | {g} | {} | fresh account |", m.boot_header.beacon.slot, pct(g));
    let mut totals = vec![];
    for (i, (_, u, committee)) in steps.iter().enumerate() {
        let what = if u.next_committee.is_some() { "with handoff" } else { "finality only" };
        let [a, b, f] = advance(&mut c, ID, u, committee).expect("a real update advances the instance");
        let p = lc::period(u.signature_slot);
        println!("| update {} (period {p}, {what}): `Begin` | {a} | {} | fresh account |", i + 1, pct(a));
        println!("| update {} (period {p}): `Miller` | {b} | {} | fresh account |", i + 1, pct(b));
        println!("| update {} (period {p}): `Finish` | {f} | {} | fresh account |", i + 1, pct(f));
        totals.push((p, what, a + b + f));
    }
    let s = c.instance(&ID).store;
    let slot = s.finalized.slot;
    let base = |proof, predicates| Instruction::Attest { instance_id: ID, slot, query: Query { chain_id: 1, proof, predicates } };
    let wp = weth_proof();
    let mut bal = [0u8; 32];
    bal[31] = 1;
    let ix = base(Proof::Storage(wp), vec![Predicate { field: Field::SlotValue, cmp: Cmp::Ge, value: bal }]);
    let g = c.send(&ix, vec![header_account(&LC, &ID, slot)]).expect("storage attestation");
    println!("| `Attest`: WETH balance slot of an account ≥ 1 wei, block {} | {g} | {} | fresh account |", s.finalized_block_number, pct(g));
    let rp = receipt_proof(2);
    let transfer = sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"));
    let ix = base(Proof::Log(rp), vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer }]);
    let g = c.send(&ix, vec![header_account(&LC, &ID, slot)]).expect("log attestation");
    println!("| `Attest`: an ERC-20 `Transfer` log in tx 2 of block {} | {g} | {} | fresh account |", s.finalized_block_number, pct(g));
    println!("\n| update | three transactions together |");
    println!("|---|---:|");
    for (p, what, t) in totals {
        println!("| period {p}, {what} | {t} ({:.2}x the cap of one transaction) |", t as f64 / GAS_CAP as f64);
    }
    println!("\nfinal store: slot {slot}, period {}, execution block {}", lc::period(slot), s.finalized_block_number);
    // P.7: what each account holds.
    let inst = c.shard(sextant_program::instance_account(&LC, &ID)).len();
    let rec = c.shard(header_account(&LC, &ID, slot)).len();
    let (_, u, committee) = &steps[0];
    let cur = sextant_program::Instance { checkpoint: m.checkpoint, cfg: m.cfg.clone(), store: steps[0].0.clone() };
    let w = sextant_host::witness(committee, &u.bits, sextant_core::lc::AggMode::Subtract);
    let p = lc::prepare(&cur.cfg, &cur.store, u, committee, &w, lc::FAST, &mut |_| {}).unwrap();
    let job = sextant_program::Job { prev: [0; 32], next: [0; 32], pk: p.pk, hm: p.hm, sig: p.sig, f: Some(vec![0; 576]) };
    let begin = Instruction::Begin { instance_id: ID, current: cur, update: u.clone(), committee: committee.clone(), witness: w };
    println!("\naccount sizes (borsh): instance {inst} bytes (constant), header record {rec} bytes (one per recorded header), job {} bytes (released at Finish)", borsh::to_vec(&job).unwrap().len());
    println!("instruction sizes: Begin with handoff {} bytes", borsh::to_vec(&begin).unwrap().len());
}
