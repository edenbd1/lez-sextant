//! Cycles (the execution gas a transaction is charged) of every sextant_lc
//! message through `lee::V03State` at LEZ v0.4.0-rc3, under the 10,000,000
//! cap: the real mainnet chain from the checkpoint through three
//! sync-committee handoffs and a finality update, then consumer attestations
//! against the last header. The v0.3 column is executor-tests' `measure_lez`
//! (docs/BENCHMARKS.md, docs/ONCHAIN.md), the same vectors.
//!
//! `cargo run --release --bin measure_lez`

use sextant_core::lc;
use sextant_core::statement::{Cmp, Field, Predicate, Proof, Query};
use sextant_executor_tests_v04::*;
use sextant_host::{mainnet, mainnet_steps, receipt_proof, weth_proof};
use sextant_program_v04::{header_account, instance_account, Message};

fn pct(c: u64) -> String {
    format!("{:.1}%", c as f64 * 100.0 / GAS_CAP as f64)
}

fn main() {
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let mut c = Chain::new();
    println!("# sextant_lc through lee::V03State (LEZ v0.4.0-rc3), gas cap {GAS_CAP} per transaction\n");
    println!("| transaction | cycles charged | share of the cap | actor runs |");
    println!("|---|---:|---:|---:|");
    let o = init(&mut c, &m, ID).expect("init");
    println!("| `Init` from the mainnet checkpoint (slot {}) | {} | {} | 2 |", m.boot_header.beacon.slot, o.cycles, pct(o.cycles));
    let mut totals = vec![];
    let mut sizes = vec![];
    for (i, (_, u, committee)) in steps.iter().enumerate() {
        let what = if u.next_committee.is_some() { "with handoff" } else { "finality only" };
        if i == 0 {
            let cur = c.instance(&ID);
            sizes.push(("Begin with handoff", borsh::to_vec(&begin_message(&cur, ID, u, committee)).unwrap().len()));
        }
        let [a, b, f] = advance(&mut c, ID, u, committee).expect("a real update advances the instance");
        let p = lc::period(u.signature_slot);
        println!("| update {} (period {p}, {what}): `Begin` | {a} | {} | 2 |", i + 1, pct(a));
        println!("| update {} (period {p}): `Miller` | {b} | {} | 1 |", i + 1, pct(b));
        println!("| update {} (period {p}): `Finish` | {f} | {} | 3 |", i + 1, pct(f));
        totals.push((p, what, a + b + f));
    }
    let s = c.instance(&ID).store;
    let slot = s.finalized.slot;
    let base = |proof, predicates| Message::Attest { instance_id: ID, slot, query: Query { chain_id: 1, proof, predicates } };
    let mut bal = [0u8; 32];
    bal[31] = 1;
    let to = lc(header_account(&LC, &ID, slot));
    let ix = base(Proof::Storage(weth_proof()), vec![Predicate { field: Field::SlotValue, cmp: Cmp::Ge, value: bal }]);
    let g = c.send("Attest", to, &[], &[], &ix).expect("storage attestation").cycles;
    println!("| `Attest`: WETH balance slot of an account ≥ 1 wei, block {} | {g} | {} | 1 |", s.finalized_block_number, pct(g));
    let transfer = sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"));
    let ix = base(Proof::Log(receipt_proof(2)), vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer }]);
    let g = c.send("Attest", to, &[], &[], &ix).expect("log attestation").cycles;
    println!("| `Attest`: an ERC-20 `Transfer` log in tx 2 of block {} | {g} | {} | 1 |", s.finalized_block_number, pct(g));
    println!("\n| update | three transactions together |");
    println!("|---|---:|");
    for (p, what, t) in totals {
        println!("| period {p}, {what} | {t} ({:.2}x the cap of one transaction) |", t as f64 / GAS_CAP as f64);
    }
    println!("\nfinal store: slot {slot}, period {}, execution block {}", lc::period(slot), s.finalized_block_number);
    let inst = c.state_of(instance_account(&LC, &ID)).len();
    let rec = c.state_of(header_account(&LC, &ID, slot)).len();
    println!("actor state sizes (borsh): instance {inst} bytes, header record {rec} bytes");
    for (what, n) in sizes {
        println!("message size: {what} {n} bytes");
    }
}
