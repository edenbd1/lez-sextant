//! Worst case of an update through `lee::V03State`: a full 512-member
//! committee with every member signing, and with the fewest signers the
//! program accepts (342, two thirds), each with and without a committee
//! handoff. Synthetic keys (`sextant_host::synthetic_chain`), mainnet's
//! configuration, the committed binary; the gas is the cycle count.
//!
//! `cargo run --release --manifest-path executor-tests/Cargo.toml --bin measure_worst`

use sextant_executor_tests::*;
use sextant_core::lc::AggMode;
use sextant_host::{synthetic_chain, witness};
use sextant_program::{instance_account, job_account, job_id, Instruction};

fn pct(c: u64) -> String {
    format!("{:.1}%", c as f64 * 100.0 / GAS_CAP as f64)
}

fn main() {
    println!("# sextant_lc through lee::V03State (LEZ v0.3.0), synthetic 512-key committee, gas cap {GAS_CAP} per transaction\n");
    println!("| signers of 512 | handoff | `Begin` | `Miller` | `Finish` | three together | largest share of the cap |");
    println!("|---:|---|---:|---:|---:|---:|---:|");
    for (n, handoff) in [(512, true), (512, false), (342, true), (342, false)] {
        let (v, committee) = synthetic_chain(n, handoff);
        let mut c = Chain::new();
        init(&mut c, &v, ID).expect("init");
        let [a, b, f] = advance(&mut c, ID, &v.finality, &committee).expect("the update advances the instance");
        println!(
            "| {n} | {} | {a} | {b} | {f} | {} | {} |",
            if handoff { "yes" } else { "no" },
            a + b + f,
            pct(a.max(b).max(f))
        );
    }
    let (v, committee) = synthetic_chain(341, true);
    let mut c = Chain::new();
    init(&mut c, &v, ID).expect("init");
    // Begin sent as is (advance() would stop at its native pre-check).
    let u = &v.finality;
    let current = c.instance(&ID);
    let job = job_account(&LC, &ID, &job_id(&current, u));
    let w = witness(&committee, &u.bits, AggMode::Subtract);
    let begin = Instruction::Begin { instance_id: ID, current, update: u.clone(), committee, witness: w };
    let e = c.send(&begin, vec![instance_account(&LC, &ID), job]);
    println!("\n341 of 512 (below the floor), `Begin`: {}", match e {
        Err(e) => format!("refused, E{}", refusal(&e).map_or("?".into(), |c| c.to_string())),
        Ok(g) => format!("ACCEPTED {g:?}"),
    });
}
