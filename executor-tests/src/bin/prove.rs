//! Real proving (P.2: proof time and size per action) of the heavy session
//! of each sextant_lc instruction, from the committed binary, with the RISC
//! Zero prover on this machine: `Begin`'s plan (every check but the pairing),
//! `Miller`'s apply, `Finish`'s job apply (the final exponentiation), and an
//! `Attest` apply (the consumer's inclusion proof).
//!
//! Development mode is refused: `RISC0_DEV_MODE` must be unset or 0.
//!
//! `cargo run --release --bin prove [-- begin miller finish attest]`

use lee_core::account::{ProgramShardSelector, ShardData};
use lee_core::program::{AccountMeta, ApplyInput, CallKind, PlanInput};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use sextant_core::lc::{self, AggMode};
use sextant_core::statement::{Cmp, Field, Predicate, Proof, Query};
use sextant_executor_tests::{BIN, ID, LC};
use sextant_host::{mainnet, mainnet_steps, receipt_proof, witness};
use sextant_program::*;
use std::time::Instant;

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn prove(label: &str, bin: &[u8], kind: CallKind, payload: Vec<u8>) {
    let mut stdin = frame(&borsh::to_vec(&kind).unwrap());
    stdin.extend(frame(&payload));
    // SEGMENT_PO2 bounds the prover's memory (default 20; 18 fits a laptop under memory pressure).
    let po2: u32 = std::env::var("SEGMENT_PO2").ok().and_then(|v| v.parse().ok()).unwrap_or(20);
    let env = ExecutorEnv::builder().write_slice(&stdin).segment_limit_po2(po2).build().unwrap();
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, bin, &ProverOpts::succinct()).expect("proving");
    let secs = t.elapsed().as_secs_f64();
    let size = borsh::to_vec(&info.receipt).map(|v| v.len()).unwrap_or(0);
    println!("| {label} | {} | {} | {} | {secs:.1} | {size} |", info.stats.user_cycles, info.stats.total_cycles, info.stats.segments);
}

fn apply_input(account: lee::AccountId, pre: Vec<u8>, effect: &Effect) -> Vec<u8> {
    borsh::to_vec(&ApplyInput {
        self_account_id: LC,
        selector: ProgramShardSelector::new(account, LC),
        pre_data: ShardData::try_from(pre).unwrap(),
        effect_data: borsh::to_vec(effect).unwrap(),
    })
    .unwrap()
}

fn main() {
    assert!(
        std::env::var("RISC0_DEV_MODE").map(|v| v == "0" || v.is_empty()).unwrap_or(true),
        "refusing to benchmark in development mode"
    );
    let which: Vec<String> = std::env::args().skip(1).collect();
    let on = |w: &str| which.is_empty() || which.iter().any(|x| x == w);
    let bin = std::fs::read(BIN).expect("the committed binary");
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let (store, u, committee) = steps[1].clone(); // period 1882, with handoff
    let current = Instance { checkpoint: m.checkpoint, cfg: m.cfg.clone(), store: store.clone() };
    let w = witness(&committee, &u.bits, AggMode::Subtract);
    let p = lc::prepare(&current.cfg, &store, &u, &committee, &w, lc::FAST, &mut |_| {}).unwrap();
    let next = Instance { store: p.next.clone(), ..current.clone() };
    let jid = job_id(&current, &u);
    let job_acc = job_account(&LC, &ID, &jid);
    let mut job = Job { prev: digest(&current), next: digest(&next), pk: p.pk.clone(), hm: p.hm.clone(), sig: p.sig.clone(), f: None };

    println!("| session | user cycles | total cycles (with paging, padding) | segments | prove (s, wall) | succinct receipt (bytes) |");
    println!("|---|---:|---:|---:|---:|---:|");
    if on("begin") {
        let ix = Instruction::Begin { instance_id: ID, current: current.clone(), update: u.clone(), committee: committee.clone(), witness: w.clone() };
        let input = PlanInput {
            self_account_id: LC,
            caller_account_id: None,
            accounts: vec![AccountMeta::new(instance_account(&LC, &ID), false, LC), AccountMeta::new(job_acc, false, LC)],
            instruction_data: borsh::to_vec(&ix).unwrap(),
        };
        prove("`Begin` plan, period 1882 with handoff", &bin, CallKind::Plan, borsh::to_vec(&input).unwrap());
    }
    if on("miller") {
        prove("`Miller` apply", &bin, CallKind::Apply, apply_input(job_acc, borsh::to_vec(&job).unwrap(), &Effect::Miller));
    }
    let f = sextant_core::bl::miller(p.pk.as_slice().try_into().unwrap(), p.hm.as_slice().try_into().unwrap(), p.sig.as_slice().try_into().unwrap()).unwrap();
    job.f = Some(f.to_vec());
    if on("finish") {
        let e = Effect::Close { prev: digest(&current), next: digest(&next) };
        prove("`Finish` job apply (final exponentiation)", &bin, CallKind::Apply, apply_input(job_acc, borsh::to_vec(&job).unwrap(), &e));
    }
    if on("attest") {
        let (sf, uf, cf) = &steps[3];
        let fin = lc::apply_update(&m.cfg, sf, uf, cf, &witness(cf, &uf.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap();
        let rec = record(&m.cfg, &fin);
        let transfer = sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"));
        let q = Query { chain_id: 1, proof: Proof::Log(receipt_proof(2)), predicates: vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer }] };
        prove(
            "`Attest` apply (ERC-20 Transfer log, receipt proof)",
            &bin,
            CallKind::Apply,
            apply_input(header_account(&LC, &ID, rec.slot), borsh::to_vec(&rec).unwrap(), &Effect::Check(q)),
        );
    }
}
