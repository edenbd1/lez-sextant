//! Real proving (P.2: proof time and size per action) of the heavy actor run
//! of each v0.4 sextant_lc message, from v04/artifacts/sextant_lc.bin, with
//! the RISC Zero prover on this machine: `Begin` at the instance (every check
//! but the pairing), `Miller` at the job, `Finish` at the job (the final
//! exponentiation), and an `Attest` at a header record. Each run is the guest
//! session LEZ v0.4 executes for that actor (`actor_entrypoint!`: one framed
//! `ReceiveInput`, one committed `Transition`).
//!
//! Development mode is refused: `RISC0_DEV_MODE` must be unset or 0.
//!
//! `cargo run --release --bin prove [-- begin miller finish attest]`

use lee::Actor;
use lee_core::program::ReceiveInput;
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use sextant_core::lc::{self, AggMode};
use sextant_core::statement::{Cmp, Field, Predicate, Proof, Query};
use sextant_executor_tests_v04::{bin, ID, LC};
use sextant_host::{mainnet, mainnet_steps, receipt_proof, witness};
use sextant_program_v04::*;
use std::time::Instant;

fn frame(bytes: &[u8]) -> Vec<u8> {
    let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(bytes);
    out
}

fn prove(label: &str, bin: &[u8], input: &ReceiveInput) {
    let stdin = frame(&borsh::to_vec(input).unwrap());
    // SEGMENT_PO2 bounds the prover's memory (default 20; 18 fits a laptop under memory pressure).
    let po2: u32 = std::env::var("SEGMENT_PO2").ok().and_then(|v| v.parse().ok()).unwrap_or(20);
    let env = ExecutorEnv::builder().write_slice(&stdin).segment_limit_po2(po2).build().unwrap();
    let t = Instant::now();
    let info = default_prover().prove_with_opts(env, bin, &ProverOpts::succinct()).expect("proving");
    let secs = t.elapsed().as_secs_f64();
    let size = borsh::to_vec(&info.receipt).map(|v| v.len()).unwrap_or(0);
    println!("| {label} | {} | {} | {} | {secs:.1} | {size} |", info.stats.user_cycles, info.stats.total_cycles, info.stats.segments);
}

fn input(account: lee::AccountId, from: Option<Actor>, pre: Vec<u8>, message: Vec<u8>) -> ReceiveInput {
    ReceiveInput { receiver: Actor::new(account, LC), from, is_authorized: false, pre_state: pre.into(), message }
}

fn main() {
    assert!(
        std::env::var("RISC0_DEV_MODE").map(|v| v == "0" || v.is_empty()).unwrap_or(true),
        "refusing to benchmark in development mode"
    );
    let which: Vec<String> = std::env::args().skip(1).collect();
    let on = |w: &str| which.is_empty() || which.iter().any(|x| x == w);
    let bin = bin();
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let (store, u, committee) = steps[1].clone(); // period 1882, with handoff
    // The instance's index after Init and update 1: the checkpoint's record, then update 1's if it moved.
    let mut index = Index::new();
    index.append(record_leaf(&record(&m.cfg, &steps[0].0)));
    if store.finalized.slot != steps[0].0.finalized.slot {
        index.append(record_leaf(&record(&m.cfg, &store)));
    }
    let current = Instance { checkpoint: m.checkpoint, cfg: m.cfg.clone(), store: store.clone(), index };
    let w = witness(&committee, &u.bits, AggMode::Subtract);
    let p = lc::prepare(&current.cfg, &store, &u, &committee, &w, lc::FAST, &mut |_| {}).unwrap();
    let next = Instance { store: p.next.clone(), ..current.clone() };
    let jid = job_id(&current, &u);
    let job_acc = job_account(&LC, &ID, &jid);
    let mut job = Job { instance_id: ID, prev: digest(&current), next, pk: p.pk.clone(), hm: p.hm.clone(), sig: p.sig.clone(), f: None };

    println!("| actor run (v0.4 binary) | user cycles | total cycles (with paging, padding) | segments | prove (s, wall) | succinct receipt (bytes) |");
    println!("|---|---:|---:|---:|---:|---:|");
    if on("begin") {
        let msg = Message::Begin { instance_id: ID, current: digest(&current), update: u.clone(), committee: committee.clone(), witness: w.clone() };
        let i = input(instance_account(&LC, &ID), None, borsh::to_vec(&current).unwrap(), borsh::to_vec(&msg).unwrap());
        prove("`Begin` at the instance, period 1882 with handoff", &bin, &i);
    }
    if on("miller") {
        let msg = Message::Miller { instance_id: ID, job_id: jid };
        prove("`Miller` at the job", &bin, &input(job_acc, None, borsh::to_vec(&job).unwrap(), borsh::to_vec(&msg).unwrap()));
    }
    let f = sextant_core::bl::miller(p.pk.as_slice().try_into().unwrap(), p.hm.as_slice().try_into().unwrap(), p.sig.as_slice().try_into().unwrap()).unwrap();
    job.f = Some(f.to_vec());
    if on("finish") {
        let msg = Message::Finish { instance_id: ID, job_id: jid };
        prove("`Finish` at the job (final exponentiation)", &bin, &input(job_acc, None, borsh::to_vec(&job).unwrap(), borsh::to_vec(&msg).unwrap()));
    }
    if on("attest") {
        let (sf, uf, cf) = &steps[3];
        let fin = lc::apply_update(&m.cfg, sf, uf, cf, &witness(cf, &uf.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap();
        let rec = record(&m.cfg, &fin);
        let transfer = sextant_host::h::<32>(&serde_json::json!("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"));
        let q = Query { chain_id: 1, proof: Proof::Log(receipt_proof(2)), predicates: vec![Predicate { field: Field::LogTopic(0), cmp: Cmp::Eq, value: transfer }] };
        let msg = Message::Attest { instance_id: ID, slot: rec.slot, query: q };
        prove("`Attest` at a header record (ERC-20 Transfer log, receipt proof)", &bin, &input(header_account(&LC, &ID, rec.slot), None, borsh::to_vec(&rec).unwrap(), borsh::to_vec(&msg).unwrap()));
    }
}
