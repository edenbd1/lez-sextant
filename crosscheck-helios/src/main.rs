//! Test-only cross-check: replay a live-run chain directory (evidence/live-run/<chain>/)
//! through Helios' consensus-core (a16z/helios 0.12.0, an independent implementation of
//! the Altair light-client sync protocol) and compare, update by update, with the
//! verdicts Sextant's replay (host/src/bin/follow, sextant-core) recorded in
//! verdicts.jsonl: the same updates accepted, the same finalized header (slot and
//! hash-tree root), and the same execution block (number, state root, receipts root).
//!
//!   crosscheck-helios <chain dir> [--verdicts FILE]    prints one JSON line per file;
//!                                                      exit 1 on any disagreement
//!   crosscheck-helios <chain dir> --only-helios        prints Helios' verdicts only
//!
//! Helios applies an update when it verifies and either finalizes a newer header or
//! supplies the next sync committee (apply_generic_update): "applied". It verifies but
//! changes nothing for an update that finalizes no newer header, or whose participation
//! is below 2/3 (it only keeps it as a candidate for force_update): "unchanged". Any
//! verification error is "refused".
use std::{collections::BTreeMap, fs, path::{Path, PathBuf}};

use alloy::{consensus::Header, primitives::{keccak256, B256, FixedBytes}};
use alloy_rlp::Decodable;
use eyre::{eyre, Result};
use helios_consensus_core::{
    apply_bootstrap, apply_generic_update,
    consensus_spec::MainnetConsensusSpec as S,
    types::{Bootstrap, FinalityUpdate, Fork, Forks, GenericUpdate, LightClientHeader, LightClientStore, Update},
    verify_bootstrap, verify_generic_update,
};
use serde_json::{json, Value};
use tree_hash::TreeHash;

fn read(p: &Path) -> Result<Value> {
    Ok(serde_json::from_str(&fs::read_to_string(p).map_err(|e| eyre!("{}: {e}", p.display()))?)?)
}

fn forks(dir: &Path) -> Result<Forks> {
    let sched = read(&dir.join("fork_schedule.json"))?;
    let list = sched["data"].as_array().ok_or(eyre!("fork_schedule.json: no data"))?;
    let mut f: Vec<Fork> = list
        .iter()
        .map(|e| -> Result<Fork> {
            let v = e["current_version"].as_str().unwrap_or_default();
            Ok(Fork {
                epoch: e["epoch"].as_str().unwrap_or("0").parse()?,
                fork_version: FixedBytes::<4>::from_slice(&hex(v)?),
            })
        })
        .collect::<Result<_>>()?;
    // genesis, altair, bellatrix, capella, deneb, electra, fulu, gloas, in schedule order
    let inactive = |prev: &Fork| Fork { epoch: u64::MAX, fork_version: prev.fork_version };
    while f.len() < 8 {
        let last = f.last().cloned().ok_or(eyre!("empty fork schedule"))?;
        f.push(inactive(&last));
    }
    Ok(Forks {
        genesis: f[0].clone(), altair: f[1].clone(), bellatrix: f[2].clone(), capella: f[3].clone(),
        deneb: f[4].clone(), electra: f[5].clone(), fulu: f[6].clone(), gloas: f[7].clone(),
    })
}

fn hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().trim_start_matches("0x");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| eyre!("{e}"))).collect()
}

/// The execution block a light-client header commits to: (block hash, number, state root,
/// receipts root). Pre-Gloas headers carry the payload header; a Gloas header carries only
/// the block hash, so the block's RLP header is looked up and its keccak checked.
fn execution(h: &LightClientHeader, headers: &BTreeMap<String, String>) -> Result<Value> {
    if let Ok(e) = h.execution() {
        return Ok(json!({"block_hash": e.block_hash().to_string(), "block_number": *e.block_number(),
            "state_root": e.state_root().to_string(), "receipts_root": e.receipts_root().to_string()}));
    }
    let bh: B256 = *h.execution_block_hash().map_err(|_| eyre!("header without execution"))?;
    let key = bh.to_string();
    let rlp = hex(headers.get(&key).ok_or(eyre!("no execution header for {key}"))?)?;
    if keccak256(&rlp) != bh {
        return Err(eyre!("execution header for {key} does not hash to it"));
    }
    let hd = Header::decode(&mut rlp.as_slice())?;
    Ok(json!({"block_hash": key, "block_number": hd.number, "state_root": hd.state_root.to_string(),
        "receipts_root": hd.receipts_root.to_string()}))
}

fn store_view(st: &LightClientStore<S>, headers: &BTreeMap<String, String>) -> Value {
    let fh = &st.finalized_header;
    let mut v = json!({
        "finalized_slot": fh.beacon().slot,
        "finalized_root": fh.beacon().tree_hash_root().to_string(),
        "period": fh.beacon().slot / 8192,
        "next_committee_known": st.next_sync_committee.is_some(),
    });
    match execution(fh, headers) {
        Ok(e) => { for (k, x) in e.as_object().unwrap() { v[k] = x.clone(); } }
        Err(e) => { v["execution_error"] = json!(e.to_string()); }
    }
    v
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(args.get(1).ok_or(eyre!("usage: crosscheck-helios <chain dir> [--verdicts FILE] [--only-helios]"))?);
    let only = args.iter().any(|a| a == "--only-helios");
    let vfile = args.iter().position(|a| a == "--verdicts").and_then(|i| args.get(i + 1)).map(PathBuf::from)
        .unwrap_or(dir.join("verdicts.jsonl"));
    let forks = forks(&dir)?;
    let genesis = read(&dir.join("genesis.json"))?;
    let gvr = B256::from_slice(&hex(genesis["data"]["genesis_validators_root"].as_str().unwrap_or_default())?);
    let headers: BTreeMap<String, String> = fs::read_to_string(dir.join("execution-headers.json")).ok()
        .and_then(|s| serde_json::from_str::<BTreeMap<String, String>>(&s).ok())
        .map(|m| m.into_iter().map(|(k, v)| (k.to_lowercase(), v)).collect()).unwrap_or_default();

    // Sextant's verdicts, keyed by file, in the order it replayed them.
    let sextant: Vec<Value> = if only { vec![] } else {
        fs::read_to_string(&vfile)?.lines().filter(|l| !l.trim().is_empty()).map(serde_json::from_str).collect::<Result<_, _>>()?
    };
    let mut order: Vec<String> = sextant.iter().filter_map(|v| v["file"].as_str().map(String::from)).collect();
    if order.is_empty() {
        let mut b: Vec<String> = fs::read_dir(&dir)?.filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.starts_with("bootstrap-") && n.ends_with(".json")).collect();
        b.sort();
        let mut u: Vec<String> = fs::read_dir(dir.join("updates"))?.filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|n| n.ends_with(".json")).collect();
        u.sort();
        order = b.into_iter().chain(u.into_iter()).collect();
    }

    let mut store = LightClientStore::<S>::default();
    let mut disagree = 0usize;
    let mut compared = 0usize;
    for (i, file) in order.iter().enumerate() {
        let mut out = json!({"file": file});
        let verdict;
        if file.starts_with("bootstrap-") {
            let j = read(&dir.join(file))?;
            let root_file = dir.join(file.replace(".json", ".root"));
            let root = B256::from_slice(&hex(&fs::read_to_string(&root_file)?)?);
            let b: Bootstrap<S> = serde_json::from_value(j["data"].clone())?;
            match verify_bootstrap(&b, root, &forks) {
                Ok(()) => { apply_bootstrap(&mut store, &b); verdict = "bootstrap"; }
                Err(e) => { out["error"] = json!(e.to_string()); verdict = "refused"; }
            }
        } else {
            let j = read(&dir.join("updates").join(file))?;
            let d = j["data"].clone();
            let g: Result<GenericUpdate<S>> = if d.get("next_sync_committee").is_some() {
                serde_json::from_value::<Update<S>>(d).map(|u| GenericUpdate::from(&u)).map_err(Into::into)
            } else {
                serde_json::from_value::<FinalityUpdate<S>>(d).map(|u| GenericUpdate::from(&u)).map_err(Into::into)
            };
            match g {
                Err(e) => { out["error"] = json!(format!("decode: {e}")); verdict = "refused"; }
                Ok(g) => {
                    out["signature_slot"] = json!(g.signature_slot);
                    out["attested_slot"] = json!(g.attested_header.beacon().slot);
                    match verify_generic_update::<S>(&g, g.signature_slot, &store, gvr, &forks) {
                        Err(e) => { out["error"] = json!(e.to_string()); verdict = "refused"; }
                        Ok(()) => {
                            let before = (store.finalized_header.beacon().tree_hash_root(), store.next_sync_committee.is_some(),
                                          store.current_sync_committee.clone());
                            apply_generic_update::<S>(&mut store, &g);
                            let after = (store.finalized_header.beacon().tree_hash_root(), store.next_sync_committee.is_some(),
                                         store.current_sync_committee.clone());
                            verdict = if before == after { "unchanged" } else { "applied" };
                        }
                    }
                }
            }
        }
        out["helios"] = json!(verdict);
        if verdict != "refused" { out["store"] = store_view(&store, &headers); }
        if !only {
            if let Some(s) = sextant.get(i) {
                compared += 1;
                let sv = s["verdict"].as_str().unwrap_or("");
                out["sextant"] = json!(sv);
                let mut diffs = vec![];
                if sv != verdict { diffs.push(format!("verdict sextant={sv} helios={verdict}")); }
                if verdict == "applied" || verdict == "bootstrap" {
                    let hs = &out["store"];
                    for k in ["finalized_slot", "finalized_root", "period", "next_committee_known", "block_number", "state_root", "receipts_root"] {
                        let a = &s["store"][k];
                        let b = &hs[k];
                        let eq = match (a.as_str(), b.as_str()) {
                            (Some(x), Some(y)) => x.eq_ignore_ascii_case(y),
                            _ => a == b,
                        };
                        if !eq { diffs.push(format!("{k} sextant={a} helios={b}")); }
                    }
                }
                if !diffs.is_empty() { disagree += 1; out["DISAGREE"] = json!(diffs); }
            }
        }
        println!("{out}");
    }
    if !only {
        eprintln!("{} entries compared, {} disagree", compared, disagree);
        if disagree > 0 || compared == 0 { std::process::exit(1); }
    }
    Ok(())
}
