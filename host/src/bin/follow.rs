//! `follow DIR CHAIN_ID`: replay a live light-client log with sextant-core,
//! the verifier the sextant_lc guest runs, from the directory's bootstrap
//! through every update in `DIR/updates/` (in signature-slot order, the order
//! the fetcher named them in), and print one JSON line per update and a last
//! `final` line with the store it ends in.
//!
//! The directory is what `scripts/live-follow.py` writes: genesis.json,
//! fork_schedule.json, bootstrap-<slot>.json and .root (the checkpoint, served
//! identically by two beacon implementations), updates/<signature slot>-<kind>.json
//! (each `{"data": LightClientUpdate}` as a beacon API served it), and
//! execution-headers.json (the RLP execution headers Gloas light-client headers
//! commit to by hash only). Nothing here trusts the fetcher: every update is
//! checked against the store the previous ones built (sync-committee
//! signature, finality and committee branches, the handoff rules), and one the
//! verifier refuses is reported and leaves the store unchanged.
//!
//! The verdicts are deterministic: anyone can rerun this on the committed
//! directory and get the same lines.
use serde_json::{json, Value};
use sextant_core::lc::{self, AggMode};
use sextant_core::{ssz, Store, SyncCommittee, Update};
use sextant_host::{chain_config, committee, hexv, json as read_json, lc_header, root_dir, update_with, with_rlp, witness};

fn hex(b: &[u8]) -> String {
    format!("0x{}", ::hex::encode(b))
}

fn store_json(s: &Store) -> Value {
    json!({
        "finalized_slot": s.finalized.slot,
        "finalized_root": hex(&ssz::beacon_header_root(&s.finalized)),
        "period": lc::period(s.finalized.slot),
        "block_number": s.finalized_block_number,
        "state_root": hex(&s.finalized_execution_state_root),
        "receipts_root": hex(&s.finalized_receipts_root),
        "next_committee_known": s.next_committee.is_some(),
    })
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    assert!(a.len() == 3, "usage: follow DIR CHAIN_ID (DIR relative to the repository)");
    let (dir, chain_id) = (a[1].trim_end_matches('/').to_string(), a[2].parse::<u64>().expect("chain id"));
    let cfg = chain_config(&dir, chain_id);
    let names = |sub: &str| -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(root_dir().join(&dir).join(sub))
            .map(|r| r.filter_map(|e| e.ok()?.file_name().into_string().ok()).collect())
            .unwrap_or_default();
        v.sort();
        v
    };
    let boot = names("").into_iter().find(|f| f.starts_with("bootstrap-") && f.ends_with(".json")).expect("a bootstrap");
    let b = read_json(&format!("{dir}/{boot}"));
    let root = std::fs::read_to_string(root_dir().join(&dir).join(boot.replace(".json", ".root"))).expect("bootstrap root");
    let rlps = if root_dir().join(&dir).join("execution-headers.json").exists() {
        read_json(&format!("{dir}/execution-headers.json"))
    } else {
        Value::Null
    };
    let bh = &b["data"]["header"];
    let boot_header = with_rlp(lc_header(bh), bh, &rlps);
    let boot_committee = committee(&b["data"]["current_sync_committee"]);
    let branch: Vec<[u8; 32]> = b["data"]["current_sync_committee_branch"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| hexv(x.as_str().unwrap()).try_into().unwrap())
        .collect();
    let checkpoint: [u8; 32] = hexv(root.trim()).try_into().unwrap();
    let mut store = match lc::bootstrap(&cfg, &checkpoint, &boot_header, &boot_committee, &branch) {
        Ok(s) => s,
        Err(e) => {
            println!("{}", json!({"file": boot, "verdict": "refused", "error": format!("{e:?}")}));
            std::process::exit(1);
        }
    };
    println!("{}", json!({"file": boot, "verdict": "bootstrap", "store": store_json(&store)}));

    let mut current: SyncCommittee = boot_committee;
    let mut next: Option<SyncCommittee> = None;
    let (mut applied, mut refused) = (0u64, 0u64);
    for f in names("updates") {
        if !f.ends_with(".json") {
            continue;
        }
        let j = read_json(&format!("{dir}/updates/{f}"));
        let u: Update = update_with(&j["data"], &rlps);
        let sp = lc::period(store.finalized.slot);
        let signer = if lc::period(u.signature_slot) == sp { Some(current.clone()) } else { next.clone() };
        let res = match &signer {
            None => Err("HandoffNotVerified (next committee unknown)".to_string()),
            Some(c) => {
                let w = witness(c, &u.bits, AggMode::Subtract);
                lc::apply_update(&cfg, &store, &u, c, &w, lc::FAST, &mut |_| {}).map_err(|e| format!("{e:?}"))
            }
        };
        let base = json!({
            "file": f,
            "signature_slot": u.signature_slot,
            "attested_slot": u.attested.beacon.slot,
            "finalized_slot_in_update": u.finalized.beacon.slot,
            "participants": u.bits.iter().map(|x| x.count_ones()).sum::<u32>(),
        });
        match res {
            Ok(s2) => {
                if lc::period(s2.finalized.slot) == sp + 1 {
                    current = next.take().expect("handoff to a known committee");
                }
                if let Some((c, _)) = &u.next_committee {
                    if s2.next_committee == Some(ssz::sync_committee_root(c)) {
                        next = Some(c.clone());
                    }
                }
                store = s2;
                applied += 1;
                let mut l = base;
                l["verdict"] = json!("applied");
                l["store"] = store_json(&store);
                println!("{l}");
            }
            Err(e) if e == "AlreadyApplied" => {
                // A finality update that finalizes nothing newer (the next one
                // inside the same epoch, or a duplicate): valid, no change.
                let mut l = base;
                l["verdict"] = json!("unchanged");
                l["error"] = json!(e);
                println!("{l}");
            }
            Err(e) => {
                refused += 1;
                let mut l = base;
                l["verdict"] = json!("refused");
                l["error"] = json!(e);
                println!("{l}");
            }
        }
    }
    println!("{}", json!({"final": true, "applied": applied, "refused": refused, "store": store_json(&store)}));
}
