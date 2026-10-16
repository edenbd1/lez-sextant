//! Host helpers: decode the beacon-API JSON in `vectors/` into the program's
//! types, build key witnesses, generate synthetic committees, and run a guest
//! in the RISC Zero executor.

use bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use serde_json::Value;
use sextant_core::lc::{self, AggMode};
use sextant_core::{bls, ssz, BeaconHeader, ChainConfig, ExecutionHeader, KeyWitness, LcHeader, Report, Store, SyncCommittee, Update};
use std::path::{Path, PathBuf};

pub fn root_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}

pub fn json(rel: &str) -> Value {
    let p = root_dir().join(rel);
    serde_json::from_slice(&std::fs::read(&p).unwrap_or_else(|_| panic!("read {}", p.display()))).unwrap()
}

/// Hex to bytes; JSON-RPC quantities may have an odd number of digits.
pub fn hexv(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    if s.len() % 2 == 1 { hex::decode(format!("0{s}")).unwrap() } else { hex::decode(s).unwrap() }
}
pub fn h<const N: usize>(v: &Value) -> [u8; N] {
    hexv(v.as_str().unwrap()).try_into().unwrap()
}
fn n(v: &Value) -> u64 {
    v.as_str().unwrap().parse().unwrap()
}

pub fn beacon(j: &Value) -> BeaconHeader {
    BeaconHeader {
        slot: n(&j["slot"]),
        proposer_index: n(&j["proposer_index"]),
        parent_root: h(&j["parent_root"]),
        state_root: h(&j["state_root"]),
        body_root: h(&j["body_root"]),
    }
}

pub fn execution(j: &Value) -> ExecutionHeader {
    let base_fee: u128 = j["base_fee_per_gas"].as_str().unwrap().parse().unwrap();
    let mut bf = [0u8; 32];
    bf[..16].copy_from_slice(&base_fee.to_le_bytes());
    ExecutionHeader {
        parent_hash: h(&j["parent_hash"]),
        fee_recipient: h(&j["fee_recipient"]),
        state_root: h(&j["state_root"]),
        receipts_root: h(&j["receipts_root"]),
        logs_bloom: hexv(j["logs_bloom"].as_str().unwrap()),
        prev_randao: h(&j["prev_randao"]),
        block_number: n(&j["block_number"]),
        gas_limit: n(&j["gas_limit"]),
        gas_used: n(&j["gas_used"]),
        timestamp: n(&j["timestamp"]),
        extra_data: hexv(j["extra_data"].as_str().unwrap()),
        base_fee_per_gas: bf,
        block_hash: h(&j["block_hash"]),
        transactions_root: h(&j["transactions_root"]),
        withdrawals_root: h(&j["withdrawals_root"]),
        blob_gas_used: n(&j["blob_gas_used"]),
        excess_blob_gas: n(&j["excess_blob_gas"]),
    }
}

fn branch(j: &Value) -> Vec<[u8; 32]> {
    j.as_array().unwrap().iter().map(h).collect()
}

/// A `LightClientHeader` in either shape: Capella to Fulu (`execution`, the
/// payload header) or Gloas (`execution_block_hash` only; see `LcHeader`).
pub fn lc_header(j: &Value) -> LcHeader {
    let execution = match j.get("execution_block_hash") {
        Some(bh) => ExecutionHeader { block_hash: h(bh), ..Default::default() },
        None => execution(&j["execution"]),
    };
    LcHeader { beacon: beacon(&j["beacon"]), execution, execution_branch: branch(&j["execution_branch"]), execution_rlp: vec![] }
}

/// Attach the RLP block header a Gloas header's store roots come from
/// (`execution-headers.json`, by block hash). Pre-Gloas headers are left as
/// they are.
pub fn with_rlp(mut hd: LcHeader, j: &Value, rlps: &Value) -> LcHeader {
    if let Some(bh) = j.get("execution_block_hash").and_then(Value::as_str) {
        if let Some(r) = rlps.get(bh).and_then(Value::as_str) {
            hd.execution_rlp = hexv(r);
        }
    }
    hd
}

pub fn committee(j: &Value) -> SyncCommittee {
    SyncCommittee { pubkeys: j["pubkeys"].as_array().unwrap().iter().map(h).collect(), aggregate: h(&j["aggregate_pubkey"]) }
}

pub fn update(d: &Value) -> Update {
    update_with(d, &Value::Null)
}

/// An update whose finalized header carries its RLP execution header (Gloas).
pub fn update_with(d: &Value, rlps: &Value) -> Update {
    Update {
        attested: lc_header(&d["attested_header"]),
        next_committee: d.get("next_sync_committee").map(|c| (committee(c), branch(&d["next_sync_committee_branch"]))),
        finalized: with_rlp(lc_header(&d["finalized_header"]), &d["finalized_header"], rlps),
        finality_branch: branch(&d["finality_branch"]),
        bits: h(&d["sync_aggregate"]["sync_committee_bits"]),
        signature: h(&d["sync_aggregate"]["sync_committee_signature"]),
        signature_slot: n(&d["signature_slot"]),
    }
}

/// A chain's configuration from the beacon-API `genesis.json` and
/// `fork_schedule.json` in its vector directory. Unscheduled forks
/// (`FAR_FUTURE_EPOCH`) are left out. The schedule lists forks in order,
/// phase0 to Fulu then Gloas, so Gloas is its eighth entry.
pub fn chain_config(dir: &str, chain_id: u64) -> ChainConfig {
    let g = json(&format!("{dir}/genesis.json"));
    let f = json(&format!("{dir}/fork_schedule.json"));
    let gloas_epoch = f["data"].get(7).map(|x| n(&x["epoch"])).unwrap_or(u64::MAX);
    let forks = f["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (n(&x["epoch"]), h(&x["current_version"])))
        .filter(|(e, _)| *e != u64::MAX)
        .collect();
    ChainConfig { chain_id, genesis_validators_root: h(&g["data"]["genesis_validators_root"]), forks, min_participants: 342, gloas_epoch }
}

pub fn mainnet_config() -> ChainConfig {
    chain_config("vectors/mainnet", 1)
}

/// A real chain from a vector directory: a bootstrap at the first slot of a
/// sync-committee period, the best update of that period and the next two,
/// and a finality update in the period after (`scripts/fetch-vectors.py`).
/// Mainnet: periods 1881-1884; Hoodi: 505-508; Sepolia: 1385-1388.
pub struct Mainnet {
    pub cfg: ChainConfig,
    pub checkpoint: [u8; 32],
    pub boot_header: LcHeader,
    pub boot_committee: SyncCommittee,
    pub boot_branch: Vec<[u8; 32]>,
    pub updates: Vec<Update>,
    pub finality: Update,
}

/// Any chain's vectors; the type kept its first name.
pub type Vectors = Mainnet;

/// The one file in `dir` named `<prefix>*<suffix>`.
fn one(dir: &str, prefix: &str, suffix: &str) -> String {
    let mut found: Vec<String> = std::fs::read_dir(root_dir().join(dir))
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|f| f.starts_with(prefix) && f.ends_with(suffix))
        .collect();
    assert_eq!(found.len(), 1, "exactly one {prefix}*{suffix} in {dir}");
    format!("{dir}/{}", found.pop().unwrap())
}

/// Without a `finality_update.json` (a range of updates only, e.g. the Gloas
/// fork crossing), the last update plays the finality update's part.
pub fn load_chain(dir: &str, chain_id: u64) -> Vectors {
    let boot = one(dir, "bootstrap-", ".json");
    let b = json(&boot);
    let root = std::fs::read_to_string(root_dir().join(boot.replace(".json", ".root"))).unwrap();
    let rlps = if root_dir().join(dir).join("execution-headers.json").exists() { json(&format!("{dir}/execution-headers.json")) } else { Value::Null };
    let u = json(&one(dir, "updates-", ".json"));
    let mut updates: Vec<Update> = u.as_array().unwrap().iter().map(|x| update_with(&x["data"], &rlps)).collect();
    let finality = if root_dir().join(dir).join("finality_update.json").exists() {
        update_with(&json(&format!("{dir}/finality_update.json"))["data"], &rlps)
    } else {
        updates.pop().unwrap()
    };
    let bh = &b["data"]["header"];
    Mainnet {
        cfg: chain_config(dir, chain_id),
        checkpoint: hexv(root.trim()).try_into().unwrap(),
        boot_header: with_rlp(lc_header(bh), bh, &rlps),
        boot_committee: committee(&b["data"]["current_sync_committee"]),
        boot_branch: branch(&b["data"]["current_sync_committee_branch"]),
        updates,
        finality,
    }
}

pub fn mainnet() -> Mainnet {
    load_chain("vectors/mainnet", 1)
}

/// Hoodi (chain 560048), fetched 2026-10-16: Fulu, the same light-client
/// containers as mainnet.
pub fn hoodi() -> Vectors {
    load_chain("vectors/hoodi", 560048)
}

/// Sepolia (chain 11155111), fetched 2026-10-16: Gloas since epoch 353,024.
pub fn sepolia() -> Vectors {
    load_chain("vectors/sepolia", 11155111)
}

/// Sepolia across the Gloas fork: a Fulu checkpoint (period 1377), a Fulu
/// update, then Gloas updates of periods 1379 and 1380.
pub fn sepolia_gloas_fork() -> Vectors {
    load_chain("vectors/sepolia-gloas-fork", 11155111)
}

/// The signing committee for each step of the real chain, and the store
/// before it, obtained by running the native verifier forward.
pub fn mainnet_steps(m: &Mainnet) -> Vec<(Store, Update, SyncCommittee)> {
    let mut store = lc::bootstrap(&m.cfg, &m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).expect("bootstrap");
    let mut current = m.boot_committee.clone();
    let mut next: Option<SyncCommittee> = None;
    let mut out = vec![];
    for u in m.updates.iter().chain(std::iter::once(&m.finality)) {
        let sp = lc::period(store.finalized.slot);
        let signer = if lc::period(u.signature_slot) == sp { current.clone() } else { next.clone().expect("next known") };
        let w = witness(&signer, &u.bits, AggMode::Subtract);
        let s2 = lc::apply_update(&m.cfg, &store, u, &signer, &w, lc::FAST, &mut |_| {})
            .expect("a real update verifies");
        out.push((store.clone(), u.clone(), signer));
        if lc::period(s2.finalized.slot) == sp + 1 {
            current = next.take().unwrap();
        }
        if let Some((c, _)) = &u.next_committee {
            if s2.next_committee == Some(ssz::sync_committee_root(c)) {
                next = Some(c.clone());
            }
        }
        store = s2;
    }
    out
}

/// Uncompressed points for the keys `mode` needs: every participant (Sum),
/// or the committee aggregate and every non-participant (Subtract).
pub fn witness(c: &SyncCommittee, bits: &[u8; 64], mode: AggMode) -> KeyWitness {
    let dec = |k: &[u8; 48]| G1Affine::from_compressed(k).unwrap().to_uncompressed().to_vec();
    let points = (0..512)
        .filter(|i| bls::bit(bits, *i) == (mode == AggMode::Sum))
        .map(|i| (i as u16, dec(&c.pubkeys[i])))
        .collect();
    KeyWitness { points, aggregate: dec(&c.aggregate) }
}

/// A synthetic committee of 512 keys, a message, and the aggregate signature
/// of the `participants` members selected by `bits_for`.
pub struct Synthetic {
    pub committee: SyncCommittee,
    pub bits: [u8; 64],
    pub msg: [u8; 32],
    pub sig: [u8; 96],
}

/// `participants` of 512 sign: member `i` participates when `(7 i) mod 512 < participants`
/// (7 is a unit mod 512, so exactly `participants` members are selected, spread out).
pub fn synthetic(participants: usize) -> Synthetic {
    let sks: Vec<Scalar> = (0..512u64).map(|i| Scalar::from(0x5e7a_0000_0000 + i * 7919 + 1)).collect();
    let pks: Vec<G1Affine> = sks.iter().map(|s| G1Affine::from(G1Affine::generator() * s)).collect();
    let agg = G1Affine::from(pks.iter().fold(G1Projective::identity(), |a, p| a + p));
    let mut bits = [0u8; 64];
    for i in 0..512 {
        if (7 * i) % 512 < participants {
            bits[i / 8] |= 1 << (i % 8);
        }
    }
    let msg = ssz::hash2(&[0x21; 32], &[0x05; 32]);
    let hm = G2Projective::from(G2Affine::from_uncompressed(&sextant_core::zk::hash_to_g2(&msg)).unwrap());
    let mut s = G2Projective::identity();
    for i in 0..512 {
        if bls::bit(&bits, i) {
            s += hm * sks[i];
        }
    }
    Synthetic {
        committee: SyncCommittee { pubkeys: pks.iter().map(|p| p.to_compressed()).collect(), aggregate: agg.to_compressed() },
        bits,
        msg,
        sig: bls12_381::G2Affine::from(s).to_compressed(),
    }
}

// ---- the executor ----

pub fn guest_bin(which: &str) -> Vec<u8> {
    let rel = match which {
        "accelerated" => "artifacts/bench/sextant_bench.accelerated.elf",
        "stock" => "artifacts/bench/sextant_bench.stock.elf",
        other => other,
    };
    let elf = std::fs::read(root_dir().join(rel)).unwrap_or_else(|_| panic!("build the guests first (scripts/build-guests.sh): {rel}"));
    risc0_binfmt::ProgramBinary::new(&elf, risc0_zkos_v1compat::V1COMPAT_ELF).encode()
}

pub struct Run {
    pub report: Report,
    pub user_cycles: u64,
    pub total_cycles: u64,
    pub segments: usize,
    pub secs: f64,
}

pub fn execute(bin: &[u8], op: &sextant_core::Op) -> Run {
    let input = borsh::to_vec(op).unwrap();
    let env = risc0_zkvm::ExecutorEnv::builder().write_slice(&input).session_limit(Some(1 << 36)).build().unwrap();
    let t = std::time::Instant::now();
    let info = risc0_zkvm::default_executor().execute(env, bin).expect("execution");
    let secs = t.elapsed().as_secs_f64();
    let report: Report = borsh::from_slice(&info.journal.bytes).expect("a Report");
    Run {
        report,
        user_cycles: info.cycles(),
        total_cycles: info.segments.iter().map(|s| 1u64 << s.po2).sum(),
        segments: info.segments.len(),
        secs,
    }
}

// ---- execution-layer proofs (the consumer side) ----

/// `eth_getProof` for WETH's `balanceOf[Uniswap v3 USDC/WETH pool]` (slot
/// `keccak(pool ‖ 3)`) at the block finalized by `finality_update.json`.
pub fn weth_proof() -> sextant_core::mpt::AccountStorageProof {
    weth_proof_from("vectors/mainnet/getproof-weth.json")
}

/// The same storage slot from another `eth_getProof` response (e.g. at the
/// checkpoint's block, `vectors/mainnet/block-26170219/`).
pub fn weth_proof_from(rel: &str) -> sextant_core::mpt::AccountStorageProof {
    let j = json(rel);
    let r = &j["result"];
    let nodes = |v: &Value| v.as_array().unwrap().iter().map(|x| hexv(x.as_str().unwrap())).collect::<Vec<_>>();
    sextant_core::mpt::AccountStorageProof {
        address: h(&r["address"]),
        account_proof: nodes(&r["accountProof"]),
        slot: h(&r["storageProof"][0]["key"]),
        storage_proof: nodes(&r["storageProof"][0]["proof"]),
    }
}

/// A receipt proof built by scripts/receipt_proof.py (root checked there
/// against the block's receiptsRoot), and the index of a log in it.
pub fn receipt_proof(tx: u64) -> sextant_core::mpt::ReceiptProof {
    receipt_proof_from(&format!("vectors/mainnet/receipt-proof-tx{tx}.json"), tx)
}

/// A receipt proof file written by scripts/receipt_proof.py, for transaction `tx`.
pub fn receipt_proof_from(rel: &str, tx: u64) -> sextant_core::mpt::ReceiptProof {
    let j = json(rel);
    sextant_core::mpt::ReceiptProof {
        tx_index: tx,
        proof: j["proof"].as_array().unwrap().iter().map(|x| hexv(x.as_str().unwrap())).collect(),
        log_index: 0,
    }
}
