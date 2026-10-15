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

pub fn lc_header(j: &Value) -> LcHeader {
    LcHeader { beacon: beacon(&j["beacon"]), execution: execution(&j["execution"]), execution_branch: branch(&j["execution_branch"]) }
}

pub fn committee(j: &Value) -> SyncCommittee {
    SyncCommittee { pubkeys: j["pubkeys"].as_array().unwrap().iter().map(h).collect(), aggregate: h(&j["aggregate_pubkey"]) }
}

pub fn update(d: &Value) -> Update {
    Update {
        attested: lc_header(&d["attested_header"]),
        next_committee: d.get("next_sync_committee").map(|c| (committee(c), branch(&d["next_sync_committee_branch"]))),
        finalized: lc_header(&d["finalized_header"]),
        finality_branch: branch(&d["finality_branch"]),
        bits: h(&d["sync_aggregate"]["sync_committee_bits"]),
        signature: h(&d["sync_aggregate"]["sync_committee_signature"]),
        signature_slot: n(&d["signature_slot"]),
    }
}

pub fn mainnet_config() -> ChainConfig {
    let g = json("vectors/mainnet/genesis.json");
    let f = json("vectors/mainnet/fork_schedule.json");
    let forks = f["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| (n(&x["epoch"]), h(&x["current_version"])))
        .filter(|(e, _)| *e != u64::MAX)
        .collect();
    ChainConfig { chain_id: 1, genesis_validators_root: h(&g["data"]["genesis_validators_root"]), forks, min_participants: 342 }
}

/// The real mainnet chain in `vectors/mainnet`: a bootstrap at the first
/// slot of period 1881, the best update of periods 1881-1883, and a recent
/// finality update in period 1884.
pub struct Mainnet {
    pub cfg: ChainConfig,
    pub checkpoint: [u8; 32],
    pub boot_header: LcHeader,
    pub boot_committee: SyncCommittee,
    pub boot_branch: Vec<[u8; 32]>,
    pub updates: Vec<Update>,
    pub finality: Update,
}

pub fn mainnet() -> Mainnet {
    let b = json("vectors/mainnet/bootstrap-15409152.json");
    let root = std::fs::read_to_string(root_dir().join("vectors/mainnet/bootstrap-15409152.root")).unwrap();
    let u = json("vectors/mainnet/updates-1881-1883.json");
    let f = json("vectors/mainnet/finality_update.json");
    Mainnet {
        cfg: mainnet_config(),
        checkpoint: hexv(root.trim()).try_into().unwrap(),
        boot_header: lc_header(&b["data"]["header"]),
        boot_committee: committee(&b["data"]["current_sync_committee"]),
        boot_branch: branch(&b["data"]["current_sync_committee_branch"]),
        updates: u.as_array().unwrap().iter().map(|x| update(&x["data"])).collect(),
        finality: update(&f["data"]),
    }
}

/// The signing committee for each step of the real chain, and the store
/// before it, obtained by running the native verifier forward.
pub fn mainnet_steps(m: &Mainnet) -> Vec<(Store, Update, SyncCommittee)> {
    let mut store = lc::bootstrap(&m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).expect("bootstrap");
    let mut current = m.boot_committee.clone();
    let mut next: Option<SyncCommittee> = None;
    let mut out = vec![];
    for u in m.updates.iter().chain(std::iter::once(&m.finality)) {
        let sp = lc::period(store.finalized.slot);
        let signer = if lc::period(u.signature_slot) == sp { current.clone() } else { next.clone().expect("next known") };
        let w = witness(&signer, &u.bits, AggMode::Subtract);
        let s2 = lc::apply_update(&m.cfg, &store, u, &signer, &w, lc::FAST, &mut |_| {})
            .expect("a real mainnet update verifies");
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
    let j = json("vectors/mainnet/getproof-weth.json");
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
    let j = json(&format!("vectors/mainnet/receipt-proof-tx{tx}.json"));
    sextant_core::mpt::ReceiptProof {
        tx_index: tx,
        proof: j["proof"].as_array().unwrap().iter().map(|x| hexv(x.as_str().unwrap())).collect(),
        log_index: 0,
    }
}
