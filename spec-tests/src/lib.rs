//! The official consensus-spec light-client test vectors
//! (`ethereum/consensus-specs` release v1.7.0-beta.4, `spec-tests/vectors/`)
//! against sextant-core.
//!
//! - `single_merkle_proof` (mainnet preset; Electra, Fulu, Gloas): sextant-core
//!   derives each proof's leaf from the test's object (the sync-committee
//!   root, the execution payload header root, the Gloas block hash, the
//!   finalized root) and checks the proof at its own generalized index
//!   against the object's root (`derived/`, computed by the pinned pyspec).
//! - `sync` (minimal preset only; Electra, Fulu, Gloas): bootstrap and every
//!   `process_update` step through `lc::bootstrap` and `lc::apply_update` on
//!   the program's path (`lc::FAST`: witnessed keys, aggregate minus
//!   non-signers, blst), compared with the spec store's finalized header after
//!   each step. Run on [`minimal`], the same source with the minimal preset.

use serde_yaml::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// sextant-core's source, compiled with the consensus minimal preset
/// (`build.rs` lists and counts every substitution).
#[allow(warnings, clippy::all)]
pub mod minimal {
    include!(concat!(env!("OUT_DIR"), "/minimal.rs"));
}

pub const RELEASE: &str = "v1.7.0-beta.4";
pub const FORKS: &[&str] = &["electra", "fulu", "gloas"];

pub fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("vectors/tests")
}

fn unsnappy(p: &Path) -> Vec<u8> {
    let c = std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()));
    snap::raw::Decoder::new().decompress_vec(&c).expect("snappy")
}

fn yaml(p: &Path) -> Value {
    serde_yaml::from_slice(&std::fs::read(p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))).expect("yaml")
}

fn hx<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s.trim_start_matches("0x")).expect("hex").try_into().expect("length")
}

fn ys(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("a string: {v:?}"))
}

/// The outcome of one test case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every check agrees with the spec.
    Pass,
    /// Agrees wherever the design applies; `why` says where it does not.
    PassScoped(String),
    Fail(String),
}

#[derive(Clone, Debug)]
pub struct Case {
    pub suite: String,
    pub fork: String,
    pub name: String,
    pub outcome: Outcome,
    /// What was compared: steps, checks.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// single_merkle_proof (mainnet preset, sextant-core itself)
// ---------------------------------------------------------------------------

pub fn single_merkle_proof() -> Vec<Case> {
    single_merkle_proof_with(false)
}

/// `tamper`: flip one bit of every object root, so that no proof may verify.
pub fn single_merkle_proof_with(tamper: bool) -> Vec<Case> {
    use sextant_core::lc::{self, split};
    use sextant_core::{ssz, ChainConfig, ExecutionHeader, LcHeader};
    let derived: serde_json::Value =
        serde_json::from_slice(&std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("derived/single_merkle_proof.json")).unwrap()).unwrap();
    let j = |v: &serde_json::Value| v.as_str().unwrap().to_string();
    let mut out = vec![];
    for row in derived.as_array().unwrap() {
        let (fork, typ, case) = (j(&row["fork"]), j(&row["type"]), j(&row["case"]));
        let dir = vectors().join(format!("mainnet/{fork}/light_client/single_merkle_proof/{typ}/{case}"));
        let proof = yaml(&dir.join("proof.yaml"));
        let leaf: [u8; 32] = hx(ys(&proof["leaf"]));
        let gindex = proof["leaf_index"].as_u64().unwrap();
        let branch: Vec<[u8; 32]> = proof["branch"].as_sequence().unwrap().iter().map(|b| hx(ys(b))).collect();
        let mut root: [u8; 32] = hx(&j(&row["object_root"]));
        if tamper {
            root[31] ^= 1;
        }
        let gloas = fork == "gloas";
        // A configuration in which the test's fork is the one in force.
        let cfg = ChainConfig {
            chain_id: 1,
            genesis_validators_root: [0; 32],
            forks: vec![(0, [0; 4])],
            min_participants: 342,
            genesis_time: 0,
            max_checkpoint_age: 1,
            gloas_epoch: if gloas { 0 } else { u64::MAX },
        };
        let gi = |(d, i): (usize, u64)| (1u64 << d) + i;
        let mut fails = vec![];
        let (ours, our_leaf, verified) = match case.as_str() {
            "current_sync_committee_merkle_proof" | "next_sync_committee_merkle_proof" => {
                let c = &row["committee"];
                let committee = sextant_core::SyncCommittee {
                    pubkeys: c["pubkeys"].as_array().unwrap().iter().map(|k| hx(&j(k))).collect(),
                    aggregate: hx(&j(&c["aggregate_pubkey"])),
                };
                let current = case.starts_with("current");
                let (d, i) = match (gloas, current) {
                    (true, true) => split(lc::CURRENT_COMMITTEE_GINDEX_GLOAS),
                    (true, false) => split(lc::NEXT_COMMITTEE_GINDEX_GLOAS),
                    (false, true) => (lc::CURRENT_COMMITTEE_DEPTH, lc::CURRENT_COMMITTEE_INDEX),
                    (false, false) => (lc::NEXT_COMMITTEE_DEPTH, lc::NEXT_COMMITTEE_INDEX),
                };
                let l = ssz::sync_committee_root(&committee);
                (gi((d, i)), l, ssz::is_valid_merkle_branch(&l, &branch, d, i, &root))
            }
            "finality_root_merkle_proof" => {
                let (d, i) = if gloas { split(lc::FINALIZED_ROOT_GINDEX_GLOAS) } else { (lc::FINALIZED_ROOT_DEPTH, lc::FINALIZED_ROOT_INDEX) };
                let l: [u8; 32] = hx(&j(&row["finalized_root"]));
                (gi((d, i)), l, ssz::is_valid_merkle_branch(&l, &branch, d, i, &root))
            }
            "execution_merkle_proof" | "execution_block_hash_merkle_proof" => {
                let execution = if gloas {
                    ExecutionHeader { block_hash: hx(&j(&row["block_hash"])), ..Default::default() }
                } else {
                    let e = &row["execution"];
                    let n = |k: &str| j(&e[k]).parse::<u64>().unwrap();
                    let b = |k: &str| hex::decode(j(&e[k]).trim_start_matches("0x")).unwrap();
                    ExecutionHeader {
                        parent_hash: hx(&j(&e["parent_hash"])),
                        fee_recipient: hx(&j(&e["fee_recipient"])),
                        state_root: hx(&j(&e["state_root"])),
                        receipts_root: hx(&j(&e["receipts_root"])),
                        logs_bloom: b("logs_bloom"),
                        prev_randao: hx(&j(&e["prev_randao"])),
                        block_number: n("block_number"),
                        gas_limit: n("gas_limit"),
                        gas_used: n("gas_used"),
                        timestamp: n("timestamp"),
                        extra_data: b("extra_data"),
                        base_fee_per_gas: hx(&j(&e["base_fee_per_gas_le"])),
                        block_hash: hx(&j(&e["block_hash"])),
                        transactions_root: hx(&j(&e["transactions_root"])),
                        withdrawals_root: hx(&j(&e["withdrawals_root"])),
                        blob_gas_used: n("blob_gas_used"),
                        excess_blob_gas: n("excess_blob_gas"),
                    }
                };
                let l = if gloas { execution.block_hash } else { ssz::execution_header_root(&execution) };
                let g = if gloas { lc::EXECUTION_BLOCK_HASH_GINDEX_GLOAS } else { gi((lc::EXECUTION_DEPTH, lc::EXECUTION_INDEX)) };
                // `is_valid_light_client_header`, through the program's own check.
                let h = LcHeader {
                    beacon: sextant_core::BeaconHeader { slot: 0, proposer_index: 0, parent_root: [0; 32], state_root: [0; 32], body_root: root },
                    execution,
                    execution_branch: branch.clone(),
                    execution_rlp: vec![],
                };
                (g, l, lc::check_execution(&cfg, &h).is_ok())
            }
            other => panic!("unknown case {other}"),
        };
        if ours != gindex {
            fails.push(format!("generalized index: spec {gindex}, sextant {ours}"));
        }
        if our_leaf != leaf {
            fails.push(format!("leaf: spec 0x{}, sextant 0x{}", hex::encode(leaf), hex::encode(our_leaf)));
        }
        if !verified {
            fails.push("the proof does not verify against the object's root".into());
        }
        out.push(Case {
            suite: "single_merkle_proof".into(),
            fork,
            name: format!("{typ}/{case}"),
            outcome: if fails.is_empty() { Outcome::Pass } else { Outcome::Fail(fails.join("; ")) },
            detail: format!("gindex {gindex}, depth {}", branch.len()),
        });
    }
    out
}

// ---------------------------------------------------------------------------
// sync (minimal preset, the minimal copy of sextant-core)
// ---------------------------------------------------------------------------

use minimal::{BeaconHeader, ChainConfig, ExecutionHeader, KeyWitness, LcHeader, Store, SyncCommittee, Update};

const N: usize = 32; // SYNC_COMMITTEE_SIZE, minimal
const BITS: usize = N / 8;
const COMMITTEE_BYTES: usize = N * 48 + 48;
/// Electra branch lengths (gindices 86/87, 169, 25).
const E_COMMITTEE: usize = 6;
const E_FINALITY: usize = 7;
const E_EXECUTION: usize = 4;
/// Gloas branch lengths (gindices 2945/2946, 735, 2856).
const G_COMMITTEE: usize = 11;
const G_FINALITY: usize = 9;
const G_EXECUTION: usize = 11;
const G_HEADER: usize = 112 + 32 + G_EXECUTION * 32;

struct R<'a>(&'a [u8], usize);
impl<'a> R<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.0[self.1..self.1 + n];
        self.1 += n;
        s
    }
    fn root(&mut self) -> [u8; 32] {
        self.take(32).try_into().unwrap()
    }
    fn u64(&mut self) -> u64 {
        u64::from_le_bytes(self.take(8).try_into().unwrap())
    }
    fn u32(&mut self) -> usize {
        u32::from_le_bytes(self.take(4).try_into().unwrap()) as usize
    }
    fn roots(&mut self, n: usize) -> Vec<[u8; 32]> {
        (0..n).map(|_| self.root()).collect()
    }
}

fn beacon(r: &mut R) -> BeaconHeader {
    BeaconHeader { slot: r.u64(), proposer_index: r.u64(), parent_root: r.root(), state_root: r.root(), body_root: r.root() }
}

fn committee(r: &mut R) -> SyncCommittee {
    SyncCommittee { pubkeys: (0..N).map(|_| r.take(48).try_into().unwrap()).collect(), aggregate: r.take(48).try_into().unwrap() }
}

/// An Electra/Fulu `ExecutionPayloadHeader` (the Deneb shape).
fn execution(b: &[u8]) -> ExecutionHeader {
    let mut r = R(b, 0);
    let parent_hash = r.root();
    let fee_recipient = r.take(20).try_into().unwrap();
    let state_root = r.root();
    let receipts_root = r.root();
    let logs_bloom = r.take(256).to_vec();
    let prev_randao = r.root();
    let (block_number, gas_limit, gas_used, timestamp) = (r.u64(), r.u64(), r.u64(), r.u64());
    let extra_off = r.u32();
    let base_fee_per_gas = r.root();
    let block_hash = r.root();
    let transactions_root = r.root();
    let withdrawals_root = r.root();
    let (blob_gas_used, excess_blob_gas) = (r.u64(), r.u64());
    assert_eq!(extra_off, r.1, "extra_data follows the fixed part");
    ExecutionHeader {
        parent_hash,
        fee_recipient,
        state_root,
        receipts_root,
        logs_bloom,
        prev_randao,
        block_number,
        gas_limit,
        gas_used,
        timestamp,
        extra_data: b[extra_off..].to_vec(),
        base_fee_per_gas,
        block_hash,
        transactions_root,
        withdrawals_root,
        blob_gas_used,
        excess_blob_gas,
    }
}

/// A `LightClientHeader` in its Electra shape (variable size).
fn header_electra(b: &[u8]) -> LcHeader {
    let mut r = R(b, 0);
    let beacon = beacon(&mut r);
    let off = r.u32();
    let execution_branch = r.roots(E_EXECUTION);
    assert_eq!(off, r.1);
    LcHeader { beacon, execution: execution(&b[off..]), execution_branch, execution_rlp: vec![] }
}

/// A `LightClientHeader` in its Gloas shape: `execution_block_hash` only.
/// Returns `None` for a pre-Gloas header carried in that shape (the spec's
/// normalized legacy header: no payload header, which a pre-Gloas sextant
/// header needs).
fn header_gloas(r: &mut R, cfg: &ChainConfig) -> Result<LcHeader, String> {
    let beacon = beacon(r);
    let block_hash = r.root();
    let execution_branch = r.roots(G_EXECUTION);
    if beacon.slot / minimal::lc::SLOTS_PER_EPOCH < cfg.gloas_epoch && beacon != BeaconHeader::empty() {
        return Err(format!("a pre-Gloas header (slot {}) in the Gloas container", beacon.slot));
    }
    Ok(LcHeader { beacon, execution: ExecutionHeader { block_hash, ..Default::default() }, execution_branch, execution_rlp: vec![] })
}

trait Empty {
    fn empty() -> Self;
}
impl Empty for BeaconHeader {
    fn empty() -> Self {
        BeaconHeader { slot: 0, proposer_index: 0, parent_root: [0; 32], state_root: [0; 32], body_root: [0; 32] }
    }
}

fn bootstrap(b: &[u8], cfg: &ChainConfig) -> Result<(LcHeader, SyncCommittee, Vec<[u8; 32]>), String> {
    if b.len() == G_HEADER + COMMITTEE_BYTES + G_COMMITTEE * 32 {
        let mut r = R(b, 0);
        let h = header_gloas(&mut r, cfg)?;
        Ok((h, committee(&mut r), r.roots(G_COMMITTEE)))
    } else {
        let mut r = R(b, 0);
        let off = r.u32();
        let c = committee(&mut r);
        let br = r.roots(E_COMMITTEE);
        assert_eq!(off, r.1);
        Ok((header_electra(&b[off..]), c, br))
    }
}

fn zero(br: &[[u8; 32]]) -> bool {
    br.iter().all(|x| x == &[0; 32])
}

fn update(b: &[u8], cfg: &ChainConfig) -> Result<Update, String> {
    let gloas_len = 2 * G_HEADER + COMMITTEE_BYTES + G_COMMITTEE * 32 + G_FINALITY * 32 + BITS + 96 + 8;
    let mut r = R(b, 0);
    let (attested, next, next_branch, finalized, finality_branch);
    if b.len() == gloas_len {
        attested = header_gloas(&mut r, cfg)?;
        next = committee(&mut r);
        next_branch = r.roots(G_COMMITTEE);
        finalized = header_gloas(&mut r, cfg)?;
        finality_branch = r.roots(G_FINALITY);
    } else {
        let a_off = r.u32();
        next = committee(&mut r);
        next_branch = r.roots(E_COMMITTEE);
        let f_off = r.u32();
        finality_branch = r.roots(E_FINALITY);
        let rest = r.1;
        attested = header_electra(&b[a_off..f_off]);
        finalized = header_electra(&b[f_off..]);
        r.1 = rest;
    }
    let bits: [u8; BITS] = r.take(BITS).try_into().unwrap();
    let signature: [u8; 96] = r.take(96).try_into().unwrap();
    let signature_slot = r.u64();
    Ok(Update {
        attested,
        // `is_sync_committee_update`: a non-zero branch.
        next_committee: if zero(&next_branch) { None } else { Some((next, next_branch)) },
        finalized,
        finality_branch,
        bits,
        signature,
        signature_slot,
    })
}

/// `get_lc_execution_root` of a header as sextant-core reads it.
fn execution_root(cfg: &ChainConfig, h: &LcHeader) -> [u8; 32] {
    if minimal::lc::is_gloas(cfg, h.beacon.slot) {
        h.execution.block_hash
    } else {
        minimal::ssz::execution_header_root(&h.execution)
    }
}

/// `config.yaml` read line by line (it holds integers past u64, e.g.
/// TERMINAL_TOTAL_DIFFICULTY, that YAML parsers reject).
fn config(dir: &Path, gvr: [u8; 32]) -> ChainConfig {
    let text = std::fs::read_to_string(dir.join("config.yaml")).unwrap();
    let kv: HashMap<&str, &str> = text.lines().filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.trim(), v.trim().trim_matches('\''))).collect();
    let ver = |k: &str| -> [u8; 4] { hx(kv[k]) };
    let ep = |k: &str| -> u64 { kv.get(k).map_or(u64::MAX, |v| v.parse().unwrap()) };
    let mut forks = vec![(0, ver("GENESIS_FORK_VERSION"))];
    for f in ["ALTAIR", "BELLATRIX", "CAPELLA", "DENEB", "ELECTRA", "FULU", "GLOAS"] {
        let (e, k) = (ep(&format!("{f}_FORK_EPOCH")), format!("{f}_FORK_VERSION"));
        if e != u64::MAX && kv.contains_key(k.as_str()) {
            forks.push((e, ver(&k)));
        }
    }
    ChainConfig {
        chain_id: 0,
        genesis_validators_root: gvr,
        forks,
        // ceil(2/3 * 32): the spec applies an update only at a supermajority.
        min_participants: 22,
        genesis_time: 0,
        // The spec's store has no weak-subjectivity bound in these tests.
        max_checkpoint_age: u64::MAX / 4,
        gloas_epoch: ep("GLOAS_FORK_EPOCH"),
    }
}

fn witness(c: &SyncCommittee, bits: &[u8; BITS]) -> KeyWitness {
    let unc = |k: &[u8; 48]| blst::min_pk::PublicKey::uncompress(k).expect("a G1 point").serialize().to_vec();
    let points = (0..N).filter(|i| !minimal::bls::bit(bits, *i)).map(|i| (i as u16, unc(&c.pubkeys[i]))).collect();
    KeyWitness { points, aggregate: unc(&c.aggregate) }
}

pub fn sync() -> Vec<Case> {
    sync_with(|_| {})
}

/// Every update passes through `tamper` before sextant-core sees it.
pub fn sync_with(tamper: fn(&mut Update)) -> Vec<Case> {
    let mut out = vec![];
    for fork in FORKS {
        let base = vectors().join(format!("minimal/{fork}/light_client/sync/pyspec_tests"));
        let mut names: Vec<String> = std::fs::read_dir(&base).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
        names.sort();
        for name in names {
            let (outcome, detail) = sync_case(&base.join(&name), tamper);
            out.push(Case { suite: "sync".into(), fork: fork.to_string(), name, outcome, detail });
        }
    }
    out
}

fn sync_case(dir: &Path, tamper: fn(&mut Update)) -> (Outcome, String) {
    use minimal::{lc, ssz};
    let meta = yaml(&dir.join("meta.yaml"));
    let cfg = config(dir, hx(ys(&meta["genesis_validators_root"])));
    let trusted: [u8; 32] = hx(ys(&meta["trusted_block_root"]));
    let (bh, bc, bb) = match bootstrap(&unsnappy(&dir.join("bootstrap.ssz_snappy")), &cfg) {
        Ok(x) => x,
        Err(e) => return (Outcome::PassScoped(format!("bootstrap not representable: {e}")), "0 steps".into()),
    };
    let mut store: Store = match lc::bootstrap(&cfg, &trusted, &bh, &bc, &bb) {
        Ok(s) => s,
        Err(e) => return (Outcome::Fail(format!("bootstrap refused: {e:?}")), String::new()),
    };
    // Full committees by root (the store holds roots only), and the
    // execution root sextant-core computes for each header it may record.
    let mut committees: HashMap<[u8; 32], SyncCommittee> = HashMap::new();
    committees.insert(ssz::sync_committee_root(&bc), bc.clone());
    let mut exec_roots: HashMap<[u8; 32], [u8; 32]> = HashMap::new();
    exec_roots.insert(ssz::beacon_header_root(&bh.beacon), execution_root(&cfg, &bh));

    let steps = yaml(&dir.join("steps.yaml"));
    let (mut applied, mut refused, mut agree, mut checks) = (0, 0, 0, 0);
    // Why sextant's store may legitimately trail the spec's from here on.
    let mut excused: Vec<String> = vec![];
    let mut fails: Vec<String> = vec![];
    // Steps where sextant's store may differ from the spec's in a way the
    // finalized-header checks do not show.
    let mut scoped: Vec<String> = vec![];
    let mut refusals: HashMap<String, usize> = HashMap::new();
    for (k, step) in steps.as_sequence().unwrap().iter().enumerate() {
        let (kind, body) = step.as_mapping().unwrap().iter().next().map(|(k, v)| (ys(k).to_string(), v.clone())).unwrap();
        match kind.as_str() {
            "process_update" => {
                let file = ys(&body["update"]).trim().to_string();
                match update(&unsnappy(&dir.join(format!("{file}.ssz_snappy"))), &cfg) {
                    Err(e) => {
                        excused.push(format!("step {k}: {e}"));
                        refused += 1;
                    }
                    Ok(mut u) => {
                        tamper(&mut u);
                        if let Some((c, _)) = &u.next_committee {
                            committees.insert(ssz::sync_committee_root(c), c.clone());
                        }
                        exec_roots.insert(ssz::beacon_header_root(&u.finalized.beacon), execution_root(&cfg, &u.finalized));
                        let sp = lc::period(store.finalized.slot);
                        let want = if lc::period(u.signature_slot) == sp { Some(store.current_committee) } else { store.next_committee };
                        let signer = want.and_then(|r| committees.get(&r)).unwrap_or(&bc).clone();
                        let w = witness(&signer, &u.bits);
                        let res = lc::apply_update(&cfg, &store, &u, &signer, &w, lc::FAST, &mut |_| {});
                        if std::env::var("SPEC_TRACE").is_ok() {
                            eprintln!("{:?} step {k}: store {} att {} fin {} sig {} n {} next {} -> {:?}", dir.file_name().unwrap(), store.finalized.slot, u.attested.beacon.slot, u.finalized.beacon.slot, u.signature_slot, minimal::bls::participants(&u.bits), u.next_committee.is_some(), res.as_ref().map(|s| s.finalized.slot));
                        }
                        match res {
                            Ok(s) => {
                                store = s;
                                applied += 1;
                            }
                            Err(e) => {
                                refused += 1;
                                *refusals.entry(format!("{e:?}")).or_default() += 1;
                                // `update_has_finalized_next_sync_committee` with the
                                // genesis checkpoint as the finalized header: the spec
                                // takes the next committee from it, sextant needs a
                                // provable finalized header. Only possible in the first
                                // period after genesis.
                                if u.finalized.beacon.slot == 0 && u.next_committee.is_some() && store.next_committee.is_none() {
                                    scoped.push(format!("step {k}: next committee from an update finalizing genesis, refused ({e:?})"));
                                }
                            }
                        }
                    }
                }
            }
            "force_update" => excused.push(format!("step {k}: force_update (sextant applies finalized updates only)")),
            "upgrade_store" => {} // sextant's store has one shape for every fork
            other => fails.push(format!("step {k}: unknown step {other}")),
        }
        let Some(f) = body.get("checks").and_then(|c| c.get("finalized_header")) else { continue };
        checks += 1;
        let (slot, root): (u64, [u8; 32]) = (f["slot"].as_u64().unwrap(), hx(ys(&f["beacon_root"])));
        let ours = ssz::beacon_header_root(&store.finalized);
        if ours == root && store.finalized.slot == slot {
            agree += 1;
            let want: [u8; 32] = hx(ys(&f["execution_root"]));
            if exec_roots.get(&ours) != Some(&want) {
                fails.push(format!("step {k}: execution root differs from the spec's"));
            }
        } else if store.finalized.slot < slot && !excused.is_empty() {
            // Behind, after a step the design does not take: expected.
        } else if store.finalized.slot < slot {
            fails.push(format!("step {k}: sextant finalized slot {} behind the spec's {slot} with no excuse", store.finalized.slot));
        } else {
            fails.push(format!("step {k}: sextant finalized slot {} (0x{}) where the spec has {slot} (0x{})", store.finalized.slot, hex::encode(ours), hex::encode(root)));
        }
    }
    let mut r: Vec<_> = refusals.into_iter().collect();
    r.sort();
    let detail = format!(
        "{} steps, {applied} updates applied, {refused} refused{}; finalized header agrees at {agree} of {checks} checks",
        steps.as_sequence().unwrap().len(),
        if r.is_empty() { String::new() } else { format!(" ({})", r.iter().map(|(e, n)| format!("{n} {e}")).collect::<Vec<_>>().join(", ")) }
    );
    let outcome = if !fails.is_empty() {
        Outcome::Fail(fails.join("; "))
    } else if agree < checks || !scoped.is_empty() {
        Outcome::PassScoped(excused.into_iter().filter(|_| agree < checks).chain(scoped).collect::<Vec<_>>().join("; "))
    } else {
        Outcome::Pass
    };
    (outcome, detail)
}

pub fn all() -> Vec<Case> {
    let mut v = single_merkle_proof();
    v.extend(sync());
    v
}
