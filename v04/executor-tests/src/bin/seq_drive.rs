//! Drive sextant_lc on a local LEZ v0.4.0-rc3 standalone sequencer
//! (v04/scripts/e2e-seq.sh) over its JSON-RPC, with signed public
//! transactions that each declare a fee paid by one funded key (`payer`,
//! supplied at genesis), and check the run from the chain alone:
//!
//! ```text
//! seq_drive pubkey             the payer's public key, hex (for the genesis)
//! seq_drive deploy RPC DIR     load sextant_lc through the program loader; DIR/programs.json
//! seq_drive run RPC DIR        Init from the Sepolia checkpoint (vectors/sepolia-v04), every
//!                              update, attestations and refusals; DIR/manifest.tsv and
//!                              DIR/blocks/<id>.borsh for every block of the run
//! seq_drive verify RPC DIR     the verifier: re-reads every block of the manifest from the
//!                              sequencer, checks each transaction's verdict against the
//!                              block's reverted list, replays every one of them on a fresh
//!                              in-memory v0.4 state (the same message, a fresh signer) and
//!                              checks the same verdict and refusal code, and reads the
//!                              instance and header records back against the native verifier
//! ```
//!
//! Nothing here reaches a public network: RPC is a local sequencer.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use base64::Engine as _;
use borsh::BorshSerialize;
use common::{block::Block, transaction::LeeTransaction, HashType};
use lee::{
    program::Program,
    public_transaction::{Message, WitnessSet},
    AccountId, Actor, FeeDeclaration, PrivateKey, PublicAccountEvidence, PublicTransaction,
};
use lee_core::program::{PdaSeed, PROGRAM_LOADER_ACCOUNT_ID};
use serde_json::{json, Value};
use sextant_core::lc::{self, AggMode};
use sextant_core::statement::{Cmp, Field, HeaderRecord, Predicate, Proof, Query};
use sextant_core::{Error, Store};
use sextant_executor_tests_v04::{refusal, Key};
use sextant_host::{load_chain, mainnet, mainnet_steps, receipt_proof_from, weth_proof_from, witness, Mainnet};
use sextant_program_v04::{self as sx, digest, header_account, header_seed, instance_account, instance_seed, job_account, job_id_of, Instance, Job, Message as M, E_BASE};

/// The most a transaction may use: one block's `MAX_GAS_EXEC`, less a margin.
const GAS_LIMIT: u64 = 9_500_000;
/// The wallet's `max_fee_for`: `(gas_limit + 100_000) * 64`.
const MAX_FEE: u128 = (GAS_LIMIT as u128 + 100_000) * 64;
const SEGMENT: usize = 96 * 1024;
const VECTORS: &str = "vectors/sepolia-v04";
const SEPOLIA: u64 = 11_155_111;
const ID: [u8; 32] = *b"sepolia-v04/seq/instance/0000001";
const MAINNET_ID: [u8; 32] = *b"mainnet/seq/instance/00000000001";

fn payer() -> Key {
    Key::new(900)
}

struct Rpc {
    addr: String,
    id: u64,
}

impl Rpc {
    fn new(url: &str) -> Self {
        Self { addr: url.trim_start_matches("http://").trim_end_matches('/').to_string(), id: 0 }
    }

    fn call(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.id += 1;
        let body = json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params}).to_string();
        let mut s = TcpStream::connect(&self.addr).map_err(|e| format!("connect {}: {e}", self.addr))?;
        s.set_read_timeout(Some(Duration::from_secs(120))).unwrap();
        write!(s, "POST / HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", self.addr, body.len()).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        s.read_to_end(&mut out).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&out);
        let (head, rest) = text.split_once("\r\n\r\n").ok_or("no HTTP body")?;
        let payload = if head.to_ascii_lowercase().contains("transfer-encoding: chunked") { dechunk(rest) } else { rest.to_string() };
        let v: Value = serde_json::from_str(&payload).map_err(|e| format!("{e}: {payload}"))?;
        if let Some(e) = v.get("error") {
            return Err(e.to_string());
        }
        Ok(v["result"].clone())
    }

    fn nonce(&mut self, id: AccountId) -> lee_core::account::Nonce {
        let v = self.call("getAccountsNonces", json!([[id]])).expect("getAccountsNonces");
        serde_json::from_value::<Vec<lee_core::account::Nonce>>(v).expect("nonces")[0]
    }

    fn block(&mut self, id: u64) -> Option<(Vec<u8>, Block)> {
        let v = self.call("getBlock", json!([id])).expect("getBlock");
        if v.is_null() {
            return None;
        }
        let raw = base64::engine::general_purpose::STANDARD.decode(v.as_str().expect("a base64 block")).expect("base64");
        let b: Block = borsh::from_slice(&raw).expect("a v0.4 block");
        Some((raw, b))
    }

    fn last_block(&mut self) -> u64 {
        self.call("getLastBlockId", json!([])).expect("getLastBlockId").as_u64().expect("a block id")
    }

    /// The state program `program` holds in account `id`, read from the sequencer.
    fn actor_state(&mut self, id: AccountId, program: AccountId) -> Vec<u8> {
        let v = self.call("getAccountView", json!([Actor::new(id, program)])).expect("getAccountView");
        if v.is_null() {
            return vec![];
        }
        let acct: lee::Account = serde_json::from_value(v).expect("an account");
        acct.data.actor_state(program).to_vec()
    }
}

fn dechunk(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some((len, tail)) = rest.split_once("\r\n") {
        let n = usize::from_str_radix(len.trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        out.push_str(&tail[..n]);
        rest = &tail[n + 2..];
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Applied,
    Reverted,
    /// Refused by the sequencer before inclusion (not in any block).
    Rejected,
}

impl Verdict {
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Applied => "applied",
            Verdict::Reverted => "reverted",
            Verdict::Rejected => "rejected",
        }
    }
}

struct Driver {
    rpc: Rpc,
    manifest: Vec<String>,
}

impl Driver {
    /// Sign and submit `message` to `to`, declaring `actors`, signed by the
    /// payer, and wait for its block. `expect`: the verdict and, for a
    /// refusal, its code (`E72xx`), which `verify` re-derives by replay.
    fn send(&mut self, label: &str, expect: Verdict, code: Option<u32>, to: Actor, actors: &[Actor], pdas: &[(AccountId, PdaSeed)], message: &impl BorshSerialize) -> Verdict {
        let p = payer();
        self.send_signed(label, expect, code, to, actors, &[&p], pdas, message)
    }

    #[allow(clippy::too_many_arguments)]
    fn send_signed(&mut self, label: &str, expect: Verdict, code: Option<u32>, to: Actor, actors: &[Actor], signers: &[&Key], pdas: &[(AccountId, PdaSeed)], message: &impl BorshSerialize) -> Verdict {
        let p = payer();
        let mut keys: Vec<&Key> = signers.to_vec();
        if !keys.iter().any(|k| k.id == p.id) {
            keys.push(&p);
        }
        let nonces = keys.iter().map(|k| (k.id, self.rpc.nonce(k.id))).collect();
        let evidence = pdas.iter().map(|(program, seed)| PublicAccountEvidence::Pda { program: *program, seed: *seed }).collect();
        let data = Program::serialize_message(message).expect("serializes");
        let mut all = actors.to_vec();
        all.push(to);
        let msg = Message::new(to, data, all, nonces, Some(FeeDeclaration::new(p.id, GAS_LIMIT, 0, MAX_FEE)), evidence);
        let sks: Vec<&PrivateKey> = keys.iter().map(|k| &k.sk).collect();
        let tx = LeeTransaction::Public(PublicTransaction::new(msg.clone(), WitnessSet::for_message(&msg, &sks)));
        let want = tx.hash();
        let size = borsh::to_vec(&tx).map(|v| v.len()).unwrap_or(0);
        let code_s = code.map(|c| format!("E{c}")).unwrap_or_else(|| "-".into());
        let h = match self.rpc.call("sendTransaction", json!([tx])) {
            Ok(h) => h,
            Err(e) => {
                println!("{label}: rejected by the sequencer: {e}");
                assert_eq!(expect, Verdict::Rejected, "{label}: sendTransaction refused: {e}");
                self.manifest.push(format!("{label}\t{}\t{code_s}\trejected\t-\t-\t{want}\t{size}", expect.as_str()));
                return Verdict::Rejected;
            }
        };
        let h: HashType = serde_json::from_value(h).expect("a tx hash");
        assert_eq!(h, want);
        let start = Instant::now();
        loop {
            let v = self.rpc.call("getTransaction", json!([h])).expect("getTransaction");
            if !v.is_null() {
                let block = v[1].as_u64().expect("a block id");
                let (_, b) = self.rpc.block(block).expect("the block");
                let index = b.body.transactions.iter().position(|t| t.hash() == h).expect("in its block");
                let verdict = if b.body.is_reverted(index) { Verdict::Reverted } else { Verdict::Applied };
                println!("{label}: block {block} tx {index} {}", verdict.as_str());
                // A transaction expected to be refused before inclusion may instead be
                // included and reverted; either way it took no effect.
                let ok = verdict == expect || (expect == Verdict::Rejected && verdict == Verdict::Reverted);
                assert!(ok, "{label}: {} (expected {})", verdict.as_str(), expect.as_str());
                self.manifest.push(format!("{label}\t{}\t{code_s}\t{}\t{block}\t{index}\t{h}\t{size}", expect.as_str(), verdict.as_str()));
                return verdict;
            }
            if start.elapsed() > Duration::from_secs(90) && expect == Verdict::Rejected {
                println!("{label}: never included (dropped by the sequencer)");
                self.manifest.push(format!("{label}\t{}\t{code_s}\trejected\t-\t-\t{h}\t{size}", expect.as_str()));
                return Verdict::Rejected;
            }
            assert!(start.elapsed() < Duration::from_secs(300), "{label}: not included after 300 s");
            std::thread::sleep(Duration::from_millis(500));
        }
    }

    /// Load a program binary through the program loader at a fresh header
    /// account: segments tail to head, then an immutable header.
    fn deploy(&mut self, path: &Path, seed: u16) -> AccountId {
        let bin = std::fs::read(path).expect("the program binary");
        let pb = risc0_binfmt::ProgramBinary::decode(&bin).expect("a program binary");
        assert_eq!(pb.kernel_elf, risc0_zkos_v1compat::V1COMPAT_ELF, "the v1compat kernel");
        let chunks: Vec<&[u8]> = pb.user_elf.chunks(SEGMENT).collect();
        let segs: Vec<Key> = (0..chunks.len()).map(|i| Key::new(seed + 1 + i as u16)).collect();
        let header = Key::new(seed);
        for i in (0..chunks.len()).rev() {
            let next = segs.get(i + 1).map(|k| k.id);
            let m = loader::Message::WriteSegment { bytecode: chunks[i].to_vec(), next_segment: next };
            self.send_signed(&format!("deploy segment {i}"), Verdict::Applied, None, Actor::new(segs[i].id, PROGRAM_LOADER_ACCOUNT_ID), &[], &[&segs[i]], &[], &m);
        }
        let m = loader::Message::CreateHeader { first_segment: segs[0].id, immutable: true };
        self.send_signed("deploy header", Verdict::Applied, None, Actor::new(header.id, PROGRAM_LOADER_ACCOUNT_ID), &[], &[&header], &[], &m);
        header.id
    }
}

/// `program_loader_core::Message` (lez/programs/program_loader/core, v0.4.0-rc3), mirrored.
mod loader {
    use borsh::BorshSerialize;
    use lee::AccountId;
    #[derive(BorshSerialize)]
    pub enum Message {
        WriteSegment { bytecode: Vec<u8>, next_segment: Option<AccountId> },
        CreateHeader { first_segment: AccountId, immutable: bool },
    }
}

fn programs(dir: &Path) -> AccountId {
    let v: Value = serde_json::from_str(&std::fs::read_to_string(dir.join("programs.json")).expect("programs.json: run deploy first")).unwrap();
    serde_json::from_value(v["sextant_lc"].clone()).unwrap()
}

fn code(e: Error) -> Option<u32> {
    Some(E_BASE + e as u32)
}

fn vectors() -> Mainnet {
    load_chain(VECTORS, SEPOLIA)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("pubkey") => println!("{}", hex::encode(payer().pk.value())),
        Some("deploy") => {
            let dir = PathBuf::from(&args[3]);
            std::fs::create_dir_all(&dir).unwrap();
            let mut d = Driver { rpc: Rpc::new(&args[2]), manifest: vec![] };
            let lc = d.deploy(&sextant_executor_tests_v04::bin_path(), 3000);
            std::fs::write(dir.join("programs.json"), json!({"sextant_lc": lc}).to_string()).unwrap();
            std::fs::write(dir.join("deploy.tsv"), d.manifest.join("\n") + "\n").unwrap();
            println!("sextant_lc {lc}");
        }
        Some("run") => run(&args[2], Path::new(&args[3])),
        Some("verify") => std::process::exit(verify(&args[2], Path::new(&args[3]))),
        _ => {
            eprintln!("usage: seq_drive pubkey | deploy RPC DIR | run RPC DIR | verify RPC DIR");
            std::process::exit(2);
        }
    }
}

fn run(rpc: &str, dir: &Path) {
    let me = programs(dir);
    let lc = |id| Actor::new(id, me);
    let m = vectors();
    let mut d = Driver { rpc: Rpc::new(rpc), manifest: vec![] };
    let first = d.rpc.last_block() + 1;
    let inst = instance_account(&me, &ID);
    let boot_slot = m.boot_header.beacon.slot;
    let init = M::Init { instance_id: ID, checkpoint: m.checkpoint, cfg: m.cfg.clone(), header: m.boot_header.clone(), committee: m.boot_committee.clone(), branch: m.boot_branch.clone() };
    let init_actors = [lc(header_account(&me, &ID, boot_slot))];

    // 1. Init from the Sepolia checkpoint (the default 14-day bound), and a second Init.
    d.send("Init from the Sepolia checkpoint", Verdict::Applied, None, lc(inst), &init_actors, &[(me, instance_seed(&ID))], &init);
    d.send("Init again at the same id", Verdict::Reverted, Some(sx::E_EXISTS), lc(inst), &init_actors, &[], &init);

    // 2. The mainnet checkpoint of 2026-10-11 with the same 14-day bound: past it by the
    //    sequencer's clock. On v0.4 a closed validity window is found at settlement, so the
    //    transaction is included, charged and reverted.
    let mm = mainnet();
    let minit = M::Init { instance_id: MAINNET_ID, checkpoint: mm.checkpoint, cfg: mm.cfg.clone(), header: mm.boot_header.clone(), committee: mm.boot_committee.clone(), branch: mm.boot_branch.clone() };
    let stale = d.send(
        "Init from the mainnet checkpoint past its weak-subjectivity bound",
        Verdict::Reverted,
        None,
        lc(instance_account(&me, &MAINNET_ID)),
        &[lc(header_account(&me, &MAINNET_ID, mm.boot_header.beacon.slot))],
        &[(me, instance_seed(&MAINNET_ID))],
        &minit,
    );
    assert_eq!(stale, Verdict::Reverted);

    // 3. Attacks on the first update, before it lands.
    let steps = mainnet_steps(&m);
    let current = |d: &mut Driver| -> Instance { borsh::from_slice(&d.rpc.actor_state(inst, me)).expect("the instance") };
    let begin = |cur: &Instance, u: &sextant_core::Update, k: &sextant_core::SyncCommittee| M::Begin {
        instance_id: ID,
        current: digest(cur),
        update: u.clone(),
        committee: k.clone(),
        witness: witness(k, &u.bits, AggMode::Subtract),
    };
    let cur = current(&mut d);
    let (_, u0, k0) = steps[0].clone();
    // A signature over another header: Begin and Miller run, Finish refuses at the pairing.
    let mut bad = u0.clone();
    bad.signature = steps[1].1.signature;
    let jb = job_id_of(&digest(&cur), &bad);
    d.send("tampered signature: Begin", Verdict::Applied, None, lc(inst), &[lc(job_account(&me, &ID, &jb))], &[], &begin(&cur, &bad, &k0));
    d.send("tampered signature: Miller", Verdict::Applied, None, lc(job_account(&me, &ID, &jb)), &[], &[], &M::Miller { instance_id: ID, job_id: jb });
    let jstate: Job = borsh::from_slice(&d.rpc.actor_state(job_account(&me, &ID, &jb), me)).expect("the job");
    let bslot = jstate.next.store.finalized.slot;
    d.send("tampered signature: Finish", Verdict::Reverted, code(Error::BadSignature), lc(job_account(&me, &ID, &jb)), &[lc(inst), lc(header_account(&me, &ID, bslot))], &[], &M::Finish { instance_id: ID, job_id: jb });
    // Participation below the floor (341 of 512 signers).
    let mut low = u0.clone();
    for i in 341..512 {
        low.bits[i / 8] &= !(1 << (i % 8));
    }
    let jl = job_id_of(&digest(&cur), &low);
    d.send("participation below the floor: Begin", Verdict::Reverted, code(Error::BelowParticipation), lc(inst), &[lc(job_account(&me, &ID, &jl))], &[], &begin(&cur, &low, &k0));

    // 4. Every update of the vectors: Begin, Miller, Finish.
    for (n, (_, u, k)) in steps.iter().enumerate() {
        let cur = current(&mut d);
        let jid = job_id_of(&digest(&cur), u);
        let job = lc(job_account(&me, &ID, &jid));
        let p = lc::period(u.signature_slot);
        d.send(&format!("update {} (period {p}): Begin", n + 1), Verdict::Applied, None, lc(inst), &[job], &[], &begin(&cur, u, k));
        d.send(&format!("update {} (period {p}): Miller", n + 1), Verdict::Applied, None, job, &[], &[], &M::Miller { instance_id: ID, job_id: jid });
        let j: Job = borsh::from_slice(&d.rpc.actor_state(job.account_id, me)).expect("the job");
        let slot = j.next.store.finalized.slot;
        d.send(&format!("update {} (period {p}): Finish", n + 1), Verdict::Applied, None, job, &[lc(inst), lc(header_account(&me, &ID, slot))], &[], &M::Finish { instance_id: ID, job_id: jid });
        if n == 0 {
            // 5. Replays of update 1, once it has landed: built against the old store (the
            //    instance moved on), and rebuilt against the current store (already applied).
            let now = current(&mut d);
            let jr = job_id_of(&digest(&cur), &u0);
            d.send("replay of update 1 built against the old store", Verdict::Reverted, Some(sx::E_STALE), lc(inst), &[lc(job_account(&me, &ID, &jr))], &[], &begin(&cur, &u0, &k0));
            let jr2 = job_id_of(&digest(&now), &u0);
            d.send("replay of update 1 against the current store", Verdict::Reverted, code(Error::AlreadyApplied), lc(inst), &[lc(job_account(&me, &ID, &jr2))], &[], &begin(&now, &u0, &k0));
        }
    }

    let now = current(&mut d);
    // 6. Attestations against the last header and the checkpoint's, and refusals.
    let slot = now.store.finalized.slot;
    let hdr = lc(header_account(&me, &ID, slot));
    // The vector set's WETH holder holds nothing at this block: the attested statement is
    // `balanceOf[holder] == 0`, and `>= 1 wei` is the predicate the state does not satisfy.
    let weth = |chain_id| Query { chain_id, proof: Proof::Storage(weth_proof_from(&format!("{VECTORS}/getproof-weth.json"))), predicates: vec![Predicate { field: Field::SlotValue, cmp: Cmp::Eq, value: [0; 32] }] };
    let att = |q: Query, s: u64| M::Attest { instance_id: ID, slot: s, query: q };
    d.send("Attest: WETH balanceOf[holder] == 0 at the last header", Verdict::Applied, None, hdr, &[], &[], &att(weth(SEPOLIA), slot));
    let log92 = || receipt_proof_from(&format!("{VECTORS}/receipt-proof-tx92.json"), 92);
    d.send("Attest: a log of tx 92 at the last header", Verdict::Applied, None, hdr, &[], &[], &att(Query { chain_id: SEPOLIA, proof: Proof::Log(log92()), predicates: vec![] }, slot));
    let ckpt = format!("{VECTORS}/block-{}/receipt-proof-tx0.json", checkpoint_block());
    let ck = || receipt_proof_from(&ckpt, 0);
    d.send("Attest: a log of tx 0 at the checkpoint header", Verdict::Applied, None, lc(header_account(&me, &ID, boot_slot)), &[], &[], &att(Query { chain_id: SEPOLIA, proof: Proof::Log(ck()), predicates: vec![] }, boot_slot));
    d.send("Attest as a mainnet statement (other chain)", Verdict::Reverted, code(Error::ChainMismatch), hdr, &[], &[], &att(weth(1), slot));
    let mut zero = weth(SEPOLIA);
    zero.predicates[0].cmp = Cmp::Ge;
    zero.predicates[0].value[31] = 1;
    d.send("Attest: WETH balanceOf[holder] >= 1 wei, which the state does not satisfy", Verdict::Reverted, code(Error::PredicateFalse), hdr, &[], &[], &att(zero, slot));
    d.send("Attest: the checkpoint's receipt against the last header", Verdict::Reverted, code(Error::BadInclusion), hdr, &[], &[], &att(Query { chain_id: SEPOLIA, proof: Proof::Log(ck()), predicates: vec![] }, slot));
    d.send(
        "Attest at a slot never recorded",
        Verdict::Reverted,
        Some(sx::E_NO_INSTANCE),
        lc(header_account(&me, &ID, slot + 1)),
        &[],
        &[(me, header_seed(&ID, slot + 1))],
        &att(weth(SEPOLIA), slot + 1),
    );

    // Every block of the run, and the manifest.
    let last = d.rpc.last_block();
    let blocks = dir.join("blocks");
    std::fs::create_dir_all(&blocks).unwrap();
    for id in first..=last {
        let (raw, _) = d.rpc.block(id).expect("the block");
        std::fs::write(blocks.join(format!("{id}.borsh")), &raw).unwrap();
    }
    let mut out = vec!["# label\texpected\tcode\tverdict\tblock\ttx\thash\tbytes".to_string()];
    out.extend(d.manifest.iter().cloned());
    out.push(format!("# program sextant_lc {me}"));
    out.push(format!("# instance {} ({}) final slot {slot} period {} execution block {}", String::from_utf8_lossy(&ID), inst, lc::period(slot), now.store.finalized_block_number));
    out.push(format!("# blocks {first}..={last}"));
    std::fs::write(dir.join("manifest.tsv"), out.join("\n") + "\n").unwrap();
    println!("run done: blocks {first}..={last}, final slot {slot} (period {}), execution block {}", lc::period(slot), now.store.finalized_block_number);
}

/// The execution block of the checkpoint (vectors/sepolia-v04/block-<n>/).
fn checkpoint_block() -> u64 {
    let root = sextant_host::root_dir().join(VECTORS);
    std::fs::read_dir(&root)
        .unwrap()
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .find_map(|f| f.strip_prefix("block-").and_then(|n| n.parse().ok()))
        .expect("a block-<n> directory")
}

// ---- the verifier ----

struct Row {
    label: String,
    expected: String,
    code: Option<u32>,
    verdict: String,
    block: Option<u64>,
    index: Option<usize>,
    hash: String,
}

fn rows(dir: &Path) -> Vec<Row> {
    std::fs::read_to_string(dir.join("manifest.tsv"))
        .expect("manifest.tsv")
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            Row {
                label: f[0].into(),
                expected: f[1].into(),
                code: f[2].strip_prefix('E').and_then(|c| c.parse().ok()),
                verdict: f[3].into(),
                block: f[4].parse().ok(),
                index: f[5].parse().ok(),
                hash: f[6].into(),
            }
        })
        .collect()
}

struct Check {
    pass: u32,
    fail: u32,
}

impl Check {
    fn ok(&mut self, cond: bool, what: &str) {
        if cond {
            self.pass += 1;
            println!("PASS {what}");
        } else {
            self.fail += 1;
            println!("FAIL {what}");
        }
    }
}

/// Returns the process exit code: 0 when every check passed.
fn verify(rpc: &str, dir: &Path) -> i32 {
    let me = programs(dir);
    let mut r = Rpc::new(rpc);
    let mut c = Check { pass: 0, fail: 0 };
    // A fresh in-memory v0.4 state with the same binary at the same account.
    let bin = sextant_executor_tests_v04::bin();
    let mut shadow = sextant_executor_tests_v04::Chain::new().with_program(me, bin);
    let mut fresh = 20_000u16;
    for row in rows(dir) {
        let what = &row.label;
        if row.verdict == "rejected" {
            // Never included: nothing on chain to check but its absence.
            let v = r.call("getTransaction", json!([row.hash])).unwrap_or(Value::Null);
            c.ok(v.is_null() && row.expected == "rejected", &format!("{what}: not in any block, as expected"));
            continue;
        }
        let (Some(bid), Some(ix)) = (row.block, row.index) else {
            c.ok(false, &format!("{what}: no block in the manifest"));
            continue;
        };
        let Some((_, b)) = r.block(bid) else {
            c.ok(false, &format!("{what}: block {bid} not served"));
            continue;
        };
        let Some(tx) = b.body.transactions.get(ix) else {
            c.ok(false, &format!("{what}: block {bid} has no tx {ix}"));
            continue;
        };
        c.ok(tx.hash().to_string() == row.hash, &format!("{what}: block {bid} tx {ix} is {}", &row.hash[..16.min(row.hash.len())]));
        let chain_verdict = if b.body.is_reverted(ix) { "reverted" } else { "applied" };
        let as_expected = chain_verdict == row.expected || (row.expected == "rejected" && chain_verdict == "reverted");
        c.ok(as_expected && chain_verdict == row.verdict, &format!("{what}: {chain_verdict} by the block's reverted list (expected {})", row.expected));
        // Replay the same root call with the same declared actors and evidence, from a fresh signer,
        // at the block's timestamp.
        let LeeTransaction::Public(ptx) = tx else {
            c.ok(false, &format!("{what}: not a public transaction"));
            continue;
        };
        let m = &ptx.message;
        let to = m.execution.root.to;
        if to.program_account_id != me {
            continue; // the program loader's own transactions (deploy)
        }
        fresh += 1;
        let k = Key::new(fresh);
        let nonces: BTreeMap<_, _> = [(k.id, shadow.state.get_account_by_id(k.id).nonce)].into();
        let msg = Message::new(to, m.execution.root.message.clone(), m.public_context.actors.iter().copied(), nonces, None, m.admission_evidence.clone());
        let replay = PublicTransaction::new(msg.clone(), WitnessSet::for_message(&msg, &[&k.sk]));
        shadow.now = b.header.timestamp;
        shadow.block = bid;
        let res = shadow.submit(what, &replay);
        let (rv, rc) = match &res {
            Ok(_) => ("applied", None),
            Err(e) if e.starts_with("not includable") => ("rejected", None),
            Err(e) => ("reverted", refusal(e)),
        };
        let cycles = shadow.log.last().map(|l| l.1).unwrap_or(0);
        let same = rv == chain_verdict || (chain_verdict == "reverted" && rv == "rejected");
        c.ok(same, &format!("{what}: replayed on rc3's state machine: {rv} ({cycles} cycles)"));
        if let Some(want) = row.code {
            c.ok(rc == Some(want), &format!("{what}: refusal E{want} on replay (got {})", rc.map(|x| format!("E{x}")).unwrap_or("none".into())));
        }
    }
    // Read back: the instance, the job states, every header record, against the native verifier.
    let m = vectors();
    let steps = mainnet_steps(&m);
    let native: Store = {
        let (s, u, k) = steps.last().unwrap();
        lc::apply_update(&m.cfg, s, u, k, &witness(k, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap()
    };
    let inst_bytes = r.actor_state(instance_account(&me, &ID), me);
    let inst: Option<Instance> = borsh::from_slice(&inst_bytes).ok();
    c.ok(inst.as_ref().map(|i| &i.store) == Some(&native), "the instance's store on the sequencer is the native verifier's after every update");
    c.ok(inst_bytes == shadow.actor_state(instance_account(&me, &ID), me), "the instance on the sequencer is the replay's, byte for byte");
    let boot = lc::bootstrap(&m.cfg, &m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).expect("bootstrap");
    let mut records = vec![sx::record(&m.cfg, &boot)];
    for (s, u, k) in &steps {
        let next = lc::apply_update(&m.cfg, s, u, k, &witness(k, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).expect("a real update");
        records.push(sx::record(&m.cfg, &next));
    }
    records.dedup_by_key(|r| r.slot);
    for want in records {
        let rec: Option<HeaderRecord> = borsh::from_slice(&r.actor_state(header_account(&me, &ID, want.slot), me)).ok();
        c.ok(rec.as_ref() == Some(&want), &format!("header record at slot {} (period {}, execution block {}) is the native verifier's", want.slot, lc::period(want.slot), want.block_number));
    }
    c.ok(r.actor_state(instance_account(&me, &MAINNET_ID), me).is_empty(), "no mainnet instance: the stale checkpoint never landed");
    println!("\nverify: {} passed, {} failed", c.pass, c.fail);
    i32::from(c.fail > 0)
}
