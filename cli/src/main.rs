//! `sextant`: deploy sextant_lc on a LEZ v0.3 sequencer and drive it from the
//! committed mainnet vectors.
//!
//! Every transaction is first executed locally, through `lee::V03State` with
//! the committed binary and the accounts the instruction touches as the chain
//! has them now (the **pre-check**). An instruction the program accepts is
//! sent with a gas limit of its measured gas plus 10%; one it refuses is
//! reported with its typed code (`E72xx`) and, with `--force`, sent anyway so
//! that the chain's own verdict is on record. On v0.3.1 a public transaction
//! whose program refuses fails settlement: the sequencer leaves it out of the
//! block and charges nothing, so it never resolves by hash.
//!
//! The fee payer co-signs every transaction without joining its accounts, as
//! the wallet does for program_loader writes. A transaction the sequencer
//! drops is sent again, at most three times, each attempt signed with the
//! payer's nonce as the chain has it, so at most one attempt can land.
//!
//! Each transaction prints one JSON line: label, operation, pre-check, gas
//! limit, every attempt's hash, the block it landed in, and the verdict
//! (`applied`: included; `not-included`: no attempt resolved).

use std::{path::PathBuf, time::Duration};

use anyhow::{anyhow, ensure, Context as _, Result};
use clap::{Parser, Subcommand, ValueEnum};
use common::{transaction::LeeTransaction, HashType};
use lee::{
    program::Program,
    public_transaction::{Message, WitnessSet},
    AccountId, FeeDeclaration, PrivateKey, ProgramShardSelector, PublicKey, PublicTransaction, V03State,
    ValidatedStateDiff,
};
use sequencer_service_rpc::{RpcClient as _, SequencerClient, SequencerClientBuilder};
use sextant_core::lc::{self, AggMode};
use sextant_core::statement::{Cmp, Field, Predicate, Proof, Query};
use sextant_core::{ChainConfig, Store, SyncCommittee, Update};
use sextant_host::{mainnet, mainnet_steps, receipt_proof, receipt_proof_from, weth_proof, weth_proof_from, witness, Mainnet};
use sextant_program::{header_account, instance_account, job_account, job_id, Instance, Instruction};
use sha2::{Digest as _, Sha256};
use wallet::{program_facades::program_loader::ProgramLoader, WalletCore};

const LOCAL_RPC: &str = "http://127.0.0.1:3040";
/// `MAX_GAS_EXEC`: the most execution gas one transaction may declare.
const GAS_CAP: u64 = 10_000_000;
/// The checkpoint's execution block, for which `vectors/mainnet/block-26170219/` holds proofs.
const CHECKPOINT_BLOCK_DIR: &str = "vectors/mainnet/block-26170219";
const CHECKPOINT_TX: u64 = 16;
/// The keccak of `Transfer(address,address,uint256)`: topic 0 of an ERC-20 transfer log.
const TRANSFER: &str = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";
/// Sepolia's genesis validators root: an instance configured with it is another chain's.
const SEPOLIA_GVR: &str = "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078";

#[derive(Parser)]
#[command(name = "sextant", version, about = "sextant_lc on LEZ v0.3, driven from the mainnet vectors")]
struct Cli {
    /// The program's header account (base58).
    #[arg(long, env = "SEXTANT_PROGRAM", global = true)]
    program: Option<AccountId>,
    /// The sequencer.
    #[arg(long, env = "SEXTANT_RPC", global = true, default_value = LOCAL_RPC)]
    rpc: String,
    /// The packed program binary.
    #[arg(long, env = "SEXTANT_BIN", global = true, default_value = "artifacts/programs/v0.3/sextant_lc.bin")]
    bin: PathBuf,
    /// The account that pays every fee (its key must be in the wallet).
    #[arg(long, env = "SEXTANT_PAYER", global = true)]
    payer: Option<AccountId>,
    /// The instance id: at most 32 bytes of text, zero-padded.
    #[arg(long, env = "SEXTANT_INSTANCE", global = true, default_value = "mainnet")]
    instance: String,
    /// The instance was initialised with another chain's configuration (`init --wrong-chain`).
    #[arg(long, global = true)]
    wrong_chain: bool,
    /// Send even if the pre-check says the program refuses.
    #[arg(long, global = true)]
    force: bool,
    /// Seconds to wait for each attempt to be included.
    #[arg(long, env = "SEXTANT_WAIT", global = true, default_value_t = 240)]
    wait: u64,
    /// A label for the JSON line.
    #[arg(long, global = true, default_value = "")]
    label: String,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Tamper {
    /// Another real signature (the next update's): a valid point, refused at `Finish`.
    Resigned,
    /// One byte of the compressed signature flipped.
    Bitflip,
    /// 171 participation bits cleared: 341 of 512 signers.
    Participation,
    /// The finalized header moved one epoch: not the one the finality branch proves.
    Moved,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum At {
    /// The checkpoint's header, recorded by `Init` (execution block 26,170,219).
    Checkpoint,
    /// The header recorded by the last update (execution block 26,197,200).
    Final,
}

#[derive(Clone, Copy, ValueEnum, PartialEq, Eq)]
enum Kind {
    /// An ERC-20 `Transfer` log, through a receipt proof.
    Log,
    /// WETH `balanceOf` the Uniswap v3 USDC/WETH pool ≥ 1 wei, through `eth_getProof`.
    Storage,
}

#[derive(Subcommand)]
enum Cmd {
    /// The ImageID and deployment digest of `--bin`.
    ImageId,
    /// Deploy `--bin` through program_loader.
    Deploy {
        /// Resume into this header account (already in the wallet). Needs `--segment`.
        #[arg(long, requires = "segment")]
        header: Option<AccountId>,
        #[arg(long, requires = "header")]
        segment: Vec<AccountId>,
    },
    /// The instance's accounts.
    Ids,
    /// The instance as the chain holds it.
    Show,
    /// The payer's balance.
    Balance,
    /// `Init` from the committed mainnet bootstrap.
    Init,
    /// Step 1 of update `n` (1-based; the vectors hold 4).
    Begin {
        n: usize,
        #[arg(long)]
        tamper: Option<Tamper>,
    },
    /// Step 2 of update `n`.
    Miller {
        n: usize,
        #[arg(long)]
        tamper: Option<Tamper>,
    },
    /// Step 3 of update `n`.
    Finish {
        n: usize,
        #[arg(long)]
        tamper: Option<Tamper>,
    },
    /// The consumer check against a recorded header.
    Attest {
        #[arg(long, value_enum)]
        at: At,
        #[arg(long, value_enum)]
        kind: Kind,
        /// The chain the consumer expects (1 = mainnet).
        #[arg(long, default_value_t = 1)]
        chain_id: u64,
        /// Ask for the opposite of what holds.
        #[arg(long)]
        negate: bool,
        /// Ask about a storage slot the proof does not cover.
        #[arg(long)]
        wrong_slot: bool,
        /// Name a slot this many slots after the recorded header's.
        #[arg(long, default_value_t = 0)]
        slot_offset: u64,
    },
}

fn id32(s: &str) -> Result<[u8; 32]> {
    ensure!(s.len() <= 32, "an instance id is at most 32 bytes: {s}");
    let mut b = [0u8; 32];
    b[..s.len()].copy_from_slice(s.as_bytes());
    Ok(b)
}

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).expect("hex").try_into().expect("32 bytes")
}

fn image_hex(bin: &[u8]) -> Result<String> {
    let id = risc0_binfmt::compute_image_id(bin).map_err(|e| anyhow!("{e}"))?;
    Ok(hex::encode(id.as_bytes()))
}

struct Ctx {
    rpc: SequencerClient,
    program: Option<AccountId>,
    bin: Vec<u8>,
    payer: Option<AccountId>,
    instance: [u8; 32],
    wrong_chain: bool,
    force: bool,
    wait: u64,
    label: String,
    m: Mainnet,
}

/// What the pre-check found: the gas the program uses, or its refusal.
enum Pre {
    Gas(u64),
    Refused(String),
}

impl Ctx {
    fn program(&self) -> Result<AccountId> {
        self.program.ok_or_else(|| anyhow!("name the program's header with --program or SEXTANT_PROGRAM"))
    }
    fn payer(&self) -> Result<AccountId> {
        self.payer.ok_or_else(|| anyhow!("name the fee payer with --payer or SEXTANT_PAYER"))
    }
    async fn account(&self, id: AccountId) -> Result<lee::Account> {
        self.rpc.get_account(id).await.map_err(|e| anyhow!("reading {id} from the sequencer: {e}"))
    }
    async fn shard(&self, id: AccountId) -> Result<Vec<u8>> {
        let p = self.program()?;
        Ok(self.account(id).await?.data.shard(p).to_vec())
    }
    fn cfg(&self) -> ChainConfig {
        let mut cfg = self.m.cfg.clone();
        if self.wrong_chain {
            cfg.chain_id = 11_155_111;
            cfg.genesis_validators_root = hex32(SEPOLIA_GVR);
        }
        cfg
    }
    /// The store before update `n`, the update, and its signing committee.
    fn step(&self, n: usize) -> Result<(Store, Update, SyncCommittee)> {
        let steps = mainnet_steps(&self.m);
        ensure!((1..=steps.len()).contains(&n), "the vectors hold updates 1 to {}", steps.len());
        Ok(steps[n - 1].clone())
    }
    /// The instance as it is before update `n`, if every earlier update was applied.
    fn current(&self, n: usize) -> Result<Instance> {
        Ok(Instance { checkpoint: self.m.checkpoint, cfg: self.cfg(), store: self.step(n)?.0 })
    }
    fn update(&self, n: usize, tamper: Option<Tamper>) -> Result<Update> {
        let mut u = self.step(n)?.1;
        match tamper {
            None => {}
            Some(Tamper::Resigned) => {
                let steps = mainnet_steps(&self.m);
                u.signature = steps[n % steps.len()].1.signature;
            }
            Some(Tamper::Bitflip) => u.signature[40] ^= 0x01,
            Some(Tamper::Participation) => {
                for i in 341..512 {
                    u.bits[i / 8] &= !(1 << (i % 8));
                }
            }
            Some(Tamper::Moved) => u.finalized.beacon.slot += 32,
        }
        Ok(u)
    }
    /// The store after update `n` (the native verifier; a tampered update keeps
    /// the honest `next`, which is what a forger would claim).
    fn next(&self, n: usize) -> Result<Store> {
        let (store, u, committee) = self.step(n)?;
        let w = witness(&committee, &u.bits, AggMode::Subtract);
        lc::apply_update(&self.cfg(), &store, &u, &committee, &w, lc::FAST, &mut |_| {}).map_err(|e| anyhow!("{e:?}"))
    }

    /// Execute `ix` locally through `lee::V03State`, with the committed binary at
    /// the program's address and `rows` as the chain has them now.
    async fn precheck(&self, ix: &Instruction, rows: &[AccountId]) -> Result<Pre> {
        let p = self.program()?;
        let program = Program::new(self.bin.clone().into())?;
        let mut accounts = vec![];
        for r in rows {
            accounts.push((*r, self.account(*r).await?));
        }
        let state = V03State::new().with_named_programs([(p, program)]).with_public_accounts(accounts);
        let k = PrivateKey::try_new([0x5a; 32]).expect("a valid scalar");
        let kid = AccountId::from(&PublicKey::new_from_private_key(&k));
        let sel = rows.iter().map(|a| ProgramShardSelector::new(*a, p)).collect();
        let message = Message::try_new(p, sel, vec![state.get_account_by_id(kid).nonce], ix.clone())?;
        let tx = PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[&k]));
        Ok(match ValidatedStateDiff::from_public_transaction_with_cycle_budget(&tx, &state, 1, 0, GAS_CAP) {
            Ok((_, charge)) => Pre::Gas(charge.cycles),
            Err(e) => {
                let e = e.to_string();
                Pre::Refused(e.find("E72").map(|i| e[i..].chars().take_while(|c| *c != '\n' && *c != '"').collect()).unwrap_or(e))
            }
        })
    }

    /// Whether program_loader has written `a` (a segment or the header).
    async fn loaded(&self, a: AccountId) -> Result<bool> {
        Ok(!self.account(a).await?.data.shard(lee_core::program::PROGRAM_LOADER_ACCOUNT_ID).is_empty())
    }

    async fn balance(&self, who: AccountId) -> Result<u128> {
        self.rpc.get_account_balance(who).await.map_err(|e| anyhow!("balance of {who}: {e}"))
    }

    async fn included(&self, h: HashType) -> Option<u64> {
        match self.rpc.get_transaction(h).await {
            Ok(Some((_, b))) => Some(b),
            _ => None,
        }
    }

    /// Pre-check, then send `ix` over `rows`, signed and paid by the payer only.
    async fn run(&self, wallet: &WalletCore, op: &str, ix: Instruction, rows: Vec<AccountId>, fallback_gas: u64) -> Result<()> {
        let p = self.program()?;
        let payer = self.payer()?;
        let pre = self.precheck(&ix, &rows).await?;
        let (gas_limit, pre_json) = match &pre {
            Pre::Gas(g) => ((g + g / 10).clamp(100_000, GAS_CAP), serde_json::json!({"gas": g})),
            Pre::Refused(e) => (fallback_gas, serde_json::json!({"refused": e})),
        };
        let mut line = serde_json::json!({"op": op, "label": self.label, "precheck": pre_json, "gas_limit": gas_limit});
        if matches!(pre, Pre::Refused(_)) && !self.force {
            line["verdict"] = "refused-precheck".into();
            println!("{line}");
            return Ok(());
        }
        let key = wallet.get_account_public_signing_key(payer).ok_or_else(|| anyhow!("the wallet holds no key for the payer {payer}"))?.clone();
        let fees = self.rpc.get_fee_state().await.map_err(|e| anyhow!("getFeeState: {e}"))?;
        let data = Program::serialize_instruction(ix.clone())?;
        let sel: Vec<_> = rows.iter().map(|a| ProgramShardSelector::new(*a, p)).collect();
        let build = |nonce, max_fee| {
            let message = Message::new_preserialized(p, sel.clone(), vec![nonce], data.clone(), Some(FeeDeclaration::new(payer, gas_limit, 0, max_fee)));
            LeeTransaction::Public(PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[&key])))
        };
        // The reserve the sequencer takes before executing: the gas limit and the
        // transaction's bytes at today's base fees. A payer that cannot cover it is
        // dropped at the fee screen, which is not a refusal by the program, so it is
        // checked here and recorded.
        let data_bytes = borsh::to_vec(&build(lee_core::account::Nonce(0), 0))?.len() as u128;
        let reserve = u128::from(gas_limit) * u128::from(fees.base_fee_exec) + data_bytes * u128::from(fees.base_fee_stor);
        let max_fee = reserve * 2;
        let balance = self.balance(payer).await?;
        line["tx_bytes"] = (data_bytes as u64).into();
        line["fee_reserve"] = reserve.to_string().into();
        line["payer_balance_before"] = balance.to_string().into();
        ensure!(balance > reserve, "the payer holds {balance}, below the fee reserve {reserve}: a send would be dropped at the fee screen");
        let mut hashes: Vec<HashType> = vec![];
        let mut found = None;
        for attempt in 1..=3 {
            let nonce = self.rpc.get_accounts_nonces(vec![payer]).await.map_err(|e| anyhow!("nonce: {e}"))?[0];
            match self.rpc.send_transaction(build(nonce, max_fee)).await {
                Ok(h) => {
                    eprintln!("{op}: attempt {attempt} sent {h} (nonce {nonce:?})");
                    hashes.push(h);
                }
                Err(e) => eprintln!("{op}: attempt {attempt} not accepted by the sequencer: {e}"),
            }
            let start = std::time::Instant::now();
            while start.elapsed() < Duration::from_secs(self.wait) && found.is_none() {
                for h in &hashes {
                    if let Some(b) = self.included(*h).await {
                        found = Some((*h, b));
                        break;
                    }
                }
                if found.is_none() {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
            if found.is_some() {
                break;
            }
            eprintln!("{op}: attempt {attempt} not included after {}s", self.wait);
        }
        line["attempts"] = hashes.iter().map(|h| h.to_string()).collect();
        match found {
            Some((h, b)) => {
                line["tx"] = h.to_string().into();
                line["block"] = b.into();
                line["verdict"] = "applied".into();
            }
            None => {
                line["tx"] = hashes.last().map(|h| h.to_string()).unwrap_or_else(|| "-".into()).into();
                line["verdict"] = if hashes.is_empty() { "rejected" } else { "not-included" }.into();
            }
        }
        line["payer_balance_after"] = self.balance(payer).await?.to_string().into();
        println!("{line}");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let rpc = SequencerClientBuilder::default().build(&cli.rpc).with_context(|| format!("not a sequencer URL: {}", cli.rpc))?;
    let bin = std::fs::read(&cli.bin).with_context(|| format!("reading {}", cli.bin.display()))?;
    let ctx = Ctx {
        rpc,
        program: cli.program,
        bin,
        payer: cli.payer,
        instance: id32(&cli.instance)?,
        wrong_chain: cli.wrong_chain,
        force: cli.force,
        wait: cli.wait,
        label: cli.label.clone(),
        m: mainnet(),
    };
    let signs = matches!(cli.cmd, Cmd::Deploy { .. } | Cmd::Init | Cmd::Begin { .. } | Cmd::Miller { .. } | Cmd::Finish { .. } | Cmd::Attest { .. });
    let wallet = if signs {
        Some(WalletCore::from_env().await.context("this command signs, so it needs a v0.3 wallet home (LEE_WALLET_HOME_DIR)")?)
    } else {
        None
    };
    let id = ctx.instance;
    match cli.cmd {
        Cmd::ImageId => {
            let sha = hex::encode(Sha256::digest(&ctx.bin));
            println!("{}", serde_json::json!({"image_id": image_hex(&ctx.bin)?, "bytes": ctx.bin.len(), "sha256": sha}));
        }
        Cmd::Balance => println!("{}", ctx.balance(ctx.payer()?).await?),
        Cmd::Ids => {
            let p = ctx.program()?;
            let boot = lc::bootstrap(&ctx.m.checkpoint, &ctx.m.boot_header, &ctx.m.boot_committee, &ctx.m.boot_branch).map_err(|e| anyhow!("{e:?}"))?;
            let last = mainnet_steps(&ctx.m).len();
            let fin = ctx.next(last)?;
            println!(
                "{}",
                serde_json::json!({
                    "instance_id": hex::encode(id),
                    "instance": instance_account(&p, &id).to_string(),
                    "checkpoint_header": header_account(&p, &id, boot.finalized.slot).to_string(),
                    "checkpoint_slot": boot.finalized.slot,
                    "final_header": header_account(&p, &id, fin.finalized.slot).to_string(),
                    "final_slot": fin.finalized.slot,
                })
            );
        }
        Cmd::Show => {
            let p = ctx.program()?;
            let bytes = ctx.shard(instance_account(&p, &id)).await?;
            if bytes.is_empty() {
                println!("{}", serde_json::json!({"instance": null}));
            } else {
                let i: Instance = borsh::from_slice(&bytes)?;
                let s = &i.store;
                println!(
                    "{}",
                    serde_json::json!({
                        "chain_id": i.cfg.chain_id,
                        "slot": s.finalized.slot,
                        "period": lc::period(s.finalized.slot),
                        "block_number": s.finalized_block_number,
                        "state_root": hex::encode(s.finalized_execution_state_root),
                        "receipts_root": hex::encode(s.finalized_receipts_root),
                        "digest": hex::encode(sextant_program::digest(&i)),
                    })
                );
            }
        }
        Cmd::Deploy { header, segment } => {
            let payer = ctx.payer()?;
            let bytecode = ctx.bin.clone();
            let user_elf = risc0_binfmt::ProgramBinary::decode(&bytecode).map_err(|e| anyhow!("{e}"))?.user_elf.to_vec();
            let segments = user_elf.len().div_ceil(program_loader_core::MAX_SEGMENT_DATA_LEN);
            let mut wallet = wallet.expect("deploy opens the wallet");
            let (header, segs) = match header {
                Some(h) => {
                    ensure!(segment.len() == segments, "this binary needs {segments} segment accounts, got {}", segment.len());
                    (h, segment)
                }
                None => {
                    let h = wallet.create_new_account_public(None).0;
                    let s: Vec<AccountId> = std::iter::repeat_with(|| wallet.create_new_account_public(None).0).take(segments).collect();
                    wallet.store_persistent_data()?;
                    (h, s)
                }
            };
            // Printed before anything is sent: with these ids, `deploy --header --segment`
            // resumes a deploy that stopped half way.
            eprintln!("{}", serde_json::json!({"op": "deploy-plan", "header": header.to_string(), "segments": segs.iter().map(|s| s.to_string()).collect::<Vec<_>>()}));
            let loader = ProgramLoader(&wallet);
            let chunks: Vec<&[u8]> = user_elf.chunks(program_loader_core::MAX_SEGMENT_DATA_LEN).collect();
            let mut sent: Vec<String> = vec![];
            // Segments last to first (each names the next), then the header. A step already on
            // chain is skipped, and a transaction the sequencer drops is sent again.
            for i in (0..segs.len()).rev() {
                let next = segs.get(i + 1).copied();
                let mut tries = 0;
                while !ctx.loaded(segs[i]).await? {
                    tries += 1;
                    ensure!(tries <= 6, "segment {i} ({}) is not on chain after 6 sends", segs[i]);
                    match loader.write_segment(segs[i], chunks[i].to_vec(), next, Some(payer)).await {
                        Ok(h) => {
                            eprintln!("segment {i}: sent {h} (try {tries})");
                            sent.push(format!("segment{i}:{h}"));
                        }
                        Err(e) => eprintln!("segment {i}: send failed (try {tries}): {e:?}"),
                    }
                    wait_for(|| ctx.loaded(segs[i]), Duration::from_secs(ctx.wait)).await;
                }
                eprintln!("segment {i}: on chain");
            }
            let mut tries = 0;
            while !ctx.loaded(header).await? {
                tries += 1;
                ensure!(tries <= 6, "the header {header} is not on chain after 6 sends");
                match loader.create_header(header, segs[0], &segs, false, Some(payer)).await {
                    Ok(h) => {
                        eprintln!("header: sent {h} (try {tries})");
                        sent.push(format!("header:{h}"));
                    }
                    Err(e) => eprintln!("header: send failed (try {tries}): {e:?}"),
                }
                wait_for(|| ctx.loaded(header), Duration::from_secs(ctx.wait)).await;
            }
            println!(
                "{}",
                serde_json::json!({"op": "deploy", "header": header.to_string(), "image_id": image_hex(&bytecode)?, "segments": segs.iter().map(|s| s.to_string()).collect::<Vec<_>>(), "sent": sent})
            );
        }
        Cmd::Init => {
            let p = ctx.program()?;
            let m = &ctx.m;
            let boot = lc::bootstrap(&m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).map_err(|e| anyhow!("{e:?}"))?;
            let ix = Instruction::Init {
                instance_id: id,
                checkpoint: m.checkpoint,
                cfg: ctx.cfg(),
                header: m.boot_header.clone(),
                committee: m.boot_committee.clone(),
                branch: m.boot_branch.clone(),
            };
            let rows = vec![instance_account(&p, &id), header_account(&p, &id, boot.finalized.slot)];
            ctx.run(wallet.as_ref().unwrap(), "init", ix, rows, 2_000_000).await?;
        }
        Cmd::Begin { n, tamper } => {
            let p = ctx.program()?;
            let (_, _, committee) = ctx.step(n)?;
            let current = ctx.current(n)?;
            let u = ctx.update(n, tamper)?;
            let w = witness(&committee, &u.bits, AggMode::Subtract);
            let job = job_account(&p, &id, &job_id(&current, &u));
            let ix = Instruction::Begin { instance_id: id, current, update: u, committee, witness: w };
            ctx.run(wallet.as_ref().unwrap(), "begin", ix, vec![instance_account(&p, &id), job], 6_000_000).await?;
        }
        Cmd::Miller { n, tamper } => {
            let p = ctx.program()?;
            let jid = job_id(&ctx.current(n)?, &ctx.update(n, tamper)?);
            let ix = Instruction::Miller { instance_id: id, job_id: jid };
            ctx.run(wallet.as_ref().unwrap(), "miller", ix, vec![job_account(&p, &id, &jid)], 5_000_000).await?;
        }
        Cmd::Finish { n, tamper } => {
            let p = ctx.program()?;
            let current = ctx.current(n)?;
            let jid = job_id(&current, &ctx.update(n, tamper)?);
            let next = ctx.next(n)?;
            let rows = vec![instance_account(&p, &id), job_account(&p, &id, &jid), header_account(&p, &id, next.finalized.slot)];
            let ix = Instruction::Finish { instance_id: id, job_id: jid, current, next };
            ctx.run(wallet.as_ref().unwrap(), "finish", ix, rows, 4_500_000).await?;
        }
        Cmd::Attest { at, kind, chain_id, negate, wrong_slot, slot_offset } => {
            let p = ctx.program()?;
            let m = &ctx.m;
            let slot = match at {
                At::Checkpoint => lc::bootstrap(&m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).map_err(|e| anyhow!("{e:?}"))?.finalized.slot,
                At::Final => ctx.next(mainnet_steps(m).len())?.finalized.slot,
            } + slot_offset;
            let (proof, predicate) = match kind {
                Kind::Log => {
                    let rp = match at {
                        At::Checkpoint => receipt_proof_from(&format!("{CHECKPOINT_BLOCK_DIR}/receipt-proof-tx{CHECKPOINT_TX}.json"), CHECKPOINT_TX),
                        At::Final => receipt_proof(2),
                    };
                    let cmp = if negate { Cmp::Ne } else { Cmp::Eq };
                    (Proof::Log(rp), Predicate { field: Field::LogTopic(0), cmp, value: hex32(TRANSFER) })
                }
                Kind::Storage => {
                    let mut wp = match at {
                        At::Checkpoint => weth_proof_from(&format!("{CHECKPOINT_BLOCK_DIR}/getproof-weth.json")),
                        At::Final => weth_proof(),
                    };
                    if wrong_slot {
                        wp.slot[0] ^= 1;
                    }
                    let mut one = [0u8; 32];
                    one[31] = 1;
                    let cmp = if negate { Cmp::Lt } else { Cmp::Ge };
                    (Proof::Storage(wp), Predicate { field: Field::SlotValue, cmp, value: one })
                }
            };
            let ix = Instruction::Attest { instance_id: id, slot, query: Query { chain_id, proof, predicates: vec![predicate] } };
            ctx.run(wallet.as_ref().unwrap(), "attest", ix, vec![header_account(&p, &id, slot)], 500_000).await?;
        }
    }
    Ok(())
}

/// Polls `done` every 5 s until it holds or `limit` passes; a timeout is not an
/// error, the caller decides whether to send again.
async fn wait_for<F, Fut>(done: F, limit: Duration)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    let start = std::time::Instant::now();
    while start.elapsed() < limit {
        if done().await.unwrap_or(false) {
            return;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

