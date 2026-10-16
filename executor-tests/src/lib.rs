//! A one-node LEZ v0.3 chain in memory, for the committed sextant_lc binary.
//!
//! Transactions are signed `PublicTransaction`s and go through
//! `ValidatedStateDiff::from_public_transaction_with_cycle_budget`, the call
//! the sequencer's settlement makes, then `V03State::apply_state_diff`. The
//! plan and every apply run in the RISC Zero executor; the cycle count is the
//! gas the transaction is charged.

use lee::{
    public_transaction::{Message, WitnessSet},
    AccountId, PrivateKey, ProgramShardSelector, PublicKey, PublicTransaction, V03State, ValidatedStateDiff,
};
use sextant_core::lc::{self, AggMode};
use sextant_core::{Store, SyncCommittee, Update};
use sextant_host::{witness, Mainnet};
use sextant_program::{header_account, instance_account, job_account, job_id, Instance, Instruction};

/// The most execution gas one transaction may declare (and one block may
/// hold): `MAX_GAS_EXEC`, cycles one for one.
pub const GAS_CAP: u64 = 10_000_000;

/// The header account the tests deploy the program at.
pub const LC: AccountId = AccountId::new(*b"sextant_lc/test/header/000000001");

pub const BIN: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../artifacts/programs/v0.3/sextant_lc.bin");

/// A key with no prior relationship to anything: a fresh account each time.
pub struct Key {
    pub sk: PrivateKey,
    pub id: AccountId,
}

impl Key {
    #[must_use]
    pub fn new(seed: u16) -> Self {
        let mut b = [0x5a; 32];
        b[..2].copy_from_slice(&seed.to_le_bytes());
        let sk = PrivateKey::try_new(b).expect("a valid secp256k1 scalar");
        let id = AccountId::from(&PublicKey::new_from_private_key(&sk));
        Self { sk, id }
    }
}

pub struct Chain {
    pub state: V03State,
    pub block: u64,
    pub now: u64,
    pub last_cycles: u64,
    next_key: u16,
}

impl Chain {
    #[must_use]
    pub fn new() -> Self {
        let path = std::env::var("SEXTANT_BIN").unwrap_or_else(|_| BIN.to_string());
        let bin = std::fs::read(&path).expect("build and pack the guest first: scripts/build-guests.sh lez");
        let program = lee::program::Program::new(bin.into()).expect("a RISC0 program binary");
        let state = V03State::new().with_named_programs([(LC, program)]);
        Self { state, block: 10, now: 1_760_000_000_000, last_cycles: 0, next_key: 1 }
    }

    /// Send `ix` over `rows`, signed by a brand-new account (F.11: no
    /// registration, no role, no prior relationship).
    pub fn send(&mut self, ix: &Instruction, rows: Vec<AccountId>) -> Result<u64, String> {
        let k = Key::new(self.next_key);
        self.next_key += 1;
        let rows = rows.into_iter().map(|a| ProgramShardSelector::new(a, LC)).collect();
        let nonces = vec![self.state.get_account_by_id(k.id).nonce];
        let message = Message::try_new(LC, rows, nonces, ix).map_err(|e| e.to_string())?;
        let tx = PublicTransaction::new(message.clone(), WitnessSet::for_message(&message, &[&k.sk]));
        let r = ValidatedStateDiff::from_public_transaction_with_cycle_budget(&tx, &self.state, self.block, self.now, GAS_CAP);
        self.block += 1;
        self.now += 12_000;
        match r {
            Ok((diff, charge)) => {
                self.last_cycles = charge.cycles;
                let _ = self.state.apply_state_diff(diff);
                Ok(charge.cycles)
            }
            Err(e) => Err(format!("{e}")),
        }
    }

    #[must_use]
    pub fn shard(&self, id: AccountId) -> Vec<u8> {
        self.state.get_account_by_id(id).data.shard(LC).to_vec()
    }

    #[must_use]
    pub fn instance(&self, instance_id: &[u8; 32]) -> Instance {
        borsh::from_slice(&self.shard(instance_account(&LC, instance_id))).expect("an instance")
    }
}

impl Default for Chain {
    fn default() -> Self {
        Self::new()
    }
}

pub const ID: [u8; 32] = *b"mainnet/test/instance/0000000001";

/// `Init` from the mainnet checkpoint.
pub fn init(c: &mut Chain, m: &Mainnet, id: [u8; 32]) -> Result<u64, String> {
    let s = lc::bootstrap(&m.cfg, &m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).unwrap();
    let ix = Instruction::Init {
        instance_id: id,
        checkpoint: m.checkpoint,
        cfg: m.cfg.clone(),
        header: m.boot_header.clone(),
        committee: m.boot_committee.clone(),
        branch: m.boot_branch.clone(),
    };
    c.send(&ix, vec![instance_account(&LC, &id), header_account(&LC, &id, s.finalized.slot)])
}

/// The three transactions of one update; returns their gas.
pub fn advance(c: &mut Chain, id: [u8; 32], u: &Update, committee: &SyncCommittee) -> Result<[u64; 3], String> {
    let current = c.instance(&id);
    let w = witness(committee, &u.bits, AggMode::Subtract);
    let next: Store = lc::apply_update(&current.cfg, &current.store, u, committee, &w, lc::FAST, &mut |_| {}).map_err(|e| format!("{e:?}"))?;
    let jid = job_id(&current, u);
    let job = job_account(&LC, &id, &jid);
    let begin = Instruction::Begin { instance_id: id, current: current.clone(), update: u.clone(), committee: committee.clone(), witness: w };
    let g1 = c.send(&begin, vec![instance_account(&LC, &id), job])?;
    let g2 = c.send(&Instruction::Miller { instance_id: id, job_id: jid }, vec![job])?;
    let fin = Instruction::Finish { instance_id: id, job_id: jid, current, next: next.clone() };
    let g3 = c.send(&fin, vec![instance_account(&LC, &id), job, header_account(&LC, &id, next.finalized.slot)])?;
    Ok([g1, g2, g3])
}

pub fn refusal(e: &str) -> Option<u32> {
    let i = e.find("E72")?;
    e[i + 1..i + 5].parse().ok()
}
