//! erc20_receiver: the smallest useful consumer of sextant_lc.
//!
//! `Claim` says "this ERC-20 `Transfer` of `amount` from `from` to the
//! receiver's `recipient` happened in Ethereum block `block_number`" and
//! credits the receiver, once. The program does no Ethereum verification of
//! its own: it hands the receipt proof and the predicates to sextant_lc's
//! `Attest` as a chained call, so the claim lands only if the light client
//! accepts it, in the same transaction (all or nothing).
//!
//! Accounts:
//!
//! - **header** (sextant_lc's shard): the record sextant_lc wrote for `slot`.
//!   This program reads it, without writing, to bind the claimed block number
//!   and chain to what the light client finalized; `Attest` then checks the
//!   proof against the same record's receipts root.
//! - **receiver** `sha256("receiver" ‖ borsh(Receiver))`: the running count
//!   and total credited. Its address commits to the whole configuration,
//!   including which sextant_lc deployment and instance it trusts, so a
//!   receiver bound to another light client is another account.
//! - **nullifier** `sha256("nullifier" ‖ receiver ‖ statement_id)`: written
//!   once per transfer; a second claim of the same transfer finds it and is
//!   refused. The statement identifier is sextant's (`statement::evaluate`,
//!   decision D6): the chain, the block, the transaction and log position,
//!   and the log itself, so the same transfer always maps to the same
//!   nullifier, whichever header or instance it is proven under.
//!
//! A v0.3 `plan` cannot read accounts; as in sextant_lc, it does the pure
//! work and hands `apply` what to check against the stored bytes.

use borsh::{BorshDeserialize, BorshSerialize};
use lee_core::{
    account::{AccountId, ProgramShardSelector},
    program::{AccountMeta, ChainedCall, PdaSeed, Plan, PlanInput, ProgramEvent},
};
use sextant_core::mpt::ReceiptProof;
use sextant_core::statement::{Cmp, Field, HeaderRecord, Predicate, Proof, Query};
use sextant_program::{header_account, sha256};

/// `keccak256("Transfer(address,address,uint256)")`.
pub const TRANSFER: [u8; 32] = [
    0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b, 0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa, 0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4,
    0xa1, 0x16, 0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
];

pub const E_ACCOUNTS: u32 = 7390;
pub const E_CLAIMED: u32 = 7391;
pub const E_NO_HEADER: u32 = 7392;
pub const E_HEADER: u32 = 7393;
pub const E_OVERFLOW: u32 = 7394;

#[track_caller]
pub fn refuse(code: u32, why: &str) -> ! {
    panic!("E{code}: {why}")
}

#[track_caller]
fn refuse_unless(ok: bool, code: u32, why: &str) {
    if !ok {
        refuse(code, why);
    }
}

/// What a receiver credits, fixed by its address.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Receiver {
    /// The sextant_lc deployment (program header account) it trusts.
    pub sextant: AccountId,
    pub instance_id: [u8; 32],
    pub chain_id: u64,
    /// The ERC-20 contract.
    pub token: [u8; 20],
    pub recipient: [u8; 20],
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Instruction {
    /// Rows: [header (sextant_lc's shard), receiver, nullifier].
    Claim { receiver: Receiver, slot: u64, block_number: u64, from: [u8; 20], amount: [u8; 32], proof: ReceiptProof },
}

/// What the nullifier account holds: the claim it spent.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Claimed {
    pub statement_id: [u8; 32],
    pub slot: u64,
    pub block_number: u64,
    pub tx_index: u64,
    pub log_index: u32,
    pub from: [u8; 20],
    pub amount: [u8; 32],
}

/// What the receiver account holds.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Totals {
    pub claims: u64,
    /// Sum of the amounts, a 256-bit big-endian word like the log's.
    pub total: [u8; 32],
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Effect {
    /// Read only, on sextant_lc's header record: it exists, for this chain and block.
    Header { chain_id: u64, slot: u64, block_number: u64 },
    /// The nullifier is unspent; spend it.
    Spend(Claimed),
    Credit([u8; 32]),
}

pub fn word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

pub fn receiver_account(me: &AccountId, r: &Receiver) -> AccountId {
    AccountId::for_public_pda(me, &PdaSeed::new(sha256(&[b"receiver", &borsh::to_vec(r).expect("infallible")])))
}

pub fn nullifier_account(me: &AccountId, receiver: &AccountId, statement_id: &[u8; 32]) -> AccountId {
    AccountId::for_public_pda(me, &PdaSeed::new(sha256(&[b"nullifier", receiver.value(), statement_id])))
}

/// sextant's statement identifier (`sextant_core::statement::evaluate`) for
/// a log with exactly these three topics and 32 bytes of data, the shape of
/// every ERC-20 `Transfer`. The predicates below pin each of these fields to
/// the proven log, so no other identifier can be claimed for one transfer.
pub fn statement_id(chain_id: u64, block_number: u64, proof: &ReceiptProof, token: &[u8; 20], topics: &[[u8; 32]; 3], data: &[u8; 32]) -> [u8; 32] {
    sha256(&[
        b"sextant/statement/v1",
        &chain_id.to_le_bytes(),
        &[1u8],
        &block_number.to_le_bytes(),
        &proof.tx_index.to_le_bytes(),
        &proof.log_index.to_le_bytes(),
        token,
        &topics[0],
        &topics[1],
        &topics[2],
        data,
    ])
}

/// The query `Attest` must accept: the log at the proof's position is a
/// `Transfer` by `token`, from `from`, to the recipient, of `amount`.
pub fn query(r: &Receiver, from: &[u8; 20], amount: &[u8; 32], proof: ReceiptProof) -> Query {
    let eq = |field, value| Predicate { field, cmp: Cmp::Eq, value };
    Query {
        chain_id: r.chain_id,
        proof: Proof::Log(proof),
        predicates: vec![
            eq(Field::LogAddress, word(&r.token)),
            eq(Field::LogTopic(0), TRANSFER),
            eq(Field::LogTopic(1), word(from)),
            eq(Field::LogTopic(2), word(&r.recipient)),
            eq(Field::LogDataWord(0), *amount),
        ],
    }
}

#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub struct Credited {
    pub receiver: AccountId,
    pub statement_id: [u8; 32],
    pub block_number: u64,
    pub amount: [u8; 32],
}

fn rows<const N: usize>(input: &PlanInput) -> [AccountMeta; N] {
    <[AccountMeta; N]>::try_from(input.accounts.clone()).unwrap_or_else(|_| refuse(E_ACCOUNTS, "wrong number of accounts for this instruction"))
}

#[must_use]
pub fn plan(input: &PlanInput, ix: Instruction) -> Plan {
    let me = input.self_account_id;
    let mut plan = Plan::new(input);
    match ix {
        Instruction::Claim { receiver, slot, block_number, from, amount, proof } => {
            let [hdr, rcv, nul] = rows::<3>(input);
            refuse_unless(
                hdr.account_id == header_account(&receiver.sextant, &receiver.instance_id, slot) && hdr.program_account_id == receiver.sextant,
                E_ACCOUNTS,
                "the first row is sextant_lc's header record for this slot",
            );
            let rid = receiver_account(&me, &receiver);
            refuse_unless(rcv.account_id == rid && rcv.program_account_id == me, E_ACCOUNTS, "the second row is the receiver PDA");
            let topics = [TRANSFER, word(&from), word(&receiver.recipient)];
            let id = statement_id(receiver.chain_id, block_number, &proof, &receiver.token, &topics, &amount);
            refuse_unless(
                nul.account_id == nullifier_account(&me, &rid, &id) && nul.program_account_id == me,
                E_ACCOUNTS,
                "the third row is this transfer's nullifier PDA",
            );
            let claimed = Claimed { statement_id: id, slot, block_number, tx_index: proof.tx_index, log_index: proof.log_index, from, amount };
            plan.inspect(&hdr, receiver.sextant, &Effect::Header { chain_id: receiver.chain_id, slot, block_number });
            plan.effect(&nul, &Effect::Spend(claimed));
            plan.effect(&rcv, &Effect::Credit(amount));
            // The verification itself: sextant_lc's consumer check, over the
            // same header row. If it refuses, the whole transaction does.
            let attest = sextant_program::Instruction::Attest { instance_id: receiver.instance_id, slot, query: query(&receiver, &from, &amount, proof) };
            plan.call(ChainedCall::new(receiver.sextant, vec![ProgramShardSelector::from(&hdr)], &attest));
            let sel = sha256(&[b"erc20_receiver::Credited"]);
            plan.event(ProgramEvent {
                selector: sel[..8].try_into().expect("8 bytes"),
                data: borsh::to_vec(&Credited { receiver: rid, statement_id: id, block_number, amount }).expect("infallible"),
            });
        }
    }
    plan
}

fn add(a: &[u8; 32], b: &[u8; 32]) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = u16::from(a[i]) + u16::from(b[i]) + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    (carry == 0).then_some(out)
}

fn put<T: BorshSerialize>(t: &T) -> Vec<u8> {
    borsh::to_vec(t).expect("infallible")
}

#[must_use]
pub fn apply(effect: Effect, pre: &[u8]) -> Option<Vec<u8>> {
    match effect {
        Effect::Header { chain_id, slot, block_number } => {
            refuse_unless(!pre.is_empty(), E_NO_HEADER, "sextant_lc has recorded no header at this slot: wait for the update that finalizes it");
            let r: HeaderRecord = borsh::from_slice(pre).expect("a header record");
            refuse_unless(
                r.chain_id == chain_id && r.slot == slot && r.block_number == block_number,
                E_HEADER,
                "the recorded header is not the claimed chain and block",
            );
            None
        }
        Effect::Spend(c) => {
            refuse_unless(pre.is_empty(), E_CLAIMED, "this transfer was already claimed for this receiver");
            Some(put(&c))
        }
        Effect::Credit(amount) => {
            let mut t: Totals = if pre.is_empty() { Totals::default() } else { borsh::from_slice(pre).expect("totals") };
            t.claims += 1;
            t.total = add(&t.total, &amount).unwrap_or_else(|| refuse(E_OVERFLOW, "the total would overflow 256 bits"));
            Some(put(&t))
        }
    }
}
