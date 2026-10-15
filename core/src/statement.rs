//! The consumer side: a query (a proof and a predicate) evaluated against a
//! finalized header the program recorded, yielding a verified statement with
//! a deterministic identifier a consumer can key a nullifier on (F.3, F.4,
//! F.5, F.6).

use crate::mpt::{self, AccountSlot, AccountStorageProof, Log, ReceiptProof};
use crate::types::Root;
use crate::Error;
use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest, Sha256};

/// What the program keeps of each finalized header it verified: immutable,
/// one account per header, so a consumer's proof never races an update.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HeaderRecord {
    pub chain_id: u64,
    pub slot: u64,
    pub beacon_root: Root,
    pub block_number: u64,
    pub state_root: Root,
    pub receipts_root: Root,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// A value the statement exposes, as a 32-byte big-endian word.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Field {
    AccountBalance,
    AccountNonce,
    SlotValue,
    LogAddress,
    LogTopic(u8),
    /// The `i`-th 32-byte word of the log's data.
    LogDataWord(u8),
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Predicate {
    pub field: Field,
    pub cmp: Cmp,
    pub value: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum Proof {
    Storage(AccountStorageProof),
    Log(ReceiptProof),
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Query {
    /// The chain the consumer expects; refused if the record is another's.
    pub chain_id: u64,
    pub proof: Proof,
    /// All must hold (a compound condition over one header, soft #4).
    pub predicates: Vec<Predicate>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Statement {
    /// `sha256` over the chain and the attested state itself (decision D6).
    pub id: Root,
    pub chain_id: u64,
    pub block_number: u64,
    pub predicates: Vec<Predicate>,
}

fn word(b: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    let n = b.len().min(32);
    w[32 - n..].copy_from_slice(&b[b.len() - n..]);
    w
}

fn holds(v: &[u8; 32], p: &Predicate) -> bool {
    match p.cmp {
        Cmp::Eq => v == &p.value,
        Cmp::Ne => v != &p.value,
        Cmp::Lt => v < &p.value,
        Cmp::Le => v <= &p.value,
        Cmp::Gt => v > &p.value,
        Cmp::Ge => v >= &p.value,
    }
}

/// Verify `q` against `r` and return the statement, or the typed refusal.
pub fn evaluate(r: &HeaderRecord, q: &Query) -> Result<Statement, Error> {
    if q.chain_id != r.chain_id {
        return Err(Error::ChainMismatch);
    }
    let mut h = Sha256::new();
    h.update(b"sextant/statement/v1");
    h.update(r.chain_id.to_le_bytes());
    let lookup: Box<dyn Fn(Field) -> Option<[u8; 32]>> = match &q.proof {
        Proof::Storage(p) => {
            let a: AccountSlot = borsh::from_slice(&mpt::verify_account_storage(&r.state_root, p)?).unwrap();
            // A state fact: the same account and slot holding the same values
            // is the same statement, whichever finalized block it is read at.
            h.update([0u8]);
            h.update(p.address);
            h.update(p.slot);
            h.update(a.balance);
            h.update(a.nonce);
            h.update(a.slot_value);
            Box::new(move |f| match f {
                Field::AccountBalance => Some(a.balance),
                Field::AccountNonce => Some(a.nonce),
                Field::SlotValue => Some(a.slot_value),
                _ => None,
            })
        }
        Proof::Log(p) => {
            let l: Log = borsh::from_slice(&mpt::verify_receipt_log(&r.receipts_root, p)?).unwrap();
            if l.status != 1 {
                return Err(Error::PredicateFalse); // a reverted transaction's logs prove nothing happened
            }
            // An event: unique to its block, transaction and position.
            h.update([1u8]);
            h.update(r.block_number.to_le_bytes());
            h.update(p.tx_index.to_le_bytes());
            h.update(p.log_index.to_le_bytes());
            h.update(l.address);
            for t in &l.topics {
                h.update(t);
            }
            h.update(&l.data);
            Box::new(move |f| match f {
                Field::LogAddress => Some(word(&l.address)),
                Field::LogTopic(i) => l.topics.get(i as usize).copied(),
                Field::LogDataWord(i) => l.data.get(32 * i as usize..32 * i as usize + 32).map(word),
                _ => None,
            })
        }
    };
    for p in &q.predicates {
        let v = lookup(p.field).ok_or(Error::Malformed)?;
        if !holds(&v, p) {
            return Err(Error::PredicateFalse);
        }
    }
    Ok(Statement { id: h.finalize().into(), chain_id: r.chain_id, block_number: r.block_number, predicates: q.predicates.clone() })
}
