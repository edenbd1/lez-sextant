//! Merkle-Patricia proofs against an execution-layer root: an account and
//! one of its storage slots (`eth_getProof`), and a receipt with one of its
//! logs. The consumer-side cost of an attestation is this file.

use crate::Error;
use borsh::{BorshDeserialize, BorshSerialize};
use tiny_keccak::{Hasher, Keccak};

pub fn keccak(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(data);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

// ---- RLP, decoding only ----

/// `(is_list, payload start, payload length)` of the item at the start of `b`.
fn header(b: &[u8]) -> Result<(bool, usize, usize), Error> {
    let p = *b.first().ok_or(Error::BadInclusion)?;
    let be = |n: usize| -> Result<usize, Error> {
        let s = b.get(1..1 + n).ok_or(Error::BadInclusion)?;
        Ok(s.iter().fold(0usize, |a, x| (a << 8) | *x as usize))
    };
    Ok(match p {
        0x00..=0x7f => (false, 0, 1),
        0x80..=0xb7 => (false, 1, (p - 0x80) as usize),
        0xb8..=0xbf => {
            let n = (p - 0xb7) as usize;
            (false, 1 + n, be(n)?)
        }
        0xc0..=0xf7 => (true, 1, (p - 0xc0) as usize),
        _ => {
            let n = (p - 0xf7) as usize;
            (true, 1 + n, be(n)?)
        }
    })
}

/// The items of an RLP list, each as its full encoding.
fn list(b: &[u8]) -> Result<Vec<&[u8]>, Error> {
    let (is_list, off, len) = header(b)?;
    if !is_list || off + len != b.len() {
        return Err(Error::BadInclusion);
    }
    let mut out = vec![];
    let mut rest = &b[off..];
    while !rest.is_empty() {
        let (_, o, l) = header(rest)?;
        let (item, r) = rest.split_at_checked(o + l).ok_or(Error::BadInclusion)?;
        out.push(item);
        rest = r;
    }
    Ok(out)
}

/// The payload of an RLP string.
fn bytes(item: &[u8]) -> Result<&[u8], Error> {
    let (is_list, off, len) = header(item)?;
    if is_list {
        return Err(Error::BadInclusion);
    }
    item.get(off..off + len).ok_or(Error::BadInclusion)
}

fn nibbles(key: &[u8]) -> Vec<u8> {
    key.iter().flat_map(|b| [b >> 4, b & 0x0f]).collect()
}

/// Hex-prefix decoding: `(is_leaf, path nibbles)`.
fn hex_prefix(enc: &[u8]) -> Result<(bool, Vec<u8>), Error> {
    let n = nibbles(enc);
    let flag = *n.first().ok_or(Error::BadInclusion)?;
    let leaf = flag & 2 == 2;
    let odd = flag & 1 == 1;
    Ok((leaf, n[if odd { 1 } else { 2 }..].to_vec()))
}

/// Walk `proof` from `root` along `key`. `Ok(Some(value))` proves inclusion,
/// `Ok(None)` proves absence, `Err` means the proof does not verify.
pub fn get(root: &[u8; 32], key: &[u8], proof: &[Vec<u8>]) -> Result<Option<Vec<u8>>, Error> {
    let path = nibbles(key);
    let mut at = 0usize;
    let mut want: Vec<u8> = root.to_vec(); // a 32-byte hash, or an inline node
    let mut nodes = proof.iter();
    loop {
        let node: Vec<u8> = if want.len() == 32 {
            let n = nodes.next().ok_or(Error::BadInclusion)?;
            if keccak(n) != want.as_slice() {
                return Err(Error::BadInclusion);
            }
            n.clone()
        } else {
            want.clone()
        };
        let items = list(&node)?;
        match items.len() {
            17 => {
                if at == path.len() {
                    let v = bytes(items[16])?;
                    return Ok((!v.is_empty()).then(|| v.to_vec()));
                }
                let child = items[path[at] as usize];
                at += 1;
                want = child_ref(child)?;
                if want.is_empty() {
                    return Ok(None);
                }
            }
            2 => {
                let (leaf, p) = hex_prefix(bytes(items[0])?)?;
                if leaf {
                    return Ok((path[at..] == p[..]).then(|| bytes(items[1]).map(|v| v.to_vec())).transpose()?);
                }
                if !path[at..].starts_with(&p) {
                    return Ok(None);
                }
                at += p.len();
                want = child_ref(items[1])?;
            }
            _ => return Err(Error::BadInclusion),
        }
    }
}

/// A child reference: a 32-byte hash, an inline node (a list under 32 bytes), or empty.
fn child_ref(item: &[u8]) -> Result<Vec<u8>, Error> {
    let (is_list, _, _) = header(item)?;
    if is_list {
        Ok(item.to_vec())
    } else {
        let v = bytes(item)?;
        if v.is_empty() || v.len() == 32 {
            Ok(v.to_vec())
        } else {
            Err(Error::BadInclusion)
        }
    }
}

fn be32(v: &[u8]) -> Result<[u8; 32], Error> {
    if v.len() > 32 {
        return Err(Error::BadInclusion);
    }
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(v);
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountStorageProof {
    pub address: [u8; 20],
    pub account_proof: Vec<Vec<u8>>,
    pub slot: [u8; 32],
    pub storage_proof: Vec<Vec<u8>>,
}

/// What an account-and-slot proof establishes.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct AccountSlot {
    pub nonce: [u8; 32],
    pub balance: [u8; 32],
    pub storage_root: [u8; 32],
    pub code_hash: [u8; 32],
    pub slot_value: [u8; 32],
}

pub fn verify_account_storage(state_root: &[u8; 32], p: &AccountStorageProof) -> Result<Vec<u8>, Error> {
    let acct = get(state_root, &keccak(&p.address), &p.account_proof)?.ok_or(Error::BadInclusion)?;
    let f = list(&acct)?;
    if f.len() != 4 {
        return Err(Error::BadInclusion);
    }
    let storage_root = be32(bytes(f[2])?)?;
    let v = match get(&storage_root, &keccak(&p.slot), &p.storage_proof)? {
        Some(enc) => be32(bytes(&enc)?)?,
        None => [0u8; 32],
    };
    let out = AccountSlot {
        nonce: be32(bytes(f[0])?)?,
        balance: be32(bytes(f[1])?)?,
        storage_root,
        code_hash: be32(bytes(f[3])?)?,
        slot_value: v,
    };
    Ok(borsh::to_vec(&out).unwrap())
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ReceiptProof {
    pub tx_index: u64,
    pub proof: Vec<Vec<u8>>,
    pub log_index: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Log {
    pub status: u8,
    pub address: [u8; 20],
    pub topics: Vec<[u8; 32]>,
    pub data: Vec<u8>,
}

fn rlp_index(i: u64) -> Vec<u8> {
    if i == 0 {
        return vec![0x80];
    }
    let b: Vec<u8> = i.to_be_bytes().iter().copied().skip_while(|x| *x == 0).collect();
    if b.len() == 1 && b[0] < 0x80 {
        b
    } else {
        let mut o = vec![0x80 + b.len() as u8];
        o.extend(b);
        o
    }
}

pub fn verify_receipt_log(receipts_root: &[u8; 32], p: &ReceiptProof) -> Result<Vec<u8>, Error> {
    let r = get(receipts_root, &rlp_index(p.tx_index), &p.proof)?.ok_or(Error::BadInclusion)?;
    // Typed receipts are `type ‖ rlp(...)`; legacy ones start with a list header.
    let body = if r.first().copied().unwrap_or(0) < 0x7f { &r[1..] } else { &r[..] };
    let f = list(body)?;
    if f.len() != 4 {
        return Err(Error::BadInclusion);
    }
    let status = bytes(f[0])?.first().copied().unwrap_or(0);
    let logs = list(f[3])?;
    let log = list(logs.get(p.log_index as usize).ok_or(Error::BadInclusion)?)?;
    if log.len() != 3 {
        return Err(Error::BadInclusion);
    }
    let address: [u8; 20] = bytes(log[0])?.try_into().map_err(|_| Error::BadInclusion)?;
    let topics = list(log[1])?
        .into_iter()
        .map(|t| bytes(t).and_then(|b| b.try_into().map_err(|_| Error::BadInclusion)))
        .collect::<Result<Vec<[u8; 32]>, Error>>()?;
    let out = Log { status, address, topics, data: bytes(log[2])?.to_vec() };
    Ok(borsh::to_vec(&out).unwrap())
}
