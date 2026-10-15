//! `FastAggregateVerify` as Ethereum uses it (BLS12-381, minimal-pubkey-size,
//! proof-of-possession ciphersuite), over two interchangeable backends, split
//! into the steps whose cost we measure. Points cross this interface
//! uncompressed and already validated.

use crate::lc::{AggMode, Opts, COMMITTEE_SIZE};
use crate::types::{KeyWitness, SyncCommittee};
use crate::{bl, Error};
#[cfg(feature = "zkcrypto")]
use crate::zk;

/// The proof-of-possession ciphersuite Ethereum signs with.
pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[derive(Clone, Copy, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum Lib {
    /// zkcrypto `bls12_381` (the r0vm-helios / SP1 Helios base).
    Zkcrypto,
    /// supranational `blst` (the program's choice, decision D1).
    Blst,
}

/// How the program turns a committed 48-byte key into a curve point.
#[derive(Clone, Copy, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum KeyMode {
    /// Decompress (a square root) and check the subgroup, per key.
    Checked,
    /// Decompress, no subgroup check.
    Unchecked,
    /// The submitter supplies the uncompressed point; the program checks that
    /// it is on the curve and compresses to the committed bytes. No square
    /// root and no subgroup check: sound because the key's bytes are bound to
    /// a sync-committee root verified against a beacon state root, and every
    /// key in a beacon state passed `KeyValidate` when its deposit was
    /// processed (consensus-specs `process_deposit` verifies a proof of
    /// possession). The check is only that the witness *is* that key.
    Witness,
}

pub fn bit(bits: &[u8; 64], i: usize) -> bool {
    (bits[i / 8] >> (i % 8)) & 1 == 1
}

pub fn participants(bits: &[u8; 64]) -> usize {
    bits.iter().map(|b| b.count_ones() as usize).sum()
}

fn wit(w: &KeyWitness, i: usize) -> Option<&[u8]> {
    w.points.iter().find(|(j, _)| *j as usize == i).map(|(_, p)| p.as_slice())
}

/// The aggregate key of the members `bits` marks, uncompressed.
pub fn signing_key(lib: Lib, c: &SyncCommittee, bits: &[u8; 64], w: &KeyWitness, o: Opts) -> Result<[u8; 96], Error> {
    let take = |want: bool| (0..COMMITTEE_SIZE).filter(move |i| bit(bits, *i) == want);
    macro_rules! go {
        ($m:ident) => {{
            let dec = |i: usize| $m::decode_key(&c.pubkeys[i], o.keys, wit(w, i)).ok_or(Error::BadKey);
            match o.agg {
                AggMode::Sum => {
                    let pts = take(true).map(dec).collect::<Result<Vec<_>, _>>()?;
                    Ok($m::combine(&pts, &[]))
                }
                AggMode::Subtract => {
                    let all = $m::decode_key(&c.aggregate, o.keys, Some(&w.aggregate)).ok_or(Error::BadKey)?;
                    let pts = take(false).map(dec).collect::<Result<Vec<_>, _>>()?;
                    Ok($m::combine(&[all], &pts))
                }
            }
        }};
    }
    match lib {
        #[cfg(feature = "zkcrypto")]
        Lib::Zkcrypto => go!(zk),
        #[cfg(not(feature = "zkcrypto"))]
        Lib::Zkcrypto => Err(Error::Malformed),
        Lib::Blst => go!(bl),
    }
}

pub fn hash_to_g2(lib: Lib, msg: &[u8]) -> [u8; 192] {
    match lib {
        #[cfg(feature = "zkcrypto")]
        Lib::Zkcrypto => zk::hash_to_g2(msg),
        #[cfg(not(feature = "zkcrypto"))]
        Lib::Zkcrypto => unimplemented!("built without the zkcrypto backend"),
        Lib::Blst => bl::hash_to_g2(msg),
    }
}

pub fn decode_signature(lib: Lib, sig: &[u8; 96]) -> Option<[u8; 192]> {
    match lib {
        #[cfg(feature = "zkcrypto")]
        Lib::Zkcrypto => zk::decode_signature(sig),
        #[cfg(not(feature = "zkcrypto"))]
        Lib::Zkcrypto => unimplemented!("built without the zkcrypto backend"),
        Lib::Blst => bl::decode_signature(sig),
    }
}

pub fn pairing_check(lib: Lib, pk: &[u8; 96], hm: &[u8; 192], sig: &[u8; 192]) -> bool {
    match lib {
        #[cfg(feature = "zkcrypto")]
        Lib::Zkcrypto => zk::pairing_check(pk, hm, sig),
        #[cfg(not(feature = "zkcrypto"))]
        Lib::Zkcrypto => unimplemented!("built without the zkcrypto backend"),
        Lib::Blst => bl::pairing_check(pk, hm, sig),
    }
}
