//! sextant-core: Ethereum light-client verification for a RISC Zero guest,
//! as the RFP-021 prototype measures it.

pub mod bl;
pub mod bls;
pub mod lc;
#[cfg(feature = "zkcrypto")]
pub mod zk;
pub mod mpt;
pub mod ssz;
pub mod statement;
pub mod types;

use borsh::{BorshDeserialize, BorshSerialize};
pub use types::*;

/// Typed refusals (U.5). The code is stable; the message says what to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
#[repr(u8)]
#[borsh(use_discriminant = true)]
pub enum Error {
    Malformed = 1,
    NotFinalized = 2,
    BadSignature = 3,
    HandoffNotVerified = 4,
    BelowParticipation = 5,
    CheckpointStale = 6,
    BadInclusion = 7,
    PredicateFalse = 8,
    ChainMismatch = 9,
    AlreadyApplied = 10,
    BadExecutionBranch = 11,
    BadCommitteeBranch = 12,
    CommitteeMismatch = 13,
    BadKey = 14,
    CheckpointMismatch = 15,
}

/// One measured operation. The guest runs it and journals the cycle count
/// reached after each stage. Points are passed uncompressed and validated.
#[derive(Clone, Debug, BorshSerialize, BorshDeserialize)]
pub enum Op {
    /// (a) One pairing check `e(pk, hm) == e(g1, sig)`, by stage.
    Pairing { lib: bls::Lib, pk: Vec<u8>, hm: Vec<u8>, sig: Vec<u8> },
    /// `hash_to_curve` of a 32-byte signing root onto G2.
    HashToG2 { lib: bls::Lib, msg: [u8; 32] },
    /// Signature decompression with its subgroup check.
    DecodeSignature { lib: bls::Lib, sig: [u8; 96] },
    /// (b) Assemble the signing key for `bits` from a committee.
    SigningKey { committee: SyncCommittee, bits: [u8; 64], witness: KeyWitness, opts: lc::Opts },
    /// `hash_tree_root` of a 512-key committee.
    CommitteeRoot { committee: SyncCommittee },
    /// The whole `FastAggregateVerify` on a committee, bits, message and signature.
    FastAggregateVerify { committee: SyncCommittee, bits: [u8; 64], witness: KeyWitness, opts: lc::Opts, msg: [u8; 32], sig: [u8; 96] },
    /// (c) A whole `LightClientUpdate` against a store, in one session.
    Update { cfg: ChainConfig, store: Store, update: Update, committee: SyncCommittee, witness: KeyWitness, opts: lc::Opts },
    /// (c), split: every check but the pairing.
    Prepare { cfg: ChainConfig, store: Store, update: Update, committee: SyncCommittee, witness: KeyWitness, opts: lc::Opts },
    /// (c), split: the two Miller loops (blst).
    Miller { pk: Vec<u8>, hm: Vec<u8>, sig: Vec<u8> },
    /// (c), split: the final exponentiation (blst).
    FinalExp { f: Vec<u8> },
    /// Instance initialisation from a `LightClientBootstrap`.
    Bootstrap { root: [u8; 32], header: LcHeader, committee: SyncCommittee, branch: Vec<[u8; 32]> },
    /// Consumer side: an account and storage-slot proof under a state root.
    StorageProof { state_root: [u8; 32], proof: mpt::AccountStorageProof },
    /// Consumer side: a receipt (and one of its logs) under a receipts root.
    ReceiptProof { receipts_root: [u8; 32], proof: mpt::ReceiptProof },
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Report {
    pub ok: Result<Vec<u8>, Error>,
    /// `(stage, cycle counter after it)`.
    pub marks: Vec<(String, u64)>,
}

fn arr<const N: usize>(v: &[u8]) -> Result<&[u8; N], Error> {
    v.try_into().map_err(|_| Error::Malformed)
}

/// Run `op`; `clock` reads the cycle counter (zero on the host).
pub fn run(op: &Op, clock: &dyn Fn() -> u64) -> Report {
    let mut marks: Vec<(String, u64)> = vec![("start".into(), clock())];
    let mut mark = |l: &'static str| marks.push((l.into(), clock()));
    let ok: Result<Vec<u8>, Error> = (|| match op {
        Op::Pairing { lib, pk, hm, sig } => {
            let (pk, hm, sig) = (arr::<96>(pk)?, arr::<192>(hm)?, arr::<192>(sig)?);
            let ok = match lib {
                #[cfg(feature = "zkcrypto")]
                bls::Lib::Zkcrypto => zk::pairing_stages(pk, hm, sig, &mut mark),
                #[cfg(not(feature = "zkcrypto"))]
                bls::Lib::Zkcrypto => return Err(Error::Malformed),
                bls::Lib::Blst => {
                    let f = bl::miller(pk, hm, sig).ok_or(Error::Malformed)?;
                    mark("miller_loop_x2");
                    let ok = bl::final_is_one(&f);
                    mark("final_exponentiation");
                    ok
                }
            };
            Ok(vec![ok as u8])
        }
        Op::HashToG2 { lib, msg } => {
            let p = bls::hash_to_g2(*lib, msg);
            mark("hash_to_g2");
            Ok(p.to_vec())
        }
        Op::DecodeSignature { lib, sig } => {
            let s = bls::decode_signature(*lib, sig).ok_or(Error::BadSignature)?;
            mark("signature_decode");
            Ok(s.to_vec())
        }
        Op::SigningKey { committee, bits, witness, opts } => {
            let pk = bls::signing_key(opts.lib, committee, bits, witness, *opts)?;
            mark("signing_key");
            Ok(pk.to_vec())
        }
        Op::CommitteeRoot { committee } => {
            let r = ssz::sync_committee_root(committee);
            mark("committee_root");
            Ok(r.to_vec())
        }
        Op::FastAggregateVerify { committee, bits, witness, opts, msg, sig } => {
            let pk = bls::signing_key(opts.lib, committee, bits, witness, *opts)?;
            mark("signing_key");
            let hm = bls::hash_to_g2(opts.lib, msg);
            mark("hash_to_g2");
            let s = bls::decode_signature(opts.lib, sig).ok_or(Error::BadSignature)?;
            mark("signature_decode");
            let ok = bls::pairing_check(opts.lib, &pk, &hm, &s);
            mark("pairing");
            if ok { Ok(vec![1]) } else { Err(Error::BadSignature) }
        }
        Op::Update { cfg, store, update, committee, witness, opts } => {
            let s = lc::apply_update(cfg, store, update, committee, witness, *opts, &mut mark)?;
            Ok(borsh::to_vec(&s).unwrap())
        }
        Op::Prepare { cfg, store, update, committee, witness, opts } => {
            let p = lc::prepare(cfg, store, update, committee, witness, *opts, &mut mark)?;
            Ok(borsh::to_vec(&p).unwrap())
        }
        Op::Miller { pk, hm, sig } => {
            let f = bl::miller(arr::<96>(pk)?, arr::<192>(hm)?, arr::<192>(sig)?).ok_or(Error::Malformed)?;
            mark("miller_loop_x2");
            Ok(f.to_vec())
        }
        Op::FinalExp { f } => {
            let ok = bl::final_is_one(arr::<576>(f)?);
            mark("final_exponentiation");
            if ok { Ok(vec![1]) } else { Err(Error::BadSignature) }
        }
        Op::Bootstrap { root, header, committee, branch } => {
            let s = lc::bootstrap(root, header, committee, branch)?;
            mark("bootstrap");
            Ok(borsh::to_vec(&s).unwrap())
        }
        Op::StorageProof { state_root, proof } => {
            let v = mpt::verify_account_storage(state_root, proof)?;
            mark("storage_proof");
            Ok(v)
        }
        Op::ReceiptProof { receipts_root, proof } => {
            let v = mpt::verify_receipt_log(receipts_root, proof)?;
            mark("receipt_proof");
            Ok(v)
        }
    })();
    Report { ok, marks }
}
