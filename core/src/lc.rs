//! The light-client rules: bootstrap an instance from a trusted checkpoint,
//! then advance it with finalized `LightClientUpdate`s, following the Altair
//! `sync-protocol.md` (finalized updates only, no optimistic head) with the
//! Electra generalized indices that mainnet uses since May 2025, and the
//! Gloas ones (EIP-7688, EIP-7732) from an instance's configured Gloas epoch:
//! Sepolia since 2026-10-06, Hoodi from 2026-10-26.

use crate::bls::{self, KeyMode, Lib};
use crate::ssz::{self, Root};
use crate::types::{ChainConfig, KeyWitness, LcHeader, Store, SyncCommittee, Update};
use crate::Error;

pub const SLOTS_PER_EPOCH: u64 = 32;
pub const SLOTS_PER_PERIOD: u64 = SLOTS_PER_EPOCH * 256;
pub const COMMITTEE_SIZE: usize = 512;

/// Electra generalized indices (`light-client/sync-protocol.md`, Electra).
pub const FINALIZED_ROOT_DEPTH: usize = 7;
pub const FINALIZED_ROOT_INDEX: u64 = 169 - 128;
pub const NEXT_COMMITTEE_DEPTH: usize = 6;
pub const NEXT_COMMITTEE_INDEX: u64 = 87 - 64;
pub const CURRENT_COMMITTEE_DEPTH: usize = 6;
pub const CURRENT_COMMITTEE_INDEX: u64 = 86 - 64;
/// `EXECUTION_PAYLOAD_GINDEX` (Capella): the payload header under body_root.
pub const EXECUTION_DEPTH: usize = 4;
pub const EXECUTION_INDEX: u64 = 25 - 16;

/// Gloas generalized indices (`gloas/light-client/sync-protocol.md`).
pub const FINALIZED_ROOT_GINDEX_GLOAS: u64 = 735;
pub const CURRENT_COMMITTEE_GINDEX_GLOAS: u64 = 2945;
pub const NEXT_COMMITTEE_GINDEX_GLOAS: u64 = 2946;
/// `signed_execution_payload_bid.message.parent_block_hash` under body_root.
pub const EXECUTION_BLOCK_HASH_GINDEX_GLOAS: u64 = 2856;

/// `(depth, index)` of a generalized index: `floorlog2(g)`, `g - 2^depth`.
pub const fn split(g: u64) -> (usize, u64) {
    let d = 63 - g.leading_zeros();
    (d as usize, g - (1 << d))
}

pub fn is_gloas(cfg: &ChainConfig, slot: u64) -> bool {
    slot / SLOTS_PER_EPOCH >= cfg.gloas_epoch
}

fn finalized_root_at(cfg: &ChainConfig, slot: u64) -> (usize, u64) {
    if is_gloas(cfg, slot) { split(FINALIZED_ROOT_GINDEX_GLOAS) } else { (FINALIZED_ROOT_DEPTH, FINALIZED_ROOT_INDEX) }
}
fn current_committee_at(cfg: &ChainConfig, slot: u64) -> (usize, u64) {
    if is_gloas(cfg, slot) { split(CURRENT_COMMITTEE_GINDEX_GLOAS) } else { (CURRENT_COMMITTEE_DEPTH, CURRENT_COMMITTEE_INDEX) }
}
fn next_committee_at(cfg: &ChainConfig, slot: u64) -> (usize, u64) {
    if is_gloas(cfg, slot) { split(NEXT_COMMITTEE_GINDEX_GLOAS) } else { (NEXT_COMMITTEE_DEPTH, NEXT_COMMITTEE_INDEX) }
}

pub fn period(slot: u64) -> u64 {
    slot / SLOTS_PER_PERIOD
}

pub fn fork_version(cfg: &ChainConfig, epoch: u64) -> [u8; 4] {
    let mut v = [0u8; 4];
    for (at, ver) in &cfg.forks {
        if epoch >= *at {
            v = *ver;
        }
    }
    v
}

/// How the signing key is assembled from the committee.
#[derive(Clone, Copy, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub enum AggMode {
    /// Decode every participating key and add them up (the spec's procedure).
    Sum,
    /// Start from the committee's own `aggregate_pubkey` (committed in the
    /// same SSZ root) and subtract the keys that did not sign. At mainnet
    /// participation (500+ of 512) this decodes a handful of keys, not 500.
    Subtract,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Opts {
    pub lib: Lib,
    pub keys: KeyMode,
    pub agg: AggMode,
}

/// The program's choice: blst, uncompressed-key witnesses, aggregate minus non-signers.
pub const FAST: Opts = Opts { lib: Lib::Blst, keys: KeyMode::Witness, agg: AggMode::Subtract };

/// `is_valid_light_client_header`: the execution commitment of `h` against
/// `h.beacon.body_root`, in the shape of `h`'s own fork.
pub fn check_execution(cfg: &ChainConfig, h: &LcHeader) -> Result<(), Error> {
    let ok = if is_gloas(cfg, h.beacon.slot) {
        let (d, i) = split(EXECUTION_BLOCK_HASH_GINDEX_GLOAS);
        ssz::is_valid_merkle_branch(&h.execution.block_hash, &h.execution_branch, d, i, &h.beacon.body_root)
    } else {
        if !h.execution_rlp.is_empty() {
            return Err(Error::Malformed);
        }
        let leaf = ssz::execution_header_root(&h.execution);
        ssz::is_valid_merkle_branch(&leaf, &h.execution_branch, EXECUTION_DEPTH, EXECUTION_INDEX, &h.beacon.body_root)
    };
    if ok {
        Ok(())
    } else {
        Err(Error::BadExecutionBranch)
    }
}

/// The execution roots a store records for a header: `(stateRoot,
/// receiptsRoot, number)`. Before Gloas they are in the proven payload
/// header; from Gloas, in the RLP block header that hashes to the proven
/// block hash.
pub fn execution_roots(cfg: &ChainConfig, h: &LcHeader) -> Result<(Root, Root, u64), Error> {
    check_execution(cfg, h)?;
    if is_gloas(cfg, h.beacon.slot) {
        crate::mpt::execution_header_roots(&h.execution.block_hash, &h.execution_rlp)
    } else {
        Ok((h.execution.state_root, h.execution.receipts_root, h.execution.block_number))
    }
}

/// Initialise a store from a trusted checkpoint (`LightClientBootstrap`): the
/// block root is the weak-subjectivity checkpoint, everything else is checked
/// against it.
pub fn bootstrap(cfg: &ChainConfig, trusted_block_root: &Root, header: &LcHeader, committee: &SyncCommittee, branch: &[Root]) -> Result<Store, Error> {
    if &ssz::beacon_header_root(&header.beacon) != trusted_block_root {
        return Err(Error::CheckpointMismatch);
    }
    let (state_root, receipts_root, number) = execution_roots(cfg, header)?;
    let root = ssz::sync_committee_root(committee);
    let (d, i) = current_committee_at(cfg, header.beacon.slot);
    if !ssz::is_valid_merkle_branch(&root, branch, d, i, &header.beacon.state_root) {
        return Err(Error::BadCommitteeBranch);
    }
    Ok(Store {
        finalized: header.beacon.clone(),
        finalized_execution_state_root: state_root,
        finalized_receipts_root: receipts_root,
        finalized_block_number: number,
        current_committee: root,
        next_committee: None,
    })
}

/// Everything an update needs except the pairing itself: the signing key,
/// the message point, the decoded signature, and the store the update leads
/// to if the pairing check passes.
#[derive(Clone, Debug, PartialEq, Eq, borsh::BorshSerialize, borsh::BorshDeserialize)]
pub struct Prepared {
    pub pk: Vec<u8>,
    pub hm: Vec<u8>,
    pub sig: Vec<u8>,
    pub next: Store,
}

/// Validate `u` against `store` and return the advanced store. `committee` is
/// the signing committee in full; it must hash to the root the store holds.
/// `mark(label)` is called after each stage, for cycle accounting.
pub fn apply_update(
    cfg: &ChainConfig,
    store: &Store,
    u: &Update,
    committee: &SyncCommittee,
    w: &KeyWitness,
    o: Opts,
    mark: &mut dyn FnMut(&'static str),
) -> Result<Store, Error> {
    let p = prepare(cfg, store, u, committee, w, o, mark)?;
    let ok = bls::pairing_check(o.lib, p.pk.as_slice().try_into().unwrap(), p.hm.as_slice().try_into().unwrap(), p.sig.as_slice().try_into().unwrap());
    mark("pairing");
    if ok {
        Ok(p.next)
    } else {
        Err(Error::BadSignature)
    }
}

/// Every check of an update but the pairing (see [`Prepared`]).
pub fn prepare(
    cfg: &ChainConfig,
    store: &Store,
    u: &Update,
    committee: &SyncCommittee,
    w: &KeyWitness,
    o: Opts,
    mark: &mut dyn FnMut(&'static str),
) -> Result<Prepared, Error> {
    // Ordering, period and participation (`validate_light_client_update`).
    let n = bls::participants(&u.bits);
    if n < cfg.min_participants as usize {
        return Err(Error::BelowParticipation);
    }
    if !(u.signature_slot > u.attested.beacon.slot && u.attested.beacon.slot >= u.finalized.beacon.slot) {
        return Err(Error::Malformed);
    }
    let store_period = period(store.finalized.slot);
    let sig_period = period(u.signature_slot);
    let expected = if sig_period == store_period {
        store.current_committee
    } else if sig_period == store_period + 1 {
        store.next_committee.ok_or(Error::HandoffNotVerified)?
    } else {
        return Err(Error::HandoffNotVerified);
    };
    let fin_period = period(u.finalized.beacon.slot);
    let att_period = period(u.attested.beacon.slot);
    let brings_next = u.next_committee.is_some() && store.next_committee.is_none() && att_period == store_period;
    if u.finalized.beacon.slot <= store.finalized.slot && !brings_next {
        return Err(Error::AlreadyApplied);
    }
    if fin_period == store_period + 1 && store.next_committee.is_none() {
        return Err(Error::HandoffNotVerified);
    }
    if fin_period > store_period + 1 {
        return Err(Error::HandoffNotVerified);
    }
    mark("checks");

    // The supplied committee is the one the store committed to.
    if ssz::sync_committee_root(committee) != expected {
        return Err(Error::CommitteeMismatch);
    }
    mark("committee_root");

    let pk = bls::signing_key(o.lib, committee, &u.bits, w, o)?;
    mark("signing_key");

    // Finality: the finalized header sits in the attested state.
    let (fin_state_root, fin_receipts_root, fin_number) = execution_roots(cfg, &u.finalized)?;
    let fin_root = ssz::beacon_header_root(&u.finalized.beacon);
    let (d, i) = finalized_root_at(cfg, u.attested.beacon.slot);
    if !ssz::is_valid_merkle_branch(&fin_root, &u.finality_branch, d, i, &u.attested.beacon.state_root) {
        return Err(Error::NotFinalized);
    }
    mark("finality_branch");

    // Handoff: the next committee sits in the attested state.
    let mut next_root = None;
    if let Some((next, branch)) = &u.next_committee {
        let r = ssz::sync_committee_root(next);
        let (d, i) = next_committee_at(cfg, u.attested.beacon.slot);
        if !ssz::is_valid_merkle_branch(&r, branch, d, i, &u.attested.beacon.state_root) {
            return Err(Error::BadCommitteeBranch);
        }
        if att_period == store_period {
            if let Some(known) = store.next_committee {
                if known != r {
                    return Err(Error::HandoffNotVerified);
                }
            }
        }
        next_root = Some(r);
    }
    mark("next_committee");

    let epoch = u.signature_slot.max(1).saturating_sub(1) / SLOTS_PER_EPOCH;
    let domain = ssz::sync_committee_domain(fork_version(cfg, epoch), &cfg.genesis_validators_root);
    let msg = ssz::signing_root(&ssz::beacon_header_root(&u.attested.beacon), &domain);
    mark("signing_root");

    let hm = bls::hash_to_g2(o.lib, &msg);
    mark("hash_to_g2");
    let sig = bls::decode_signature(o.lib, &u.signature).ok_or(Error::BadSignature)?;
    mark("signature_decode");

    // `apply_light_client_update`, finalized updates only.
    let mut s = store.clone();
    if store.next_committee.is_none() {
        if fin_period != store_period {
            return Err(Error::HandoffNotVerified);
        }
        s.next_committee = next_root;
    } else if fin_period == store_period + 1 {
        s.current_committee = store.next_committee.unwrap();
        s.next_committee = if att_period == fin_period { next_root } else { None };
    }
    if u.finalized.beacon.slot > store.finalized.slot {
        s.finalized = u.finalized.beacon.clone();
        s.finalized_execution_state_root = fin_state_root;
        s.finalized_receipts_root = fin_receipts_root;
        s.finalized_block_number = fin_number;
    }
    mark("next_store");
    Ok(Prepared { pk: pk.to_vec(), hm: hm.to_vec(), sig: sig.to_vec(), next: s })
}
