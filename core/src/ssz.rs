//! The SSZ hashing a light client needs: `hash_tree_root` of the handful of
//! containers it reads, and `is_valid_merkle_branch`. Written to the
//! consensus-specs definitions (phase0 `ssz/simple-serialize.md`, Altair
//! `light-client/sync-protocol.md`), nothing more general.

use crate::types::{BeaconHeader, ExecutionHeader, SyncCommittee};
use sha2::{Digest, Sha256};

pub type Root = [u8; 32];

#[inline]
pub fn hash2(a: &Root, b: &Root) -> Root {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Merkleize `leaves`, padded with zero chunks to `limit` (a power of two).
pub fn merkleize(leaves: &[Root], limit: usize) -> Root {
    assert!(limit.is_power_of_two() && leaves.len() <= limit);
    let mut layer: Vec<Root> = leaves.to_vec();
    let mut zero = [0u8; 32];
    let mut width = limit;
    while width > 1 {
        if layer.len() % 2 == 1 {
            layer.push(zero);
        }
        layer = layer.chunks(2).map(|p| hash2(&p[0], &p[1])).collect();
        zero = hash2(&zero, &zero);
        width /= 2;
    }
    layer.first().copied().unwrap_or(zero)
}

fn u64_chunk(v: u64) -> Root {
    let mut c = [0u8; 32];
    c[..8].copy_from_slice(&v.to_le_bytes());
    c
}

/// `hash_tree_root(Bytes48)`: two chunks, the second zero-padded.
pub fn pubkey_root(pk: &[u8; 48]) -> Root {
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    a.copy_from_slice(&pk[..32]);
    b[..16].copy_from_slice(&pk[32..]);
    hash2(&a, &b)
}

/// `hash_tree_root(BeaconBlockHeader)`: five fields, eight leaves.
pub fn beacon_header_root(h: &BeaconHeader) -> Root {
    merkleize(&[u64_chunk(h.slot), u64_chunk(h.proposer_index), h.parent_root, h.state_root, h.body_root], 8)
}

/// `hash_tree_root(SyncCommittee)`: `Vector[BLSPubkey, 512]` and the aggregate.
pub fn sync_committee_root(c: &SyncCommittee) -> Root {
    let leaves: Vec<Root> = c.pubkeys.iter().map(pubkey_root).collect();
    let keys = merkleize(&leaves, 512);
    hash2(&keys, &pubkey_root(&c.aggregate))
}

/// `hash_tree_root(ExecutionPayloadHeader)` for Deneb and later (Electra and
/// Fulu kept the Deneb shape): 17 fields, 32 leaves.
pub fn execution_header_root(e: &ExecutionHeader) -> Root {
    let mut fee = [0u8; 32];
    fee[..20].copy_from_slice(&e.fee_recipient);
    // logs_bloom: ByteVector[256], eight chunks.
    let bloom_leaves: Vec<Root> = e.logs_bloom.chunks(32).map(|c| c.try_into().unwrap()).collect();
    let bloom = merkleize(&bloom_leaves, 8);
    // extra_data: ByteList[32], one chunk, mixed in with its length.
    let mut extra = [0u8; 32];
    extra[..e.extra_data.len()].copy_from_slice(&e.extra_data);
    let extra = hash2(&merkleize(&[extra], 1), &u64_chunk(e.extra_data.len() as u64));
    merkleize(
        &[
            e.parent_hash,
            fee,
            e.state_root,
            e.receipts_root,
            bloom,
            e.prev_randao,
            u64_chunk(e.block_number),
            u64_chunk(e.gas_limit),
            u64_chunk(e.gas_used),
            u64_chunk(e.timestamp),
            extra,
            e.base_fee_per_gas,
            e.block_hash,
            e.transactions_root,
            e.withdrawals_root,
            u64_chunk(e.blob_gas_used),
            u64_chunk(e.excess_blob_gas),
        ],
        32,
    )
}

/// `is_valid_merkle_branch(leaf, branch, depth, index, root)`.
pub fn is_valid_merkle_branch(leaf: &Root, branch: &[Root], depth: usize, index: u64, root: &Root) -> bool {
    if branch.len() != depth {
        return false;
    }
    let mut v = *leaf;
    for (i, sib) in branch.iter().enumerate() {
        v = if (index >> i) & 1 == 1 { hash2(sib, &v) } else { hash2(&v, sib) };
    }
    &v == root
}

/// `compute_signing_root(object_root, domain)`.
pub fn signing_root(object_root: &Root, domain: &Root) -> Root {
    hash2(object_root, domain)
}

/// `compute_domain(DOMAIN_SYNC_COMMITTEE, fork_version, genesis_validators_root)`.
pub fn sync_committee_domain(fork_version: [u8; 4], genesis_validators_root: &Root) -> Root {
    let mut v = [0u8; 32];
    v[..4].copy_from_slice(&fork_version);
    let fork_data_root = hash2(&v, genesis_validators_root);
    let mut d = [0u8; 32];
    d[..4].copy_from_slice(&[7, 0, 0, 0]);
    d[4..].copy_from_slice(&fork_data_root[..28]);
    d
}
