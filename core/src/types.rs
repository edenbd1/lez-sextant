//! Wire types: the light-client containers of the consensus specs, in borsh,
//! as a submitter hands them to the program.

use borsh::{BorshDeserialize, BorshSerialize};

pub type Root = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct BeaconHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: Root,
    pub state_root: Root,
    pub body_root: Root,
}

/// `ExecutionPayloadHeader`, Deneb shape (unchanged in Electra and Fulu).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionHeader {
    pub parent_hash: Root,
    pub fee_recipient: [u8; 20],
    pub state_root: Root,
    pub receipts_root: Root,
    pub logs_bloom: Vec<u8>,
    pub prev_randao: Root,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    /// uint256, little-endian, as SSZ hashes it.
    pub base_fee_per_gas: Root,
    pub block_hash: Root,
    pub transactions_root: Root,
    pub withdrawals_root: Root,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
}

/// `LightClientHeader` (Capella and later).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct LcHeader {
    pub beacon: BeaconHeader,
    pub execution: ExecutionHeader,
    pub execution_branch: Vec<Root>,
}

#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct SyncCommittee {
    pub pubkeys: Vec<[u8; 48]>,
    pub aggregate: [u8; 48],
}

/// `LightClientUpdate` (a finality update is the same with no committee).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Update {
    pub attested: LcHeader,
    pub next_committee: Option<(SyncCommittee, Vec<Root>)>,
    pub finalized: LcHeader,
    pub finality_branch: Vec<Root>,
    /// `sync_committee_bits`, Bitvector[512], SSZ bit order.
    pub bits: [u8; 64],
    pub signature: [u8; 96],
    pub signature_slot: u64,
}

/// Uncompressed points the submitter supplies so the program does not take a
/// square root per key. Each is checked against the committed compressed
/// bytes (on the curve, same x, same sign of y); see `bls::decode_witnessed`.
#[derive(Clone, Debug, Default, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct KeyWitness {
    /// `(index in committee, 96-byte uncompressed point)`.
    pub points: Vec<(u16, Vec<u8>)>,
    /// The committee's aggregate key, uncompressed.
    pub aggregate: Vec<u8>,
}

/// What an instance fixes at initialisation and never changes (F.9).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct ChainConfig {
    /// EIP-155 chain id of the execution layer (1 mainnet, 11155111 Sepolia...).
    pub chain_id: u64,
    pub genesis_validators_root: Root,
    /// `(activation epoch, fork version)`, ascending.
    pub forks: Vec<(u64, [u8; 4])>,
    /// Minimum participating committee members, out of 512 (342 = two thirds).
    pub min_participants: u16,
    /// Beacon genesis, unix seconds (slot `s` starts at `genesis_time + 12 s`).
    pub genesis_time: u64,
    /// The weak-subjectivity bound, in seconds: a store whose finalized
    /// header is older than this may no longer be advanced (E7206); a fresh
    /// instance has to be initialised from a recent checkpoint.
    pub max_checkpoint_age: u64,
}

/// The tracked consensus state of one instance.
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct Store {
    pub finalized: BeaconHeader,
    pub finalized_execution_state_root: Root,
    pub finalized_receipts_root: Root,
    pub finalized_block_number: u64,
    pub current_committee: Root,
    pub next_committee: Option<Root>,
}
