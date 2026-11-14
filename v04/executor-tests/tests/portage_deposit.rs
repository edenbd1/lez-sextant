//! A reference consumer statement on v0.4: a **native ETH deposit** into
//! Portage's WrapVault on Sepolia, attested by sextant_lc against the
//! finalized header that contains it.
//!
//! vectors/sepolia-portage: the Sepolia checkpoint finalized after the vault's
//! two deposits (slot 11,536,448, execution block 12,092,950). Transaction 63
//! of that block (0x2508a663…) is the deposit of index 1: its receipt's second
//! log is the vault's
//! `Deposit(uint256 indexed index, bytes32 leaf, bytes32 commitment, address indexed token, uint256 amount, bytes32 root)`
//! with `token = address(0)` (native ETH) and `amount = 0.001 ETH`. The proof
//! of that receipt (`block-12092950/receipt-proof-tx63.json`) is built offline
//! from the block's receipts, whose trie rebuilds the header's receipts root.
//!
//! The statement a consumer sends (`Attest`, variant 0, so any program can
//! encode it): the log is the vault's, its topic is `Deposit`, its index is 1,
//! the token is native ETH, the amount is 10^15 wei, and the vault root it
//! committed. Portage's wrap_bridge consumes the vault's `knownRoot` storage
//! slot instead (edenbd1/lez-portage `v0.4-spike`); this is the log-shaped
//! statement over the same deposit.

use sextant_core::lc;
use sextant_core::statement::{Cmp, Field, Predicate, Proof, Query};
use sextant_core::Error;
use sextant_executor_tests_v04::*;
use sextant_host::{receipt_proof_from, sepolia_portage};
use sextant_program_v04::*;

const ID: [u8; 32] = *b"sepolia/portage/deposit/00000001";
const SEPOLIA: u64 = 11_155_111;
const PROOF: &str = "vectors/sepolia-portage/block-12092950/receipt-proof-tx63.json";

fn word(hex: &str) -> [u8; 32] {
    sextant_host::h::<32>(&serde_json::json!(hex))
}

fn addr(hex: &str) -> [u8; 32] {
    let a = sextant_host::h::<20>(&serde_json::json!(hex));
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(&a);
    w
}

fn eq(field: Field, value: [u8; 32]) -> Predicate {
    Predicate { field, cmp: Cmp::Eq, value }
}

/// The vault's `Deposit` log of index 1: native ETH, 0.001 ETH.
fn deposit(log_index: u32, predicates: Vec<Predicate>) -> Query {
    let mut p = receipt_proof_from(PROOF, 63);
    p.log_index = log_index;
    Query { chain_id: SEPOLIA, proof: Proof::Log(p), predicates }
}

fn statement() -> Vec<Predicate> {
    let mut amount = [0u8; 32];
    amount[24..].copy_from_slice(&1_000_000_000_000_000u64.to_be_bytes());
    let mut index = [0u8; 32];
    index[31] = 1;
    vec![
        eq(Field::LogAddress, addr("0x4ae65712a472e11842a2e1fe61c7a52da99c8f7a")),
        // keccak256("Deposit(uint256,bytes32,bytes32,address,uint256,bytes32)")
        eq(Field::LogTopic(0), word("0x682b302394eb6512f331fec198dc22b15dfcdc2232cd41a97b8e19278f419f11")),
        eq(Field::LogTopic(1), index),
        eq(Field::LogTopic(2), [0; 32]), // token: address(0), native ETH
        eq(Field::LogDataWord(2), amount),
        // the vault root after this deposit
        eq(Field::LogDataWord(3), word("0x0f783dbd56aa5c54bbf04ee3fb09590a3e92812fff29466175fcaecea880dc77")),
    ]
}

fn setup() -> (Chain, u64) {
    let m = sepolia_portage();
    let mut c = Chain::new();
    c.now = lc::slot_time(&m.cfg, m.boot_header.beacon.slot) * 1000 + 600_000;
    init(&mut c, &m, ID).unwrap();
    let s = c.instance(&ID).store;
    assert_eq!(s.finalized_block_number, 12_092_950);
    (c, s.finalized.slot)
}

#[test]
fn a_native_eth_deposit_into_the_vault_is_attested() {
    let (mut c, slot) = setup();
    let o = attest(&mut c, ID, slot, deposit(1, statement())).expect("the deposit is attested");
    println!("Attest (vault Deposit log, 6 predicates): {} cycles", o.cycles);
    assert!(o.cycles < GAS_CAP / 10);
}

#[test]
fn a_deposit_statement_that_does_not_hold_is_refused() {
    let (mut c, slot) = setup();
    let pf = E_BASE + Error::PredicateFalse as u32;
    // Another amount.
    let mut s = statement();
    s[4].value[31] ^= 1;
    assert_eq!(refusal(&attest(&mut c, ID, slot, deposit(1, s)).unwrap_err()), Some(pf));
    // An ERC-20 token instead of native ETH.
    let mut s = statement();
    s[3].value[31] = 1;
    assert_eq!(refusal(&attest(&mut c, ID, slot, deposit(1, s)).unwrap_err()), Some(pf));
    // The receipt's first log (the native-ETH system Transfer of 0xff…fe) is not the vault's.
    assert_eq!(refusal(&attest(&mut c, ID, slot, deposit(0, statement())).unwrap_err()), Some(pf));
    // The same statement as a mainnet one.
    let mut q = deposit(1, statement());
    q.chain_id = 1;
    assert_eq!(refusal(&attest(&mut c, ID, slot, q).unwrap_err()), Some(E_BASE + Error::ChainMismatch as u32));
    // A forged receipt node.
    let mut q = deposit(1, statement());
    if let Proof::Log(p) = &mut q.proof {
        let last = p.proof.len() - 1;
        let n = p.proof[last].len() - 1;
        p.proof[last][n] ^= 1;
    }
    assert_eq!(refusal(&attest(&mut c, ID, slot, q).unwrap_err()), Some(E_BASE + Error::BadInclusion as u32));
}
