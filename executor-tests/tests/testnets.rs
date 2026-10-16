//! The committed sextant_lc binary through `lee::V03State` on the two public
//! Ethereum testnets: Hoodi (Fulu) and Sepolia (Gloas since epoch 353,024),
//! and one Sepolia instance across the Gloas fork. Each instance is
//! initialised from its chain's checkpoint, advanced through every update of
//! its vectors with every step under the cap, ends where the native verifier
//! ends, and serves an attestation against its last header.

use sextant_core::lc;
use sextant_core::statement::{Proof, Query};
use sextant_core::{Error, Store};
use sextant_executor_tests::*;
use sextant_host::{hoodi, mainnet_steps, receipt_proof_from, sepolia, sepolia_gloas_fork, weth_proof_from, Mainnet};
use sextant_program::*;

/// Init and every update of `m` through the binary; returns the final store
/// and the heaviest step's gas.
fn run(c: &mut Chain, m: &Mainnet, id: [u8; 32]) -> (Store, u64) {
    init(c, m, id).unwrap();
    let mut heaviest = 0;
    for (_, u, committee) in mainnet_steps(m) {
        let gas = advance(c, id, &u, &committee).unwrap();
        println!("{}: period {} update, Begin/Miller/Finish gas {gas:?}", String::from_utf8_lossy(&id), lc::period(u.finalized.beacon.slot));
        assert!(gas.iter().all(|g| *g < GAS_CAP / 100 * 60), "{gas:?}");
        heaviest = heaviest.max(*gas.iter().max().unwrap());
    }
    let store = c.instance(&id).store;
    let native = mainnet_steps(m).last().map(|(s, u, k)| {
        let w = sextant_host::witness(k, &u.bits, lc::AggMode::Subtract);
        lc::apply_update(&m.cfg, s, u, k, &w, lc::FAST, &mut |_| {}).unwrap()
    });
    assert_eq!(Some(store.clone()), native, "the program ends where the native verifier ends");
    (store, heaviest)
}

fn attest(c: &mut Chain, id: [u8; 32], slot: u64, q: Query) -> Result<u64, String> {
    c.send(&Instruction::Attest { instance_id: id, slot, query: q }, vec![header_account(&LC, &id, slot)])
}

fn refused(r: Result<u64, String>) -> u32 {
    let e = r.expect_err("the transaction must be refused");
    refusal(&e).unwrap_or_else(|| panic!("no typed refusal in: {e}"))
}

#[test]
fn hoodi_runs_through_the_binary_and_attests() {
    let m = hoodi();
    let id = *b"hoodi/test/instance/000000000001";
    let mut c = Chain::new();
    let (s, _) = run(&mut c, &m, id);
    assert_eq!(lc::period(s.finalized.slot), 508);
    let q = |chain_id| Query { chain_id, proof: Proof::Log(receipt_proof_from("vectors/hoodi/receipt-proof-tx2.json", 2)), predicates: vec![] };
    attest(&mut c, id, s.finalized.slot, q(560_048)).unwrap();
    // A Hoodi record is not a mainnet statement.
    assert_eq!(refused(attest(&mut c, id, s.finalized.slot, q(1))), E_BASE + Error::ChainMismatch as u32);
}

#[test]
fn sepolia_gloas_runs_through_the_binary_and_attests() {
    let m = sepolia();
    assert!(lc::is_gloas(&m.cfg, m.boot_header.beacon.slot));
    let id = *b"sepolia/test/instance/0000000001";
    let mut c = Chain::new();
    let (s, _) = run(&mut c, &m, id);
    assert_eq!(lc::period(s.finalized.slot), 1388);
    let storage = |chain_id| Query { chain_id, proof: Proof::Storage(weth_proof_from("vectors/sepolia/getproof-weth.json")), predicates: vec![] };
    attest(&mut c, id, s.finalized.slot, storage(11_155_111)).unwrap();
    let log = Query { chain_id: 11_155_111, proof: Proof::Log(receipt_proof_from("vectors/sepolia/receipt-proof-tx2.json", 2)), predicates: vec![] };
    attest(&mut c, id, s.finalized.slot, log).unwrap();
    assert_eq!(refused(attest(&mut c, id, s.finalized.slot, storage(1))), E_BASE + Error::ChainMismatch as u32);
}

#[test]
fn one_sepolia_instance_crosses_the_gloas_fork_through_the_binary() {
    let m = sepolia_gloas_fork();
    assert!(!lc::is_gloas(&m.cfg, m.boot_header.beacon.slot), "a Fulu checkpoint");
    let id = *b"sepolia/gloas/fork/instance/0001";
    let mut c = Chain::new();
    let (s, _) = run(&mut c, &m, id);
    assert!(lc::is_gloas(&m.cfg, s.finalized.slot), "a Gloas finalized header");
}
