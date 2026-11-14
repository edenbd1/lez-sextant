//! The v0.4 sextant_lc binary through `lee::V03State` (LEZ v0.4.0-rc3) on the
//! two public Ethereum testnets: Hoodi (Fulu) and Sepolia (Gloas), one
//! Sepolia instance across the Gloas fork, and the Sepolia checkpoint of a
//! Portage vault deposit. Each instance is initialised from its chain's
//! checkpoint, advanced through every update of its vectors with every step
//! under the cap, ends where the native verifier ends, and serves an
//! attestation against its last header.

use sextant_core::lc;
use sextant_core::statement::{Proof, Query};
use sextant_core::{Error, Store};
use sextant_executor_tests_v04::*;
use sextant_host::{hoodi, mainnet_steps, receipt_proof_from, sepolia, sepolia_gloas_fork, sepolia_portage, weth_proof_from, Mainnet};
use sextant_program_v04::*;

fn run(c: &mut Chain, m: &Mainnet, id: [u8; 32]) -> (Store, u64) {
    init(c, m, id).unwrap();
    let mut heaviest = 0;
    for (_, u, committee) in mainnet_steps(m) {
        let gas = advance(c, id, &u, &committee).unwrap();
        println!("{}: period {} update, Begin/Miller/Finish cycles {gas:?}", String::from_utf8_lossy(&id), lc::period(u.finalized.beacon.slot));
        assert!(gas.iter().all(|g| *g < GAS_CAP / 100 * 60), "{gas:?}");
        heaviest = heaviest.max(*gas.iter().max().unwrap());
    }
    let store = c.instance(&id).store;
    if let Some(native) = native_final(m) {
        assert_eq!(store, native, "the program ends where the native verifier ends");
    }
    (store, heaviest)
}

fn refused(r: Result<Outcome, String>) -> u32 {
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

#[test]
fn the_portage_deposit_checkpoint_initialises_on_v04() {
    // vectors/sepolia-portage: the finalized header of execution block
    // 12,092,950, the block of a Portage vault deposit on Sepolia.
    let m = sepolia_portage();
    let id = *b"sepolia/portage/instance/0000001";
    let mut c = Chain::new();
    c.now = lc::slot_time(&m.cfg, m.boot_header.beacon.slot) * 1000 + 600_000;
    init(&mut c, &m, id).unwrap();
    let s = c.instance(&id).store;
    assert_eq!(s.finalized_block_number, 12_092_950);
    let rec: sextant_core::statement::HeaderRecord = borsh::from_slice(&c.state_of(header_account(&LC, &id, s.finalized.slot))).unwrap();
    assert_eq!(rec.state_root, s.finalized_execution_state_root);
}
