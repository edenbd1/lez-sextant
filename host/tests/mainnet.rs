//! The verification core, natively, on real Ethereum mainnet data: a
//! bootstrap at slot 15,409,152, three sync-committee handoffs (periods 1881
//! to 1884) and a finality update, then the adversarial cases of the RFP's
//! Verification Security section, each refused with its typed code.

use sextant_core::bls::{self, KeyMode, Lib};
use sextant_core::lc::{self, AggMode, Opts};
use sextant_core::{ssz, Error};
use sextant_host::*;

const FAST: Opts = lc::FAST;

#[test]
fn the_real_chain_verifies_from_the_checkpoint() {
    let m = mainnet();
    let steps = mainnet_steps(&m);
    assert_eq!(steps.len(), 4);
    // Three handoffs: the store ends in period 1884 with the committee of 1884.
    let (last_store, last, signer) = steps.last().unwrap();
    let w = witness(signer, &last.bits, AggMode::Subtract);
    let s = lc::apply_update(&m.cfg, last_store, last, signer, &w, FAST, &mut |_| {}).unwrap();
    assert_eq!(lc::period(s.finalized.slot), 1884);
    assert_eq!(s.current_committee, ssz::sync_committee_root(&m.updates[2].next_committee.as_ref().unwrap().0));
}

#[test]
fn every_key_strategy_yields_the_same_key() {
    let m = mainnet();
    let (_, u, c) = &mainnet_steps(&m)[0];
    let mut keys = vec![];
    for lib in [Lib::Zkcrypto, Lib::Blst] {
        for keys_mode in [KeyMode::Checked, KeyMode::Unchecked, KeyMode::Witness] {
            for agg in [AggMode::Sum, AggMode::Subtract] {
                let w = witness(c, &u.bits, agg);
                keys.push(bls::signing_key(lib, c, &u.bits, &w, Opts { lib, keys: keys_mode, agg }).unwrap());
            }
        }
    }
    assert_eq!(keys.len(), 12);
    assert!(keys.windows(2).all(|p| p[0] == p[1]));
}

fn step(i: usize) -> (sextant_host::Mainnet, sextant_core::Store, sextant_core::Update, sextant_core::SyncCommittee) {
    let m = mainnet();
    let (s, u, c) = mainnet_steps(&m)[i].clone();
    (m, s, u, c)
}

fn verdict(m: &Mainnet, s: &sextant_core::Store, u: &sextant_core::Update, c: &sextant_core::SyncCommittee) -> Result<sextant_core::Store, Error> {
    let w = witness(c, &u.bits, AggMode::Subtract);
    lc::apply_update(&m.cfg, s, u, c, &w, FAST, &mut |_| {})
}

#[test]
fn a_fabricated_chain_is_refused() {
    // A self-consistent fabrication: a finalized header carrying an execution
    // state root of the attacker's choosing, its own valid execution branch,
    // an attested state root that commits to it through a valid finality
    // branch, and the real signature. Every Merkle check passes; the
    // signature does not, because the committee never signed this header.
    let (m, s, mut u, c) = step(1);
    u.finalized.execution.state_root = [0xEE; 32];
    let leaf = ssz::execution_header_root(&u.finalized.execution);
    let mut v = leaf;
    for (i, sib) in u.finalized.execution_branch.iter().enumerate() {
        v = if (lc::EXECUTION_INDEX >> i) & 1 == 1 { ssz::hash2(sib, &v) } else { ssz::hash2(&v, sib) };
    }
    u.finalized.beacon.body_root = v;
    let mut r = ssz::beacon_header_root(&u.finalized.beacon);
    for (i, sib) in u.finality_branch.iter().enumerate() {
        r = if (lc::FINALIZED_ROOT_INDEX >> i) & 1 == 1 { ssz::hash2(sib, &r) } else { ssz::hash2(&r, sib) };
    }
    u.attested.beacon.state_root = r;
    // The next-committee branch hangs off the same state root: rebuild it too
    // would need a second preimage, so drop the handoff and keep the rest.
    u.next_committee = None;
    assert!(lc::check_execution(&m.cfg, &u.finalized).is_ok());
    assert_eq!(verdict(&m, &s, &u, &c).unwrap_err(), Error::BadSignature);
}

#[test]
fn a_committee_never_handed_off_is_refused() {
    // Period 1883's update presented to the store of period 1881: its signers
    // were never handed off from the checkpoint.
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let (s0, _, _) = &steps[0];
    let (_, u2, c2) = &steps[2];
    assert_eq!(verdict(&m, s0, u2, c2).unwrap_err(), Error::HandoffNotVerified);
    // And a committee that is not the stored one, in the right period.
    let (s1, u1, _) = &steps[1];
    assert_eq!(verdict(&m, s1, u1, c2).unwrap_err(), Error::CommitteeMismatch);
}

#[test]
fn participation_below_two_thirds_is_refused() {
    let (m, s, mut u, c) = step(1);
    for i in 0..512 {
        if i >= 341 {
            u.bits[i / 8] &= !(1 << (i % 8));
        }
    }
    assert_eq!(verdict(&m, &s, &u, &c).unwrap_err(), Error::BelowParticipation);
}

#[test]
fn a_tampered_signature_or_bitfield_is_refused() {
    let (m, s, mut u, c) = step(1);
    u.bits[0] ^= 1; // one member claimed absent who signed, or the reverse
    assert_eq!(verdict(&m, &s, &u, &c).unwrap_err(), Error::BadSignature);
    let (m, s, mut u, c) = step(1);
    u.signature[5] ^= 1;
    assert_eq!(verdict(&m, &s, &u, &c).unwrap_err(), Error::BadSignature);
}

#[test]
fn a_header_that_is_not_finalized_is_refused() {
    let (m, s, mut u, c) = step(1);
    u.finalized.beacon.slot += 32; // a different, unfinalized header
    assert_eq!(verdict(&m, &s, &u, &c).unwrap_err(), Error::NotFinalized);
}

#[test]
fn a_tampered_execution_root_is_refused() {
    let (m, s, mut u, c) = step(1);
    u.finalized.execution.receipts_root[0] ^= 1;
    assert_eq!(verdict(&m, &s, &u, &c).unwrap_err(), Error::BadExecutionBranch);
}

#[test]
fn another_chain_is_refused() {
    // Same update, an instance configured for another chain (Sepolia's
    // genesis validators root): the signing domain differs.
    let (mut m, s, u, c) = step(1);
    m.cfg.genesis_validators_root = h(&serde_json::json!("0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"));
    assert_eq!(verdict(&m, &s, &u, &c).unwrap_err(), Error::BadSignature);
}

#[test]
fn an_applied_update_is_refused_as_a_duplicate() {
    let (m, s, u, c) = step(1);
    let s2 = verdict(&m, &s, &u, &c).unwrap();
    // Replayed after it landed (a competing operator's copy): refused, not
    // double-applied (R.8).
    assert_eq!(verdict(&m, &s2, &u, &c).unwrap_err(), Error::AlreadyApplied);
}

#[test]
fn the_checkpoint_must_match() {
    let m = mainnet();
    let mut root = m.checkpoint;
    root[0] ^= 1;
    assert_eq!(lc::bootstrap(&m.cfg, &root, &m.boot_header, &m.boot_committee, &m.boot_branch).unwrap_err(), Error::CheckpointMismatch);
    let mut c = m.boot_committee.clone();
    c.pubkeys.swap(0, 1);
    assert_eq!(lc::bootstrap(&m.cfg, &m.checkpoint, &m.boot_header, &c, &m.boot_branch).unwrap_err(), Error::BadCommitteeBranch);
}

#[test]
fn synthetic_committees_verify_at_any_participation() {
    for n in [342, 400, 512] {
        let s = synthetic(n);
        for lib in [Lib::Zkcrypto, Lib::Blst] {
            for agg in [AggMode::Sum, AggMode::Subtract] {
                let w = witness(&s.committee, &s.bits, agg);
                let pk = bls::signing_key(lib, &s.committee, &s.bits, &w, Opts { lib, keys: KeyMode::Witness, agg }).unwrap();
                let hm = bls::hash_to_g2(lib, &s.msg);
                let sig = bls::decode_signature(lib, &s.sig).unwrap();
                assert!(bls::pairing_check(lib, &pk, &hm, &sig), "n = {n}, {lib:?}, {agg:?}");
            }
        }
    }
}

#[test]
fn both_libraries_agree_on_every_real_update() {
    let m = mainnet();
    for (s, u, c) in mainnet_steps(&m) {
        let w = witness(&c, &u.bits, AggMode::Subtract);
        let zk = lc::apply_update(&m.cfg, &s, &u, &c, &w, Opts { lib: Lib::Zkcrypto, ..FAST }, &mut |_| {});
        let bl = lc::apply_update(&m.cfg, &s, &u, &c, &w, FAST, &mut |_| {});
        assert!(zk.is_ok());
        assert_eq!(zk, bl);
        // And the two-step pairing of the program gives the same verdict.
        let p = lc::prepare(&m.cfg, &s, &u, &c, &w, FAST, &mut |_| {}).unwrap();
        let f = sextant_core::bl::miller(p.pk.as_slice().try_into().unwrap(), p.hm.as_slice().try_into().unwrap(), p.sig.as_slice().try_into().unwrap()).unwrap();
        assert!(sextant_core::bl::final_is_one(&f));
        let mut bad = u.clone();
        bad.signature = m.updates[0].signature; // another header's signature
        if bad.signature != u.signature {
            let p = lc::prepare(&m.cfg, &s, &bad, &c, &w, FAST, &mut |_| {}).unwrap();
            let f = sextant_core::bl::miller(p.pk.as_slice().try_into().unwrap(), p.hm.as_slice().try_into().unwrap(), p.sig.as_slice().try_into().unwrap()).unwrap();
            assert!(!sextant_core::bl::final_is_one(&f));
        }
    }
}

#[test]
fn a_store_older_than_the_weak_subjectivity_bound_is_refused() {
    // F.10: every update is checked against the store's age on the chain's own
    // clock (signature slot vs finalized slot), with the typed code E7206.
    for i in 0..4 {
        let (mut m, s, u, c) = step(i);
        let gap = lc::slot_time(&m.cfg, u.signature_slot) - lc::slot_time(&m.cfg, s.finalized.slot);
        assert!(gap <= m.cfg.max_checkpoint_age, "the real chain is fresh at step {i}");
        m.cfg.max_checkpoint_age = gap;
        assert!(verdict(&m, &s, &u, &c).is_ok());
        m.cfg.max_checkpoint_age = gap - 1;
        assert_eq!(verdict(&m, &s, &u, &c).unwrap_err(), Error::CheckpointStale);
    }
}
