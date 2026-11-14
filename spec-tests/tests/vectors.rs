//! No vendored consensus-spec light-client vector fails against sextant-core,
//! and the harness does fail when the vectors are corrupted.

use sextant_spec_tests::{single_merkle_proof, single_merkle_proof_with, sync, sync_with, Case, Outcome};

fn fails(cases: &[Case]) -> Vec<&Case> {
    cases.iter().filter(|c| matches!(c.outcome, Outcome::Fail(_))).collect()
}

#[test]
fn single_merkle_proof_electra_fulu_gloas() {
    // Four proofs per fork: the execution commitment, the finalized root, both committees.
    let cases = single_merkle_proof();
    assert_eq!(cases.len(), 12, "every vendored case ran");
    assert!(fails(&cases).is_empty(), "{:#?}", fails(&cases));
}

#[test]
fn sync_electra_fulu_gloas() {
    let cases = sync();
    assert_eq!(cases.len(), 15, "every vendored case ran");
    assert!(fails(&cases).is_empty(), "{:#?}", fails(&cases));
    // supply_sync_committee_from_past_update only teaches the store its next
    // committee; the finalized header the spec checks does not move. That
    // sextant took the committee is checked here instead.
    for c in cases.iter().filter(|c| c.name == "supply_sync_committee_from_past_update") {
        assert!(c.detail.contains(", 1 updates applied, 0 refused"), "{c:?}");
    }
}

#[test]
fn a_wrong_object_root_fails_every_proof() {
    assert_eq!(fails(&single_merkle_proof_with(true)).len(), 12);
}

#[test]
fn a_corrupted_signature_fails_every_case_in_which_the_spec_advances() {
    let cases = sync_with(|u| u.signature[95] ^= 1);
    let failed: Vec<_> = fails(&cases).iter().map(|c| format!("{}/{}", c.fork, c.name)).collect();
    // gloas_store_with_legacy_data (Electra, Fulu) and
    // supply_sync_committee_from_past_update (all three) never move the
    // spec's finalized header: ten of fifteen fail.
    assert_eq!(failed.len(), 10, "{failed:?}");
    assert!(failed.iter().all(|c| !c.ends_with("gloas_store_with_legacy_data") && !c.ends_with("supply_sync_committee_from_past_update")));
    for c in cases.iter().filter(|c| c.name == "supply_sync_committee_from_past_update") {
        assert!(c.detail.contains(", 0 updates applied, 1 refused (1 BadSignature)"), "{c:?}");
    }
}

#[test]
fn a_finalized_header_moved_off_its_branch_fails_too() {
    let cases = sync_with(|u| u.finalized.beacon.proposer_index ^= 1);
    assert_eq!(fails(&cases).len(), 10);
    for c in cases.iter().filter(|c| c.name == "supply_sync_committee_from_past_update") {
        assert!(c.detail.contains("(1 NotFinalized)"), "{c:?}");
    }
}
