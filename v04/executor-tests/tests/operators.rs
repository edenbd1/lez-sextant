//! Update operators in contention (docs/V04.md, "Operators in contention"):
//! several submitters racing on one update's `Begin`, `Miller` and `Finish`,
//! on rc3's state machine with the committed binary.
//!
//! The job binds the update to the store it starts from: its id is
//! `sha256(digest(instance) ‖ digest(update))` and its content is computed by
//! the instance from its own state, so every operator who starts the same
//! update from the same store reaches the same job, anyone can continue
//! anyone's job, and nobody can put anything else at that address. A losing
//! racer's transaction reverts with a code that says the step is done; the
//! instance moves once.

use sextant_core::lc::{self, AggMode};
use sextant_core::{Error, SyncCommittee, Update};
use sextant_executor_tests_v04::*;
use sextant_host::{mainnet, mainnet_steps, witness};
use sextant_program_v04::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    Begin,
    Miller,
    Finish,
}

/// What a submission came to: applied, a typed refusal, or not admitted (the
/// job account no longer exists, so the transaction never reaches the program).
fn verdict<T>(r: &Result<T, String>) -> String {
    match r {
        Ok(_) => "applied".into(),
        Err(e) => refusal(e).map(|c| format!("E{c}")).unwrap_or_else(|| "not admitted".into()),
    }
}

fn submit(c: &mut Chain, step: Step, current: &Instance, u: &Update, k: &SyncCommittee) -> (String, u64) {
    let jid = job_id(current, u);
    let next_slot = lc::apply_update(&current.cfg, &current.store, u, k, &witness(k, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {})
        .map(|s| s.finalized.slot)
        .unwrap_or(current.store.finalized.slot);
    let r = match step {
        Step::Begin => begin(c, ID, current, u, k).map(|(o, _)| o),
        Step::Miller => miller(c, ID, jid),
        Step::Finish => finish(c, ID, jid, next_slot),
    };
    let cycles = c.log.last().map(|l| l.1).unwrap_or(0);
    (verdict(&r), cycles)
}

#[test]
fn three_operators_submitting_every_step_land_the_update_once() {
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, k) = mainnet_steps(&m)[0].clone();
    let current = c.instance(&ID);
    let jid = job_id(&current, &u);
    let mut table = vec![];
    let mut wasted = 0u64;
    for step in [Step::Begin, Step::Miller, Step::Finish] {
        for op in ["A", "B", "C"] {
            let before_job = c.job(&ID, &jid);
            let (v, cycles) = submit(&mut c, step, &current, &u, &k);
            println!("operator {op} {step:?}: {v} ({cycles} cycles)");
            table.push((op, step, v.clone()));
            let first = op == "A";
            match (step, first) {
                (_, true) => assert_eq!(v, "applied", "{op} {step:?}"),
                // The same job from the same store: Open finds it already there, a no-op.
                (Step::Begin, false) => {
                    assert_eq!(v, "applied");
                    assert_eq!(c.job(&ID, &jid), before_job, "the second Begin changes nothing");
                    wasted += cycles;
                }
                (Step::Miller, false) => {
                    assert_eq!(v, format!("E{E_JOB_STEP}"));
                    wasted += cycles;
                }
                (Step::Finish, false) => {
                    assert!(v == format!("E{E_NO_JOB}") || v == "not admitted", "{v}");
                    wasted += cycles;
                }
            }
        }
    }
    let after = c.instance(&ID);
    assert_eq!(Some(&after.store), lc::apply_update(&m.cfg, &current.store, &u, &k, &witness(&k, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).ok().as_ref());
    // A latecomer: against the old store (E7293), rebuilt against the new one (E7210).
    assert_eq!(submit(&mut c, Step::Begin, &current, &u, &k).0, format!("E{E_STALE}"));
    assert_eq!(submit(&mut c, Step::Begin, &after, &u, &k).0, format!("E{}", E_BASE + Error::AlreadyApplied as u32));
    assert_eq!(c.instance(&ID), after, "the instance moved once");
    println!("cycles spent by the losing submissions: {wasted}");
}

#[test]
fn operators_following_the_deferral_policy_finish_each_others_job_with_no_refusal() {
    // The policy: read the chain before each submission; if the instance moved
    // off the store the update was built against, stop; if the job exists,
    // send its next step; otherwise Begin. Three operators taking turns
    // complete one update in exactly three applied transactions.
    let m = mainnet();
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    for (_, u, k) in mainnet_steps(&m) {
        let built_against = c.instance(&ID);
        let jid = job_id(&built_against, &u);
        let mut applied = vec![];
        for op in ["A", "B", "C", "A", "B", "C"] {
            if c.instance(&ID) != built_against {
                break; // landed: nothing to do
            }
            let step = match c.job(&ID, &jid) {
                None => Step::Begin,
                Some(j) if j.f.is_none() => Step::Miller,
                Some(_) => Step::Finish,
            };
            let (v, _) = submit(&mut c, step, &built_against, &u, &k);
            assert_eq!(v, "applied", "{op} {step:?} under the policy");
            applied.push((op, step));
        }
        assert_eq!(applied, vec![("A", Step::Begin), ("B", Step::Miller), ("C", Step::Finish)]);
    }
    assert_eq!(Some(c.instance(&ID).store), native_final(&m));
}

#[test]
fn a_griefer_can_neither_block_nor_poison_an_honest_job() {
    let m = mainnet();
    let steps = mainnet_steps(&m);
    let mut c = Chain::new();
    init(&mut c, &m, ID).unwrap();
    let (_, u, k) = steps[0].clone();
    let current = c.instance(&ID);
    let honest = job_id(&current, &u);
    // 1. A forged update (another header's signature) from the same store: it
    //    passes Begin and Miller (the pairing is Finish's) at another job id.
    let mut forged = u.clone();
    forged.signature = steps[1].1.signature;
    let griefer = job_id(&current, &forged);
    assert_ne!(griefer, honest);
    assert_eq!(submit(&mut c, Step::Begin, &current, &forged, &k).0, "applied");
    assert_eq!(submit(&mut c, Step::Miller, &current, &forged, &k).0, "applied");
    // 2. A Begin claiming a store the instance does not hold.
    let mut other = current.clone();
    other.store.finalized.slot += 1;
    assert_eq!(submit(&mut c, Step::Begin, &other, &u, &k).0, format!("E{E_STALE}"));
    // 3. Writing the honest job's address directly is not a message the program accepts.
    let e = c.send("Open", lc(job_account(&LC, &ID, &honest)), &[], &[(LC, job_seed(&ID, &honest))], &Internal::Open { job_id: honest, job: c.job(&ID, &griefer).unwrap() });
    assert!(e.is_err());
    // 4. The honest operator opens its job; the griefer front-runs its Miller.
    assert_eq!(submit(&mut c, Step::Begin, &current, &u, &k).0, "applied");
    assert_eq!(submit(&mut c, Step::Miller, &current, &u, &k).0, "applied"); // the griefer's
    assert_eq!(submit(&mut c, Step::Miller, &current, &u, &k).0, format!("E{E_JOB_STEP}")); // the honest one's: done already
    // The honest operator finishes; the front-run only did its work for it.
    assert_eq!(submit(&mut c, Step::Finish, &current, &u, &k).0, "applied");
    let after = c.instance(&ID);
    // 5. The forged job's Finish fails the pairing.
    assert_eq!(submit(&mut c, Step::Finish, &current, &forged, &k).0, format!("E{}", E_BASE + Error::BadSignature as u32));
    assert_eq!(c.instance(&ID), after);
}

#[test]
fn four_operators_in_random_interleavings_land_each_update_once() {
    // Four operators, each submitting Begin, Miller, Finish in order without
    // reading the chain, scheduled by a seeded generator. Whatever the order,
    // exactly one Miller and one Finish apply, every other submission reverts
    // with a code meaning "already done" or is not admitted, and the instance
    // ends at the native verifier's store.
    let m = mainnet();
    let (_, u, k) = mainnet_steps(&m)[0].clone();
    let want = {
        let s = lc::bootstrap(&m.cfg, &m.checkpoint, &m.boot_header, &m.boot_committee, &m.boot_branch).unwrap();
        lc::apply_update(&m.cfg, &s, &u, &k, &witness(&k, &u.bits, AggMode::Subtract), lc::FAST, &mut |_| {}).unwrap()
    };
    for seed in [1u64, 7, 2026] {
        let mut c = Chain::new();
        init(&mut c, &m, ID).unwrap();
        let current = c.instance(&ID);
        let mut next = [0usize; 4];
        let mut rng = seed;
        let mut tally: std::collections::BTreeMap<(String, String), u32> = Default::default();
        while next.iter().any(|n| *n < 3) {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let op = (rng >> 33) as usize % 4;
            if next[op] == 3 {
                continue;
            }
            let step = [Step::Begin, Step::Miller, Step::Finish][next[op]];
            next[op] += 1;
            let (v, _) = submit(&mut c, step, &current, &u, &k);
            let ok = match step {
                Step::Begin => v == "applied" || v == format!("E{E_STALE}") || v == format!("E{E_EXISTS}"),
                Step::Miller => v == "applied" || v == format!("E{E_JOB_STEP}") || v == format!("E{E_NO_JOB}") || v == "not admitted",
                Step::Finish => v == "applied" || v == format!("E{E_JOB_STEP}") || v == format!("E{E_NO_JOB}") || v == "not admitted",
            };
            assert!(ok, "seed {seed}: operator {op} {step:?}: {v}");
            *tally.entry((format!("{step:?}"), v)).or_default() += 1;
        }
        println!("seed {seed}: {tally:?}");
        let applied = |s: &str| tally.get(&(s.to_string(), "applied".to_string())).copied().unwrap_or(0);
        // The first Miller to run applies, and the first Finish (it follows its
        // operator's Miller, so that one): exactly one of each.
        assert_eq!((applied("Miller"), applied("Finish")), (1, 1), "seed {seed}");
        assert_eq!(c.instance(&ID).store, want, "seed {seed}");
    }
}
