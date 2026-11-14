//! Runs every vendored consensus-spec light-client vector against
//! sextant-core and prints the result per suite, fork and case.
//!
//! `cargo run --release --manifest-path spec-tests/Cargo.toml`

use sextant_spec_tests::{all, Outcome, RELEASE};

fn main() {
    let cases = all();
    println!("# consensus-specs {RELEASE} light_client vectors against sextant-core\n");
    println!("| suite | fork | case | result | compared |");
    println!("|---|---|---|---|---|");
    for c in &cases {
        let r = match &c.outcome {
            Outcome::Pass => "pass".to_string(),
            Outcome::PassScoped(why) => format!("pass, scoped: {why}"),
            Outcome::Fail(why) => format!("**FAIL**: {why}"),
        };
        println!("| {} | {} | {} | {r} | {} |", c.suite, c.fork, c.name, c.detail);
    }
    println!("\n| suite | fork | cases | pass | pass, scoped | fail |");
    println!("|---|---|---:|---:|---:|---:|");
    let mut keys: Vec<(String, String)> = cases.iter().map(|c| (c.suite.clone(), c.fork.clone())).collect();
    keys.dedup();
    for (s, f) in keys {
        let v: Vec<_> = cases.iter().filter(|c| c.suite == s && c.fork == f).collect();
        let n = |p: fn(&Outcome) -> bool| v.iter().filter(|c| p(&c.outcome)).count();
        println!(
            "| {s} | {f} | {} | {} | {} | {} |",
            v.len(),
            n(|o| matches!(o, Outcome::Pass)),
            n(|o| matches!(o, Outcome::PassScoped(_))),
            n(|o| matches!(o, Outcome::Fail(_)))
        );
    }
    if cases.iter().any(|c| matches!(c.outcome, Outcome::Fail(_))) {
        std::process::exit(1);
    }
}
