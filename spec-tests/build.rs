//! Writes `$OUT_DIR/minimal.rs`: sextant-core's source with the consensus
//! minimal preset in place of mainnet's. Every substitution must match the
//! number of times listed, or the build fails: a change to the core that
//! moves a preset constant cannot silently leave this copy on mainnet values.

use std::{env, fs, path::Path};

const CORE: &str = "../core/src";
const MODULES: &[&str] = &["bl", "bls", "lc", "mpt", "ssz", "statement", "types"];

/// `(file, from, to, expected occurrences)`.
const PRESET: &[(&str, &str, &str, usize)] = &[
    ("lc", "pub const SLOTS_PER_EPOCH: u64 = 32;", "pub const SLOTS_PER_EPOCH: u64 = 8;", 1),
    ("lc", "SLOTS_PER_EPOCH * 256;", "SLOTS_PER_EPOCH * 8;", 1),
    ("lc", "pub const COMMITTEE_SIZE: usize = 512;", "pub const COMMITTEE_SIZE: usize = 32;", 1),
    ("lc", "pub const SECONDS_PER_SLOT: u64 = 12;", "pub const SECONDS_PER_SLOT: u64 = 6;", 1),
    ("ssz", "merkleize(&leaves, 512)", "merkleize(&leaves, 32)", 1),
    // Bitvector[SYNC_COMMITTEE_SIZE]: 64 bytes on mainnet, 4 on minimal.
    ("bls", "[u8; 64]", "[u8; 4]", 3),
    ("types", "[u8; 64]", "[u8; 4]", 1),
    ("lib", "[u8; 64]", "[u8; 4]", 2),
    // The one step that is not a preset: from Gloas the store takes its
    // execution roots from the RLP block header that hashes to the proven
    // block hash. The spec's vectors carry no RLP (the light-client protocol
    // proves the hash only), so this copy records the hash and zero roots.
    // The real binding is tested on Sepolia's Gloas vectors in host/tests.
    (
        "lc",
        "crate::mpt::execution_header_roots(&h.execution.block_hash, &h.execution_rlp)",
        "Ok((h.execution.block_hash, [0u8; 32], 0))",
        1,
    ),
];

fn read(m: &str) -> String {
    let p = format!("{CORE}/{m}.rs");
    println!("cargo:rerun-if-changed={p}");
    fs::read_to_string(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn apply(m: &str, mut src: String) -> String {
    for (file, from, to, n) in PRESET {
        if *file == m {
            let got = src.matches(from).count();
            assert_eq!(got, *n, "{m}.rs: expected {n} x `{from}`, found {got}");
            src = src.replace(from, to);
        }
    }
    // Inner doc comments are not allowed in an included file.
    let src: String = src.lines().filter(|l| !l.trim_start().starts_with("//!")).map(|l| format!("{l}\n")).collect();
    src.replace("crate::", "crate::minimal::")
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let mut lib = apply("lib", read("lib"));
    for m in MODULES {
        let body = apply(m, read(m));
        let decl = format!("pub mod {m};");
        assert_eq!(lib.matches(&decl).count(), 1, "lib.rs declares `{decl}` once");
        lib = lib.replace(&decl, &format!("pub mod {m} {{\n{body}\n}}"));
    }
    // The zkcrypto backend is not part of this copy (its feature is off).
    assert_eq!(lib.matches("pub mod zk;").count(), 1);
    lib = lib.replace("pub mod zk;", "pub mod zk {}");
    let out = Path::new(&env::var("OUT_DIR").unwrap()).join("minimal.rs");
    fs::write(out, lib).unwrap();
}
