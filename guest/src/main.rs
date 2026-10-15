// The benchmark guest: decode one `Op`, run it through sextant-core, and
// journal the verdict with the cycle counter after every stage.
use risc0_zkvm::guest::env;
use std::io::Read;

fn main() {
    let mut buf = Vec::new();
    env::stdin().read_to_end(&mut buf).unwrap();
    let op: sextant_core::Op = borsh::from_slice(&buf).expect("an Op");
    let report = sextant_core::run(&op, &|| env::cycle_count());
    env::commit_slice(&borsh::to_vec(&report).unwrap());
}
