# Sextant: trustless Ethereum state attestation for LEZ (RFP-021 prototype)

An Ethereum light client inside a LEZ v0.3 program, and the consumer check
against what it verified, measured on real Ethereum mainnet data.

- `core/`: `sextant-core`, the verification: SSZ and the light-client rules
  (`lc.rs`, `ssz.rs`), `FastAggregateVerify` over two BLS12-381 libraries
  (`bls.rs`, `bl.rs` for blst, `zk.rs` for zkcrypto), Merkle-Patricia proofs
  (`mpt.rs`), predicates and statement identifiers (`statement.rs`).
- `programs/sextant/`: `sextant_lc`, the LEZ v0.3 program (plan/apply on
  `lee_core` at v0.3.0, `db66590ab`): `Init`, `Begin`, `Miller`, `Finish`,
  `Attest`. The packed binary is `artifacts/programs/v0.3/sextant_lc.bin`
  (ImageID `a241fa02…`, a local toolchain build; the reproducible Docker
  build comes with the testnet deployment).
- `guest/`, `guest-stock/`: one benchmark guest, built twice: with RISC Zero's
  accelerated forks and without.
- `host/`: decodes the beacon-API and JSON-RPC vectors, cross-checks every
  verdict natively, and counts cycles in the RISC Zero executor.
- `executor-tests/`: the committed program binary through `lee::V03State`, the
  state machine the v0.3 sequencer applies, under the 10,000,000 gas cap.
- `vectors/mainnet/`: what the tests run on, fetched read-only from public
  endpoints on 2026-10-15: a `LightClientBootstrap` at slot 15,409,152, the
  `LightClientUpdate`s of sync-committee periods 1881 to 1883, a finality
  update in period 1884, and for its finalized block 26,197,200 an
  `eth_getProof` (WETH `balanceOf` of the Uniswap v3 USDC/WETH pool) and the
  block's receipts.

## Reproduce

Requires the RISC Zero toolchains (`rzup install`: rust and cpp, r0vm 3.0.5).

```console
scripts/build-guests.sh                       # the two benchmark guests -> artifacts/bench/
scripts/build-guests.sh lez                   # the program -> artifacts/programs/v0.3/sextant_lc.bin
cargo test --release --manifest-path host/Cargo.toml             # 17 tests, natively, on mainnet data
cargo test --release --manifest-path executor-tests/Cargo.toml   # 7 tests, the binary through lee::V03State
cargo run --release --manifest-path host/Cargo.toml --bin measure            # docs/raw/measure-*.txt
cargo run --release --manifest-path executor-tests/Cargo.toml --bin measure_lez  # docs/raw/measure-lez-*.txt
RISC0_DEV_MODE=0 SEGMENT_PO2=18 cargo run --release --manifest-path executor-tests/Cargo.toml --bin prove
python3 scripts/receipt_proof.py vectors/mainnet/receipts.json vectors/mainnet/block.json 2 /tmp/p.json
```

Results: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md). Choices and why:
[`docs/DECISIONS.md`](docs/DECISIONS.md).

## What this prototype is not yet

Not deployed on a LEZ testnet; no Logos core module, CLI or update daemon; no
reference consumer programs (the consumer check is the `Attest` instruction);
no weak-subjectivity staleness check, no transaction proofs (native ether
sender), no historical headers. These are the milestones of the proposal.

MIT OR Apache-2.0.
