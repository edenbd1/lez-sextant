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
  (on this branch, `v2`: ImageID
  `ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928`,
  651,932 bytes, sha256 `58a600a4…`, with the weak-subjectivity check `E7206`
  and Gloas light-client headers): RISC Zero's pinned Docker builder
  (`r0.1.91.1`), byte-for-byte reproducible, checked in CI. The program on the
  public testnet as program `Ebe8rifvjyvwWUXnk7bsKeTwuyCAFSRMFuPMVHE8CbUB`
  ([`docs/ONCHAIN.md`](docs/ONCHAIN.md#the-v2-testnet-run)); `main`'s binary,
  ImageID `fa229edd…`, is the earlier program `A89TcYmW…`.
- `guest/`, `guest-stock/`: one benchmark guest, built twice: with RISC Zero's
  accelerated forks and without.
- `host/`: decodes the beacon-API and JSON-RPC vectors, cross-checks every
  verdict natively, and counts cycles in the RISC Zero executor.
- `programs/erc20_receiver/`: a consumer program. `Claim` credits an ERC-20
  `Transfer` once: it calls sextant_lc's `Attest` as a chained call in the
  same transaction and spends a nullifier keyed by the statement identifier
  ([`docs/CONSUMER.md`](docs/CONSUMER.md)). Not deployed on the testnet.
- `executor-tests/`: the committed program binaries through `lee::V03State`, the
  state machine the v0.3 sequencer applies, under the 10,000,000 gas cap.
- `cli/`: `sextant`, the client that deploys the program and drives it from the
  vectors, pre-checking every transaction through `lee::V03State` (built on the
  v0.3.0 wallet crate, with `common` from v0.3.1 for the testnet's block format);
  `scripts/e2e.sh` runs the lifecycle, `scripts/verify-onchain.sh` re-checks a
  recorded run against a sequencer's RPC.
- `evidence/`: the recorded runs, on the public LEZ testnet and on a local
  v0.3.1 sequencer ([`docs/ONCHAIN.md`](docs/ONCHAIN.md)).
- `vectors/mainnet/`: what the tests run on, fetched read-only from public
  endpoints on 2026-10-15: a `LightClientBootstrap` at slot 15,409,152, the
  `LightClientUpdate`s of sync-committee periods 1881 to 1883, a finality
  update in period 1884, and for its finalized block 26,197,200 an
  `eth_getProof` (WETH `balanceOf` of the Uniswap v3 USDC/WETH pool) and the
  block's receipts; the same two proofs for the checkpoint's own execution
  block 26,170,219 (`vectors/mainnet/block-26170219/`), which a consumer can
  attest against as soon as `Init` has run.
- `vectors/hoodi/`, `vectors/sepolia/`, `vectors/sepolia-gloas-fork/`: the same
  shape for the two public Ethereum testnets, fetched 2026-10-16
  (`scripts/fetch-vectors.py`): Hoodi periods 505 to 508 (Fulu), Sepolia
  periods 1385 to 1388 (Gloas since epoch 353,024), and one Sepolia instance
  from a Fulu checkpoint across the Gloas fork.

## Reproduce

Requires the RISC Zero toolchains (`rzup install`: rust and cpp, r0vm 3.0.5).

```console
scripts/build-guests.sh                       # the two benchmark guests -> artifacts/bench/
DOCKER=1 scripts/build-guests.sh lez          # the program, reproducibly -> artifacts/programs/v0.3/sextant_lc.bin
DOCKER=1 scripts/build-guests.sh receiver     # the consumer, reproducibly -> artifacts/programs/v0.3/erc20_receiver.bin
cargo test --release --manifest-path host/Cargo.toml             # 30 tests, natively: mainnet, Hoodi, Sepolia (Gloas)
cargo test --release --manifest-path executor-tests/Cargo.toml   # 16 tests, the binaries through lee::V03State
cargo run --release --manifest-path host/Cargo.toml --bin measure            # docs/raw/measure-*.txt
cargo run --release --manifest-path executor-tests/Cargo.toml --bin measure_lez  # docs/raw/measure-lez-*.txt
cargo run --release --manifest-path executor-tests/Cargo.toml --bin measure_receiver  # docs/raw/measure-receiver-*.txt
RISC0_DEV_MODE=0 SEGMENT_PO2=18 cargo run --release --manifest-path executor-tests/Cargo.toml --bin prove
python3 scripts/receipt_proof.py vectors/mainnet/receipts.json vectors/mainnet/block.json 2 /tmp/p.json
scripts/verify-onchain.sh --manifest evidence/testnet-v2/run.tsv          # the v2 run, against the sequencer's RPC
scripts/mutation-test-verifier.sh --manifest evidence/testnet-v2/run.tsv  # the verifier catches each corruption of the manifest
scripts/verify-onchain.sh                     # the first run (main's binary)
```

Results: [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md). On chain:
[`docs/ONCHAIN.md`](docs/ONCHAIN.md). Choices and why:
[`docs/DECISIONS.md`](docs/DECISIONS.md).

## On chain today

- **Public LEZ testnet** (v0.3.1), this branch's binary: program header
  `Ebe8rifvjyvwWUXnk7bsKeTwuyCAFSRMFuPMVHE8CbUB` (ImageID `ad6fbedb…`,
  `E7206` and Gloas). The full chain to period 1884: `Init` from the mainnet
  checkpoint, the attestations against the checkpoint's header, updates 1 to
  4 to the finalized execution block 26,197,200, the attestations against the
  last header (a `Transfer` log and a WETH balance slot), six refusals; 23
  transactions, 17 applied and 6 refused, each charged its pre-checked gas or
  its whole limit. Verifier 36 checks, 0 fail; mutation test 7 of 7.
  [`evidence/testnet-v2/run.tsv`](evidence/testnet-v2/run.tsv).
- **Public LEZ testnet** (v0.3.1), `main`'s binary: program header
  `A89TcYmWKXrzGkTUzLAxVExAB6HxSD6yf3dvjWMoiFzw`, `main`'s reproducible binary
  (ImageID `fa229edd…`).
  The full chain to period 1884: `Init` from the mainnet checkpoint, updates 1
  to 4 (`Begin`, `Miller`, `Finish` each; handoffs at periods 1881 to 1883) to
  the finalized execution block 26,197,200, attestations accepted against the
  checkpoint's header (block 26,170,219) and against the last one (a
  `Transfer` log and a WETH balance slot), seven refusals; 24 transactions, 17
  applied and 7 refused, each charged its pre-checked gas (applied) or its
  whole limit (refused). Verifier 37 checks, 0 fail.
  [`evidence/testnet/run.tsv`](evidence/testnet/run.tsv).
- **Local v0.3.1 standalone sequencer**: the whole chain in the vectors, four
  updates to block 26,197,200, the attestations under it, and every refusal of
  the executor tests: 36 transactions. [`evidence/local/e2e.tsv`](evidence/local/e2e.tsv).

## What this prototype is not yet

No instance tracks a live chain; no Logos core module or update daemon (the
client in `cli/` drives the committed vectors only); the reference consumer
program (`erc20_receiver`) runs in the executor tests only, not on a sequencer;
this branch's binary (`E7206`, Gloas) runs a mainnet instance only, no
Sepolia or Hoodi instance; no transaction proofs
(native ether sender), no historical headers; end-to-end runs against a
sequencer are not in CI. These are the
milestones of the proposal.

MIT OR Apache-2.0.
