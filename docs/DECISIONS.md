# Design decision log

Each entry records the context, the options considered, the option chosen,
and the rationale and trade-offs (Supportability #11). Figures are from
[`BENCHMARKS.md`](BENCHMARKS.md), measured on real mainnet data.

## D1. blst, through RISC Zero's accelerated fork, for BLS12-381

**Context.** Verifying a sync-committee signature is one `FastAggregateVerify`:
assemble the signing key, hash the signing root to G2, decode the signature,
check one pairing equation. Reliability #6 asks for mature, audited
implementations. Two libraries have RISC Zero accelerated forks for risc0 3.0:
zkcrypto `bls12_381` (`bls12_381/v0.8.0-risczero.1`, the base of r0vm-helios
and SP1 Helios) and supranational `blst` (`v0.3.16-risczero.0`).

**Options.** (a) zkcrypto `bls12_381`; (b) `blst`; (c) write our own pairing.

**Chosen: (b) blst.** Both run the same `sextant-core` code paths
(`core/src/zk.rs`, `core/src/bl.rs`) in the same guest, on the same mainnet
update, and both agree on every verdict (`both_libraries_agree_on_every_real_update`).

| accelerated guest | zkcrypto | blst |
|---|---:|---:|
| pairing check | 19,725,300 | 7,849,796 |
| of which final exponentiation | 10,832,615 (over the 10M cap alone) | 3,657,369 |
| hash_to_curve G2 | 2,815,078 | 1,192,728 |
| signature decode + subgroup check | 1,466,435 | 545,356 |
| whole update, fast path | 27,032,756 | 12,611,850 |

`blst` is 2.1 to 3 times cheaper at every step, and with zkcrypto the final
exponentiation alone exceeds a transaction, so the update could not be split
along the pairing's natural seam without rewriting the library. On maturity:
blst was audited by NCC Group (January 2021) and is under formal verification
by Galois (its README); the zkcrypto README states the implementation "has not
been reviewed or audited". blst is also the BLS library of the consensus
clients that produce these signatures. (c) is ruled out by the RFP (no novel
circuits) and by Reliability #6.

**Trade-off.** The accelerated layer of the fork (bigint2 FFI under blst's
field arithmetic) is RISC Zero's code, not supranational's; it is in the audit
scope (proposal, audit programme).

## D2. One update, three transactions, through a program-owned job

**Context.** The whole update costs 12.6M cycles with a committee handoff and
11.2M without one (blst, fast path). LEZ caps a transaction at 10M
(`MAX_GAS_EXEC`), and the same constant caps a block's total execution gas,
with a target of 5M per block (`lez/programs/fee/core/src/market.rs`).

**Options.** (a) one transaction: does not fit. (b) two: every check but the
pairing (about 5M), then the pairing (about 8M, 80% of a whole block). (c)
three: `Begin` (every check but the pairing), `Miller` (the two Miller loops),
`Finish` (final exponentiation, then the store advances in the same
transaction).

**Chosen: (c).** Measured through `lee::V03State`: `Begin` 5.34M to 5.47M with
a handoff, 3.66M without; `Miller` 4.22M; `Finish` 3.77M. Every step stays near
the block target instead of filling 80% of a block, leaves room for other
transactions, and keeps a margin if a fork or a LEZ change moves costs. The job
account carries the signing key, the message point, the signature, the Miller
product and the digests of the store before and after; only the program writes
it. The job id is `sha256(digest(instance) ‖ digest(update))`, so a job built
against a store that has since moved can never land (`E7293`), and two
operators racing the same update converge on one job (R.8). Anyone can send
any step: the prototype signs every step with an account the chain has never
seen. (b) is a one-instruction change if Logos prefers fewer transactions.

## D3. The signing key: the committee's aggregate minus the non-signers, from uncompressed witnesses

**Context.** Decompressing a key costs a square root; checking its subgroup
costs a scalar multiplication. For 512 keys that is 233.6M cycles with blst
(525.1M with zkcrypto), 23 times a transaction.

**Chosen.** The submitter supplies uncompressed points; the program checks each
is on the curve and compresses to the committed bytes (no square root), and
starts from the committee's own `aggregate_pubkey`, which is committed in the
same SSZ root, subtracting the keys that did not sign. 448,732 cycles at 512 of
512, 466,128 at 511 of 512 (mainnet), 2.32M at the two-thirds floor
(synthetic). No subgroup check is needed because each key's bytes are bound,
through the committee root, to a beacon state that admitted the key only after
`process_deposit` verified its proof of possession; the program checks only
that the witness *is* that key. Every strategy yields the same key on mainnet
data (`every_key_strategy_yields_the_same_key`).

## D4. Immutable header records; consumers read nothing that updates touch

**Context.** R.3 (an attestation stays valid forever) and R.11 (private
transactions can compute their result before inclusion) both fail if a
consumer reads the instance account, which every update rewrites.

**Chosen.** `Finish` writes one record per finalized header (`header`
PDA: chain id, slot, beacon root, block number, execution state root, receipts
root; 120 bytes), written once and never modified. `Attest` reads only that
record. The instance account is bounded (at most 411 bytes); header records grow by one per
recorded header (projections in BENCHMARKS.md, P.7) and no action reads more
than one (P.9).

## D5. The consumer pattern: verification inside the consumer's transaction

**Context.** F.7 and Verification Security #3.

**Chosen (prototype).** `Attest { instance, slot, query }` is an instruction of
the light-client program: it verifies the Merkle-Patricia proof against the
header record and evaluates the predicates, and refuses otherwise. A consumer
composes it as a chained call in its own transaction, naming the program by a
constant `ProgramId`, so verification and the action it authorises land or fail
together. **Open, settled in M2 with measurements:** the alternative in which
the consumer runs `sextant-core`'s inclusion code in its own `apply` against
the header record through an `inspect` guard (v0.3 `Plan::inspect`), which
saves a program call but compiles the verifier into each consumer.

## D6. The statement identifier

`sha256("sextant/statement/v1" ‖ chain_id ‖ kind ‖ …)`. For an event: block
number, transaction index, log index and the log's content, so an event has
exactly one identifier. For state: account, slot and the values read, without
the block number, so the same state read at two finalized blocks is the same
statement (F.6: identical state, identical identifier). A consumer keys its
nullifier on it.

## D7. Fork versions and light-client container shapes

**Context.** The signing domain depends on the fork version at the signature
slot; the generalized indices of the finality and committee branches changed
at Electra; Gloas will change the light-client containers again. Program code
is immutable.

**Chosen (prototype).** The fork schedule is part of the configuration fixed
at `Init`, and the Electra/Fulu container shapes are code. **To settle in M1:**
reading the fork version from the attested beacon state's `fork` field instead
of the configuration, which is safe (a wrong version only makes an honest
signature fail) and removes the need to re-initialise for a scheduled fork; a
container-changing fork still requires a new program version, released before
activation, with the consumer migration documented (Verification Security #3).

**Update (branch `v2`, 2026-10-16).** Gloas is no longer
ahead of us. Sepolia moved to it at epoch 353,024 (2026-10-06), and Hoodi
follows at epoch 132,352 (2026-10-26). Both RFP-eligible testnets will
therefore be Gloas before LEZ testnet 0.4. The program now knows both shapes:

- `ChainConfig.gloas_epoch` is fixed at `Init` like the rest of the
  configuration, and is `u64::MAX` where Gloas is unscheduled (mainnet).
- The Electra or Gloas generalized indices are chosen by the slot of the
  header they apply to: finality 169 or 735, committees 86/87 or 2945/2946,
  execution 25 or 2856.
- A Gloas light-client header proves only `execution_block_hash`. The
  submitter adds the RLP execution header, and the program keeps
  `stateRoot`, `receiptsRoot` and `number` only if the header's keccak is
  that proven hash (`mpt::execution_header_roots`). This adds about 670 bytes
  per update.
- `Store`, `HeaderRecord`, `Attest` and the consumer path are unchanged.
- One instance crosses the fork: `vectors/sepolia-gloas-fork` runs from a
  Fulu checkpoint through Gloas updates.

The wire format changes (`LcHeader.execution_rlp`, `ChainConfig.gloas_epoch`,
and 8 more bytes in the instance account), so the program binary must be
rebuilt and redeployed.

## D8. Reuse, assessed

**Kept from upstream, unchanged:** the light-client algorithm of the
consensus specs (Altair `sync-protocol.md`, Electra indices), which is also
what Helios and r0vm-helios implement; blst for every curve operation; risc0's
SHA-256 and Keccak forks. **Not reused:** r0vm-helios's guest and Helios's
`consensus-core`, because their output is a proof for an EVM contract and
their types bring an Ethereum client's dependency tree into a LEZ program; the
logic we need from them is the spec's, about 360 lines in `core/src/lc.rs` and
`core/src/ssz.rs`, tested against real mainnet data. The audit surface is therefore: our light-client and inclusion code,
the program shell, and the accelerated layer of the blst fork.

## D9. Weak-subjectivity staleness (E7206): a new program version, not deployed

**Context.** F.10: an instance whose finalized header is older than the
weak-subjectivity period must stop advancing, and a checkpoint that old must
not initialise one. The deployed sextant_lc (ImageID `fa229edd…`) defines
`E7206` but never emits it. The check reads the instance's configuration and
runs in the light client's own `Init`, `Begin` and `Finish`, so it cannot be
added around the deployed program: anyone can call those instructions
directly. It is guest code and changes the ImageID.

**Chosen (branch `v2`, milestone M1).** Two fields in `ChainConfig`, fixed at
`Init`: `genesis_time` and `max_checkpoint_age` (seconds; two weeks for the
mainnet vectors). Two checks:

1. **Against the chain itself, typed.** `lc::prepare` refuses an update signed
   more than `max_checkpoint_age` after the store's finalized header with
   `E7206` (`lc::check_fresh`), before any job is opened.
2. **Against LEZ time.** v0.3 gives a plan no clock, but a plan can declare a
   timestamp validity window. `Init`, `Begin` and `Finish` declare
   `..(genesis_time + 12 · finalized_slot + max_checkpoint_age) · 1000` ms, so
   the sequencer refuses them once that time has passed
   ("outside of the validity window").

`Attest` declares no window: header records stay valid after the instance goes
stale (R.3). Tests: `a_store_past_the_weak_subjectivity_bound_refuses_updates_with_e7206`,
`the_sequencer_clock_refuses_a_stale_store_and_records_stay_attestable`
(executor) and `a_store_older_than_the_weak_subjectivity_bound_is_refused`
(host). Cost: about 1,000 cycles per transaction (`Begin` 5,473,903 against
5,473,086 with this check alone). The `v2` binary, with this check and the
Gloas shapes of D7 (Docker, `r0.1.91.1`), has ImageID
`ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928`: `Begin`
of update 1 costs 5,474,785 gas
([`raw/measure-lez-2026-10-17-v2.txt`](raw/measure-lez-2026-10-17-v2.txt)).
It is deployed on the public testnet as a new program,
`Ebe8rifvjyvwWUXnk7bsKeTwuyCAFSRMFuPMVHE8CbUB`, where `Begin` of update 1 was
charged exactly that; the first instance keeps running `fa229edd…`
([`ONCHAIN.md`](ONCHAIN.md#the-v2-testnet-run)).

The bound also applies to a mismatched store: a mainnet update offered to a
Hoodi or Sepolia instance is refused with `E7206` first (its signature slot,
on that chain's clock, lies years after the store), and with the bound lifted
it is still refused (`HandoffNotVerified`).
