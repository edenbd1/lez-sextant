# The consensus-spec light-client vectors against sextant-core

The official test vectors of `ethereum/consensus-specs`, release
[`v1.7.0-beta.4`](https://github.com/ethereum/consensus-specs/releases/tag/v1.7.0-beta.4),
run against `sextant-core`, the verification the `sextant_lc` program
executes. Native, not in the zkVM: the program runs the same source (the
executor tests show the binary agrees with it on real chains).

```console
cargo test --release --manifest-path spec-tests/Cargo.toml        # 5 tests, in CI
cargo run  --release --manifest-path spec-tests/Cargo.toml        # the table per case
scripts/fetch-spec-tests.sh --check                               # vectors/ is the release's, byte for byte
```

## What is vendored, and from where

`vectors/tests/` holds the light-client suites for the forks sextant
supports, Electra, Fulu and Gloas, extracted from the release's
`mainnet.tar.gz` and `minimal.tar.gz` (sha256 `67762986…` and `26d09aea…`,
pinned in [`../scripts/fetch-spec-tests.sh`](../scripts/fetch-spec-tests.sh),
which re-vendors them or, with `--check`, compares them; CI runs the check).
2.3 MB, 168 files, unmodified.

| suite | preset | forks | cases | run |
|---|---|---|---:|---|
| `single_merkle_proof` | mainnet | Electra, Fulu, Gloas | 12 | yes |
| `sync` | minimal | Electra, Fulu, Gloas | 15 | yes, on the minimal-preset build (below) |
| `update_ranking` | minimal | | | no: tests `is_better_update`, the selection of a best update a full light-client store keeps; sextant keeps none (it applies any finalized, two-thirds-signed update) |
| `data_collection` | minimal | | | no: tests how a full node collects and serves light-client data |
| any suite, Altair to Deneb | | | | no: sextant verifies Electra and later (mainnet since May 2025) |

`derived/single_merkle_proof.json` holds what those vectors leave implicit:
the `hash_tree_root` of each test's object (the root its proof reaches) and
the field its leaf comes from, computed by the release's own pyspec
([`derive.py`](derive.py)). sextant-core derives each leaf itself.

## How each suite is run

**`single_merkle_proof`**, on sextant-core as built for the program. For each
of the four proofs of each fork, sextant-core derives the leaf from the
object (the root of a 512-key sync committee, the finalized checkpoint root,
the root of the execution payload header, or from Gloas the block hash), and
verifies the branch against the object's root at the generalized index
sextant uses for that fork: 25, 86, 87, 169 (Electra, Fulu), 2856, 2945,
2946, 735 (Gloas). The execution proofs go through `lc::check_execution`,
the program's own `is_valid_light_client_header`. A case passes when the
index, the leaf and the verdict all match the spec's.

**`sync`**, on the same source compiled with the minimal preset. The
release has sync vectors in the minimal preset only (32-member committees,
8-slot epochs, 8-epoch periods); sextant-core fixes mainnet's. `build.rs`
compiles a second copy of `core/src/` with exactly these substitutions,
each counted (the build fails if one no longer matches):

| constant | mainnet | minimal |
|---|---:|---:|
| `SLOTS_PER_EPOCH` | 32 | 8 |
| slots per sync-committee period | 32 x 256 | 8 x 8 |
| `COMMITTEE_SIZE`, committee Merkle width | 512 | 32 |
| `sync_committee_bits` | 64 bytes | 4 bytes |
| `SECONDS_PER_SLOT` | 12 | 6 |

and one change that is not a preset: from Gloas, a store takes its execution
roots from the RLP block header whose hash the light-client header proves.
The spec's vectors carry no RLP (the protocol proves the hash only), so the
copy records the hash with zero roots. That binding is tested on Sepolia's
real Gloas vectors (`host/tests/testnets.rs`).

Each case bootstraps from the vector's checkpoint with `lc::bootstrap`, then
sends every `process_update` through `lc::apply_update` with the program's
options (`lc::FAST`: witnessed keys, the committee aggregate minus the
non-signers, blst), the participation floor at two thirds (22 of 32, the
spec's supermajority), and the signing committee picked as the program does.
After each step, sextant's finalized header (slot and root) and its
execution root are compared with the spec store's.

- **pass**: sextant's finalized header equals the spec's at every check.
- **pass, scoped**: equal wherever the design applies; the case says where it
  does not.
- **fail**: sextant's finalized header is ahead of the spec's, differs at the
  same slot, or trails it with no step the design excludes.

## Results

`cargo run --release --manifest-path spec-tests/Cargo.toml`, 2026-11-14.
27 cases, 21 pass, 6 pass scoped, 0 fail.

| suite | fork | case | result | compared |
|---|---|---|---|---|
| single_merkle_proof | Electra, Fulu | `BeaconBlockBody/execution_merkle_proof` | pass | gindex 25, depth 4 |
| single_merkle_proof | Electra, Fulu | `BeaconState/current_sync_committee_merkle_proof` | pass | gindex 86, depth 6 |
| single_merkle_proof | Electra, Fulu | `BeaconState/finality_root_merkle_proof` | pass | gindex 169, depth 7 |
| single_merkle_proof | Electra, Fulu | `BeaconState/next_sync_committee_merkle_proof` | pass | gindex 87, depth 6 |
| single_merkle_proof | Gloas | `BeaconBlockBody/execution_block_hash_merkle_proof` | pass | gindex 2856, depth 11 |
| single_merkle_proof | Gloas | `BeaconState/current_sync_committee_merkle_proof` | pass | gindex 2945, depth 11 |
| single_merkle_proof | Gloas | `BeaconState/finality_root_merkle_proof` | pass | gindex 735, depth 9 |
| single_merkle_proof | Gloas | `BeaconState/next_sync_committee_merkle_proof` | pass | gindex 2946, depth 11 |
| sync | Electra, Fulu, Gloas | `advance_finality_without_sync_committee` | pass | 5 steps: 4 applied, 1 refused (`AlreadyApplied`); 5 of 5 checks |
| sync | Electra, Fulu, Gloas | `light_client_sync_no_force_update` | pass | 3 steps: 1 applied, 1 refused (`AlreadyApplied`); 3 of 3 checks |
| sync | Electra, Fulu, Gloas | `supply_sync_committee_from_past_update` | pass | 1 step: applied (the next committee, from an update of an earlier period); 1 of 1 checks |
| sync | Electra, Fulu, Gloas | `light_client_sync` | pass, scoped | 10 steps: 3 applied, 5 refused (2 `AlreadyApplied`, 3 `HandoffNotVerified`), 2 `force_update`; 5 of 10 checks |
| sync | Fulu | `gloas_fork` | pass, scoped | 8 steps across the Fulu-to-Gloas fork, `upgrade_store` included: 1 applied, 6 refused (`BadExecutionBranch`); 8 of 8 checks |
| sync | Electra, Fulu | `gloas_store_with_legacy_data` | pass, scoped | 1 step: refused (`BadExecutionBranch`); 1 of 1 checks |

Raw output: [`../docs/raw/spec-tests-2026-11-14.txt`](../docs/raw/spec-tests-2026-11-14.txt).

**Where the scope differs, and why.**

- `light_client_sync`: its two `force_update` steps apply the best
  non-finalized update after a sync-committee period without finality (the
  spec's timeout path). sextant applies finalized updates only, with no optimistic head
  (`core/src/lc.rs`), so from the first forced step its store trails the
  spec's, and the updates that follow are refused as `HandoffNotVerified`:
  they are signed two or three periods past its last finalized header. The five checks before agree.
- `gloas_fork` and `gloas_store_with_legacy_data`: in the first sync period
  after genesis the finalized checkpoint is the genesis block, and the spec
  lets an update finalizing genesis supply the next committee
  (`update_has_finalized_next_sync_committee`, with an empty finalized
  header). sextant requires a provable finalized header and refuses those
  (`BadExecutionBranch`). The finalized header agrees at every check; the
  difference is that sextant learns the next committee from a later update.
  It cannot arise on a chain past its first sync-committee period.

**Not exercised by these vectors.** A Gloas update whose attested header is
past the fork but whose finalized header is not carries that finalized header
in the Gloas container (a block hash, no payload header); sextant reads a
pre-Gloas header only with its payload header, so it would refuse such an
update and take a later one. That window lasts about two epochs after the
fork. `gloas_fork` does not contain one.

## The harness fails when it should

`tests/vectors.rs` also runs the vectors corrupted: every object root off by
one bit (all 12 proofs fail), every update's signature off by one bit, and
every finalized header moved off its finality branch (each fails the 10 sync
cases in which the spec's finalized header moves; the other five never move
it, and the test checks that their one update is refused instead).
