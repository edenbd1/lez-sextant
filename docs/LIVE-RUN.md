# Live run: Sextant's verifier following Sepolia and mainnet, unattended

Since 2026-11-18 08:43 UTC, `scripts/live-follow.py loop sepolia mainnet` has
followed both chains' finality, unattended, with sextant-core, the verifier the
`sextant_lc` guest runs. It keeps everything it read, so the run can be
replayed by anyone, byte for byte.

## What runs

Every 384 s (one epoch is 384 s), for each chain:

1. **Fetch.** The latest `LightClientFinalityUpdate` comes from one beacon
   implementation (Nimbus); the second (Lodestar) must agree on the finalized
   header. When a sync-committee period completes, its best `LightClientUpdate`
   (the committee handoff) is fetched from both, and it is kept only if they
   serve it identically. Gloas light-client headers name the execution block by
   hash only, so its RLP header is fetched too and checked to hash to that name.
2. **Keep.** Each finality update that finalizes a newer header goes to
   `updates/<signature slot>-finality.json`. Each period update goes to
   `updates/<signature slot>-period.json`. Every tick is one line of
   `fetch.jsonl`, saying what was read, from where, and whether the two nodes
   agreed.
3. **Replay.** `host/src/bin/follow` replays the whole directory: it starts
   from the bootstrap (the checkpoint, served identically by both nodes) and
   checks every update against the store the previous ones built. The checks
   are the sync-committee BLS signature over at least 342 of 512 members, the
   finality and next-committee Merkle branches, the handoff rules, and the
   execution header. It writes one verdict per update to `verdicts.jsonl`:
   `applied`, `unchanged` (a valid update that finalizes nothing newer) or
   `refused`. The store it ends in goes to `state.json`, and every chain's goes
   to `evidence/live-run/LATEST`.

Nothing fetched is trusted. A beacon node serving a forged or wrong update can
only produce a `refused` line, and a refused update changes nothing.

## Re-check it

```sh
scripts/verify-live.sh            # offline: replay, compare with the committed verdicts and state
scripts/verify-live.sh --online   # also against the beacon chain and an execution endpoint
```

The script checks five things:

- The replay reproduces every committed verdict and ends in `state.json`.
- Every update `fetch.jsonl` records as saved is present.
- No update was refused.
- The store advanced.
- With `--online`, two more:
  - every header the replay finalized is the canonical beacon block root at its slot;
  - the last finalized execution block has the state root the store holds.

Each endpoint can be swapped out (`--beacon-sepolia URL`, ...), for instance to
`scripts/rpc-archive.py` serving a recording.

`scripts/mutation-test-live.sh sepolia|mainnet` corrupts a copy of the
directory the way a lying beacon node could, and requires the replay to refuse
each corruption. It ran on 2026-11-18 and caught 7 of 7 on each chain:

| Corruption | Refused with |
|---|---|
| a signature bit flipped | `BadSignature` |
| a participation bit flipped | `BadSignature` |
| the finalized state root changed | `NotFinalized` |
| the finality branch changed | `NotFinalized` |
| the attested slot moved | `Malformed` |
| the signature moved into the next period without a handoff | `HandoffNotVerified` |
| participation below 342 | `BelowParticipation` |

## On chain: the same verifier as LEZ transactions

This run proves the verifier keeps up with live chains and checks updates
reproducibly. Submitting each update on the public LEZ testnet is the same
data, sent as the three transactions `Begin`, `Miller` and `Finish`
(`docs/ONCHAIN.md`).

What that costs:

- One update is about 14.8M execution gas: `Begin` 5.5M, `Miller` 4.2M,
  `Finish` 3.8M, each with 10% headroom, against a 10M cap per transaction.
- At the testnet's base fee of 8, that is about 118M testnet units per update.
- A period lasts 27.3 hours, so following one chain on chain costs about
  105M a day.
- The account that funded the earlier runs holds 29M, which is less than one
  update. It is reserved for the bridge's runs.

The public LEZ testnet has also produced no block since 2026-11-17 23:26 UTC
(tip 83,005), ahead of its move to 0.4. So this run sends nothing to LEZ: no
transaction, and no fee spent.

Funding comes from a Bedrock `ChannelDeposit` onto the LEZ channel
(a `ChannelDeposit` transaction sent with the Bedrock node's wallet, funded
with LGO from the Bedrock faucet). Once a payer
holds a few days' worth, the updates this run keeps can be sent as they come.
The on-chain store then has to match the off-chain replay header for header,
which `verify-onchain.sh` and `verify-live.sh` check from the two sides.

## Cross-checked against Helios

`scripts/crosscheck-helios.sh` replays the same directories through an
independent light client: the consensus core of
[Helios](https://github.com/a16z/helios) (a16z, `helios-consensus-core`
0.12.0, pinned to commit `2af9b41`), in the test-only crate
[`crosscheck-helios/`](../crosscheck-helios/). Nothing of Helios is in the
guest or the program; it is a second opinion on the same bytes.

For each file, in the order Sextant replayed it, Helios verifies and applies
the bootstrap or update (`verify_bootstrap`, `verify_generic_update`,
`apply_generic_update`, mainnet preset, the chain's own fork schedule and
genesis validators root) and the script requires:

- the same verdict as `verdicts.jsonl`: bootstrap, applied, or unchanged (an
  update that finalizes no newer header);
- after every applied update, the same finalized header (slot and
  hash-tree root), the same period, and the same execution block: number,
  state root and receipts root. For Sepolia, which is past Gloas, the light
  client header carries only the execution block hash, so the block's RLP
  header from `execution-headers.json` is checked to hash to it before its
  roots are read; for mainnet (Fulu) they come from the header's execution
  payload header.

It then applies the seven corruptions of `scripts/mutation-test-live.sh` to
the first applied update and requires Helios not to apply any of them.

On the snapshot committed here (2026-11-18, 08:43 to 19:51 UTC): Sepolia 90
updates applied and mainnet 89 (plus one bootstrap and one unchanged each),
Helios agreeing on every one. They include Sepolia's sync-committee handoff
from period 1416 to 1417: the period update (`000011599939-period.json`),
then updates signed by the new committee, up to finalized slot 11,608,064,
the first of period 1417. The corruptions are refused by Helios as an invalid
sync-committee signature (signature, participation bit, and "half the bits
cleared"), an invalid finality proof (state root, branch), an invalid
timestamp (attested slot) and an invalid period (signature slot). The "half
the bits cleared" mutation is caught by the signature in both clients, not
by the 2/3 participation rule: clearing bits changes the aggregate key. A
genuinely signed update below 2/3 would be refused by Sextant and kept by
Helios as a `force_update` candidate without being applied; no such update
has occurred in this run.

    scripts/crosscheck-helios.sh                      # the committed evidence/live-run/
    scripts/crosscheck-helios.sh /path/to/live-run    # any directory with sepolia/ and mainnet/
