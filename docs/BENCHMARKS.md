# Benchmarks (Performance #1, #2, #3, #4, #7, #8, #9)

Every figure here is produced by code in this repository, on the real mainnet
data in `vectors/mainnet/`, and every table has its raw output in `docs/raw/`.
Cycle counts are RISC Zero executor counts (r0vm 3.0.5): the quantity the LEZ
v0.3 state machine meters as gas, one for one, against `MAX_GAS_EXEC =
10,000,000` per transaction (also the per-block cap; the block target is 5M).
Development mode plays no part in any count; proving times are real proofs.

Machine: Apple M4 Pro, 14 cores, 24 GB, macOS 26.5, CPU proving.

## 1. The central question: does an update fit one transaction?

**No, with any library; yes, in three transactions.** Raw output:
[`raw/measure-2026-10-15.txt`](raw/measure-2026-10-15.txt)
(`cargo run --release --manifest-path host/Cargo.toml --bin measure`).

The benchmark guest runs the same `sextant-core` code against two BLS12-381
libraries, each built twice: stock, and with RISC Zero's accelerated forks
patched in (`guest/Cargo.toml`: blst `v0.3.16-risczero.0`, zkcrypto
`bls12_381/v0.8.0-risczero.1`, sha2, tiny-keccak). The two builds must return
the same verdict on every row or the harness aborts.

### 1.1 The primitives, on the update of period 1882 (512 of 512 signed)

| operation | stock | accelerated | speedup | share of 10M |
|---|---:|---:|---:|---:|
| (a) pairing check `e(pk,H(m)) = e(g1,sig)`, zkcrypto | 100,510,560 | 19,725,300 | 5.1x | 197.3% |
| (a) pairing check, **blst** | 129,951,187 | **7,849,796** | 16.6x | **78.5%** |
| hash_to_curve G2 of the signing root, zkcrypto | 35,389,027 | 2,815,078 | 12.6x | 28.2% |
| hash_to_curve G2, blst | 25,201,148 | 1,192,728 | 21.1x | 11.9% |
| signature decompression + G2 subgroup check, zkcrypto | 19,335,945 | 1,466,435 | 13.2x | 14.7% |
| signature decompression + subgroup check, blst | 11,153,316 | 545,356 | 20.5x | 5.5% |
| `hash_tree_root` of a 512-key SyncCommittee (SHA-256) | 9,751,472 | 1,509,370 | 6.5x | 15.1% |

By stage (accelerated):

| stage | zkcrypto | blst |
|---|---:|---:|
| G2 line precomputation, two points | 2,401,881 | (inside the loop) |
| Miller loops, two terms | 6,473,223 | 4,182,531 |
| final exponentiation | **10,832,615** | 3,657,369 |

With zkcrypto the final exponentiation alone exceeds a transaction.

### 1.2 (b) The signing key: aggregating the participants' keys

| strategy | stock | accelerated | share of 10M |
|---|---:|---:|---:|
| 512 of 512, decompress + subgroup-check each key, sum, zkcrypto | 3,132,916,365 | 525,079,512 | 5250.8% |
| 512 of 512, decompress (no subgroup check), sum, zkcrypto | 960,612,494 | 96,456,664 | 964.6% |
| 512 of 512, uncompressed witness checked against the committed bytes, sum, zkcrypto | 36,735,118 | 8,171,992 | 81.7% |
| 512 of 512, committee aggregate minus non-signers, zkcrypto | 2,323,177 | 451,573 | 4.5% |
| 512 of 512, decompress + subgroup-check each key, sum, blst | 3,826,823,461 | 233,602,653 | 2336.0% |
| 512 of 512, decompress (no subgroup check), sum, blst | 1,029,310,245 | 50,507,357 | 505.1% |
| 512 of 512, uncompressed witness, sum, blst | 50,616,101 | 6,575,453 | 65.8% |
| 512 of 512, **committee aggregate minus non-signers, blst** | 539,272 | **448,732** | **4.5%** |
| 511 of 512 (period 1881), aggregate minus 1 non-signer, blst | 898,471 | 466,128 | 4.7% |
| 342 of 512 (synthetic, the two-thirds floor), decompress + check, sum, zkcrypto | 2,093,232,607 | 350,675,013 | 3506.8% |
| 342 of 512, uncompressed witness, sum, zkcrypto | 25,080,289 | 5,396,943 | 54.0% |
| 342 of 512, aggregate minus 170 non-signers, zkcrypto | 13,649,362 | 2,891,995 | 28.9% |
| 342 of 512, decompress + check, sum, blst | 2,556,196,402 | 155,976,147 | 1559.8% |
| 342 of 512, uncompressed witness, sum, blst | 33,807,892 | 4,329,954 | 43.3% |
| 342 of 512, **aggregate minus 170 non-signers, blst** | 17,233,901 | **2,324,517** | **23.2%** |
| FastAggregateVerify, 342 of 512, best path, zkcrypto | 168,857,176 | 26,871,105 | 268.7% |
| FastAggregateVerify, 342 of 512, best path, blst | 183,511,882 | 11,884,928 | 118.8% |

Mainnet participation is near full (512, 511 and 510 of 512 in the vectors), so
the aggregate-minus-non-signers path decodes almost no keys; at the two-thirds
floor it decodes 170 and still costs under a quarter of a transaction. Why no
subgroup check is needed on the witnessed keys: decision D3.

### 1.3 (c) A whole LightClientUpdate, in one session

| update | stock | accelerated | share of 10M |
|---|---:|---:|---:|
| period 1882 with handoff, naive (decompress + check 512 keys, sum), zkcrypto | 3,307,714,611 | 551,582,379 | 5515.8% |
| period 1882 with handoff, best path, zkcrypto | 177,199,739 | 27,032,756 | 270.3% |
| period 1882 with handoff, naive, blst | 4,012,692,806 | 245,687,455 | 2456.9% |
| period 1882 with handoff, **best path, blst** | 186,486,933 | **12,611,850** | **126.1%** |
| period 1881 with handoff (511 signed), best path, blst | 186,923,061 | 12,706,485 | 127.1% |
| period 1884 finality update, no handoff (510 signed), best path, blst | 177,238,486 | 11,225,342 | 112.3% |

Where the 12.6M goes (best path, blst, accelerated):

| stage | cycles | share of 10M |
|---|---:|---:|
| checks (slots, periods, participation) | 1,364 | 0.0% |
| the supplied committee against the stored root | 1,081,370 | 10.8% |
| signing key (aggregate minus non-signers) | 18,968 | 0.2% |
| finality branch + execution branch | 60,872 | 0.6% |
| next committee root + branch (handoff only) | 1,088,866 | 10.9% |
| signing root | 12,142 | 0.1% |
| hash_to_curve G2 | 1,184,431 | 11.8% |
| signature decode + subgroup check | 536,173 | 5.4% |
| next store | 1,004 | 0.0% |
| pairing check | 7,840,755 | 78.4% |

**What fits one transaction:** the pairing check alone, everything else of an
update together, and every consumer attestation. **What does not:** a whole
update with any library, any update that decompresses its committee's keys,
and zkcrypto's final exponentiation alone.

### 1.4 The design those numbers imply: three steps

| step | accelerated guest | share of 10M |
|---|---:|---:|
| 1 `prepare`, period 1882 with handoff: every check but the pairing | 4,773,214 | 47.7% |
| 1 `prepare`, period 1884 finality update, no handoff | 3,386,802 | 33.9% |
| 2 the two Miller loops, product into one Fp12 | 4,194,822 | 41.9% |
| 3 final exponentiation, compare to one | 3,667,965 | 36.7% |
| instance bootstrap from the checkpoint | 1,582,131 | 15.8% |

(Session totals include decoding the input.) Why three steps rather than two,
and how the steps are bound together: decision D2.

## 2. The program, through the LEZ v0.3 state machine

`cargo run --release --manifest-path executor-tests/Cargo.toml --bin measure_lez`
runs the committed binary `artifacts/programs/v0.3/sextant_lc.bin` through
`lee::V03State` (`ValidatedStateDiff::from_public_transaction_with_cycle_budget`,
the call the sequencer's settlement makes) under the 10M cap: the plan and every
apply in the RISC Zero executor, summed. Raw output:
[`raw/measure-lez-2026-10-15.txt`](raw/measure-lez-2026-10-15.txt).

| transaction | gas (cycles) | share of the cap | signer |
|---|---:|---:|---|
| `Init` from the mainnet checkpoint (slot 15409152) | 1833662 | 18.3% | fresh account |
| update 1 (period 1881, with handoff): `Begin` | 5473086 | 54.7% | fresh account |
| update 1 (period 1881): `Miller` | 4217572 | 42.2% | fresh account |
| update 1 (period 1881): `Finish` | 3768242 | 37.7% | fresh account |
| update 2 (period 1882, with handoff): `Begin` | 5344557 | 53.4% | fresh account |
| update 2 (period 1882): `Miller` | 4217572 | 42.2% | fresh account |
| update 2 (period 1882): `Finish` | 3767512 | 37.7% | fresh account |
| update 3 (period 1883, with handoff): `Begin` | 5388603 | 53.9% | fresh account |
| update 3 (period 1883): `Miller` | 4217572 | 42.2% | fresh account |
| update 3 (period 1883): `Finish` | 3767512 | 37.7% | fresh account |
| update 4 (period 1884, finality only): `Begin` | 3662548 | 36.6% | fresh account |
| update 4 (period 1884): `Miller` | 4217572 | 42.2% | fresh account |
| update 4 (period 1884): `Finish` | 3765844 | 37.7% | fresh account |
| `Attest`: WETH balance slot of an account ≥ 1 wei, block 26197200 | 304267 | 3.0% | fresh account |
| `Attest`: an ERC-20 `Transfer` log in tx 2 of block 26197200 | 90708 | 0.9% | fresh account |

| update | three transactions together |
|---|---:|
| period 1881, with handoff | 13458900 (1.35x the cap of one transaction) |
| period 1882, with handoff | 13329641 (1.33x the cap of one transaction) |
| period 1883, with handoff | 13373687 (1.34x the cap of one transaction) |
| period 1884, finality only | 11645964 (1.16x the cap of one transaction) |

Every step is signed by an account the chain has never seen. The heaviest
step is 55% of the cap. An update costs 1.16x to 1.35x one transaction's cap in
total, spread over three. These figures are for the committed binary, the
reproducible Docker build (ImageID `fa229edd…`); the chain charged exactly
these figures, every row on a local v0.3.1 sequencer and on the public testnet,
as recorded at the time of each run ([`ONCHAIN.md`](ONCHAIN.md)).

### The `v2` binary (ImageID `ad6fbedb…`): `E7206` and Gloas, mainnet, Hoodi and Sepolia

Branch `v2` adds the weak-subjectivity check (`E7206`, three `u64`s in the
configuration with the Gloas epoch) and Gloas light-client headers. On the
mainnet vectors each transaction costs a few hundred to about 2,000 more
cycles (`Init` 1,835,474, update 1 `Begin` 5,474,785, `Miller` 4,217,768,
`Finish` 3,769,621; [`raw/measure-lez-2026-10-17-v2.txt`](raw/measure-lez-2026-10-17-v2.txt)).
The instance account grows by 24 bytes (403, 435 with a next committee); a
`Begin` with a handoff carries 52,197 bytes. The consumer's `Claim` with its
chained `Attest` costs 171,404 gas
([`raw/measure-receiver-2026-10-17-v2.txt`](raw/measure-receiver-2026-10-17-v2.txt)).

The same binary on the two public Ethereum testnets
(`executor-tests/tests/testnets.rs`,
[`raw/testnets-executor-2026-10-17.txt`](raw/testnets-executor-2026-10-17.txt)):

| chain | updates | heaviest `Begin` | `Miller` | heaviest `Finish` |
|---|---|---:|---:|---:|
| Hoodi (Fulu), periods 505 to 508 | 4 | 5,949,207 (59.5%) | 4,217,768 | 3,770,278 |
| Sepolia (Gloas), periods 1385 to 1388 | 4 | 5,498,751 (55.0%) | 4,217,768 | 3,770,380 |
| Sepolia across the Gloas fork, periods 1377 to 1380 | 4 | 5,827,490 (58.3%) | 4,217,768 | 3,770,278 |

Every step stays under 60% of the cap. Hoodi's `Begin` is the heaviest: more
non-signers to subtract from the committee aggregate than on mainnet. A Gloas
update carries the RLP execution header (about 670 bytes); the program
checks its keccak against the proven `execution_block_hash`.

## 3. Real proving (Performance #2, #4)

`RISC0_DEV_MODE=0 SEGMENT_PO2=18 cargo run --release --manifest-path executor-tests/Cargo.toml --bin prove`
proves the heavy session of each instruction from the committed binary (the
reproducible build, ImageID `fa229edd…`), with the RISC Zero prover on this
machine, and reports the succinct receipt. Raw output:
[`raw/prove-2026-10-16.txt`](raw/prove-2026-10-16.txt).

| session (committed binary) | user cycles | total cycles | segments | prove (s, wall) | succinct receipt (bytes) |
|---|---:|---:|---:|---:|---:|
| `Begin` plan, period 1882 with handoff (every check but the pairing) | 5,320,354 | 7,077,888 | 27 x 2^18 | 690.7 | 329,391 |
| `Miller` apply (two Miller loops) | 4,198,745 | 5,242,880 | 20 x 2^18 | 544.4 | 226,801 |
| `Finish` job apply (final exponentiation) | 3,672,913 | 4,456,448 | 17 x 2^18 | 476.9 | 225,815 |
| `Attest` apply (ERC-20 `Transfer` log, receipt proof) | 56,291 | 131,072 | 1 | 48.4 | 226,281 |

`Begin`'s receipt is larger because its journal carries the plan's input,
which includes the two 512-key committees. Each step of an update proves in
8 to 12 minutes on this CPU; a whole update in about 29 minutes of proving,
wherever it is proved (public transactions are executed by the sequencer;
these figures are the cost of proving each step, P.2).

Segment size matters. In an earlier run (on the build before the reproducible
one), with other applications open on this 24 GB machine, proving `Begin` at
the default 2^20-cycle segments, then `Miller` at 2^19, pushed the system 13 to
14 GB into swap and a disk watchdog stopped both; at 2^18 the update steps
proved without growing swap, and every figure above is at 2^18. The client
therefore chooses the segment size from available memory, and the peak memory
of the private path on the declared minimum hardware is part of M2.

## 4. The consumer side (the private path)

| attestation | in the guest | through the program (gas) |
|---|---:|---:|
| account + storage slot (WETH `balanceOf`), 9 + 7 nodes, Keccak | 187,776 | 304,267 |
| receipt + log (tx 2 of block 26,197,200), 3 nodes, 1,242 bytes | 47,737 | 90,708 |
| receipt + log (tx 0, a receipt with many logs), 3 nodes, 1,991 bytes | 63,863 | |

Under 3% of a transaction. Inclusion is Keccak hashing down a path, with no
curve operation: this is what a user's device proves in a private transaction.

## 5. Amortisation, latency, storage (Performance #3, #5, #7, #9)

- **Tracking**: one update per sync-committee period (8,192 slots, 27.3 hours)
  is the minimum that follows the handoffs: about 13.4M gas over three
  transactions. Each extra finality-only header costs about 11.6M. At one
  header an hour, about 279M gas a day, shared by every consumer of those
  headers; each attestation pays only its own 0.09M to 0.3M.
- **Latency**: Ethereum finality (two to three epochs, 13 to 19 minutes), the
  next finality update (available seconds after its attested block), the
  submitter's deferral, then three LEZ blocks.
- **Storage**: the instance account holds at most 411 bytes, 379 when no next committee is known (configuration and store, replaced in place); a job holds 1,137 bytes from `Begin` to `Finish`, which releases it; each header record holds 120 bytes, written once. A `Begin` with a handoff carries 52,165 bytes of instruction data (two 512-key committees), well inside a block. Header records accumulate: 38 kB a year at one
  per period, about 1 MB a year at one an hour, about 5 MB over five years. No
  action reads more than one header record or the instance, so no action's cost
  grows with stored data.

## 6. The precompile delta (Performance #8)

Of the 12.6M cycles of an update with a handoff, 9.58M are BLS12-381: key
assembly 0.02M, hash to G2 1.18M, signature decoding 0.54M, the pairing check
7.84M. A native precompile would leave about 3.0M (committee roots, branches,
signing root), so an update would fit one transaction. A precompile is
reachable only from public transactions; updates are public, and consumer
attestations use no BLS12-381 at all, so the private path does not depend on
one.
