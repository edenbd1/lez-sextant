# sextant_lc on a LEZ v0.3 sequencer

The committed binary (ImageID `fa229eddbae15b2a20126e37e03fa82a2b42c7c98f74001a7d49e93fafe205c8`,
the reproducible Docker build) deployed and driven from the committed mainnet
vectors by the client in `cli/` and `scripts/e2e.sh`, twice:

- on the **public LEZ testnet** (https://testnet.lez.logos.co, sequencer v0.3.1
  `1a003bfb`), as far as the testnet payer's balance went:
  [`evidence/testnet/run.tsv`](../evidence/testnet/run.tsv), 12 transactions;
- on a **local standalone v0.3.1 sequencer** (the same `1a003bfb` build), the
  whole chain the vectors hold:
  [`evidence/local/e2e.tsv`](../evidence/local/e2e.tsv), 36 transactions.

Re-check either from a clean clone, with nothing but python3:

```console
scripts/verify-onchain.sh                         # the testnet run, against https://testnet.lez.logos.co
scripts/mutation-test-verifier.sh                 # the verifier fails on each of 7 corruptions of the manifest
```

## How a verdict is read from the chain

LEZ v0.3 has no receipts. A public transaction the program refuses is still
included in a block: it changes nothing, and its payer is charged its whole gas
limit (`ValidatedStateDiff::from_public_transaction_metered`). An accepted one
is charged exactly the cycles it used. Every block ends with the fee program's
`Distribute` transaction, whose summary records the block's charged execution
gas and storage gas. So `verify-onchain.sh`, for every transaction of a
manifest: resolves it by hash (`getTransaction`), reads its gas limit from its
own bytes, reads the block (`getBlock`) and its fee summary, and checks that
the block's storage gas is exactly this transaction's size (it is then the only
charged transaction of its block, and the execution gas is its own). Then:

- **applied**: charged exactly the gas the client's pre-check measured, below
  the limit; for `Init`, `Begin`, `Miller`, `Finish` the accounts changed,
  and the final instance and header-record bytes are pinned by the manifest's
  `# final` lines;
- **refused**: charged exactly its limit, nothing changed. Each refusal is sent
  with the gas limit of the honest instruction of the same kind
  (`cli/src/main.rs`, `HONEST_*`), so running out of gas cannot be what
  refused it. The typed code (`E72xx`) is what the client's pre-check got
  running the same transaction through `lee::V03State` against the chain's
  accounts; the chain records only that the program refused.

It also checks the program header names the ImageID of the committed binary,
every deployment transaction resolves, and a random hash does not. The
block explorer (https://explorer.testnet.lez.logos.co) indexes thousands of
blocks behind the sequencer; the sequencer RPC is the reference.

## The public testnet run

Payer `9nqn7xA7z54QZPHs8wWn5VzTeXTgbwq8SREr38tVK9aw`; instance id
`mainnet-10152211` (instance account `3T51gKhDkckqi3XuvPdN9Wj1wckAQouDMg9CsfBXG2iZ`,
checkpoint header record `H6rGJgtLU67pBchitybgTfi8UdMpH3geS1jK2bMRsdV7`).
Verifier output: [`evidence/testnet/verify.txt`](../evidence/testnet/verify.txt)
(24 checks, 0 fail); mutation test:
[`evidence/testnet/mutation-test.txt`](../evidence/testnet/mutation-test.txt).

Program header [`A89TcYmWKXrzGkTUzLAxVExAB6HxSD6yf3dvjWMoiFzw`](https://explorer.testnet.lez.logos.co/account/A89TcYmWKXrzGkTUzLAxVExAB6HxSD6yf3dvjWMoiFzw), ImageID `fa229eddbae15b2a20126e37e03fa82a2b42c7c98f74001a7d49e93fafe205c8`.

| deployment | transaction |
|---|---|
| segment6 | [`4696985669407edc…`](https://explorer.testnet.lez.logos.co/transaction/4696985669407edc3a534a1fc885ef94237dbd3015f8befb0a8d64fa7d154a99) |
| segment5 | [`eadf6abf0a4a1442…`](https://explorer.testnet.lez.logos.co/transaction/eadf6abf0a4a1442e6bce17852fc026768cbbaac4359e61274328b3f61b7e42e) |
| segment4 | [`493cbc535a1e803b…`](https://explorer.testnet.lez.logos.co/transaction/493cbc535a1e803be61d5cecb87b020775824634554a8a37d9235c503e1a099f) |
| segment3 | [`a2cf0a241e2ffd88…`](https://explorer.testnet.lez.logos.co/transaction/a2cf0a241e2ffd881c30b1dd4551d2bdae6527960fffab42d25605b2c8ccec1c) |
| segment2 | [`b5006e54a7c5f55b…`](https://explorer.testnet.lez.logos.co/transaction/b5006e54a7c5f55b4a63367a1ba05a0d3b013688d9bf66be4961cab9f2c5ef86) |
| segment1 | [`3f8b3d81afcb051f…`](https://explorer.testnet.lez.logos.co/transaction/3f8b3d81afcb051f6d191423d80c9343dcc6a695d7f623294196c68c6d6e2876) |
| segment0 | [`41faafcc0cce9aac…`](https://explorer.testnet.lez.logos.co/transaction/41faafcc0cce9aac08d6ff61ca53f95a98debb0133432148d9c2f242666cf308) |
| header | [`cf7e066e244b0b00…`](https://explorer.testnet.lez.logos.co/transaction/cf7e066e244b0b0018f4e676a7edd852309724c79d375dfe1bd238715b6e0152) |

| step | expected | verdict | block | transaction | pre-check | charged gas / limit |
|---|---|---|---:|---|---|---:|
| init | applied | applied | 19250 | [`ba6cdef7ccf95674…`](https://explorer.testnet.lez.logos.co/transaction/ba6cdef7ccf956747c0ead1bdfcb91818fa6de9cd0227426b6b26ac7fc5217f2) | gas=1833662 | 1833662 / 2017028 |
| init-again | refused | reverted | 19251 | [`c4b6c79cec2fe1ae…`](https://explorer.testnet.lez.logos.co/transaction/c4b6c79cec2fe1aeb2da775f941755250f4578d22dde3904ec0376cf483a5f8b) | E7291 | 2017028 / 2017028 |
| attest-checkpoint-transfer-log | applied | applied | 19252 | [`33753c55f9985f03…`](https://explorer.testnet.lez.logos.co/transaction/33753c55f9985f03f9bef014b4c329c9cee34bd5741bdcebd1757415f99646a9) | gas=91173 | 91173 / 100290 |
| attest-checkpoint-weth-balance | applied | applied | 19253 | [`ffa95195ab06919c…`](https://explorer.testnet.lez.logos.co/transaction/ffa95195ab06919c9ef33f38e7a00fef4c3ca7b5ef1d7bf4fdcf0cdfe1475fab) | gas=304267 | 304267 / 334693 |
| attest-wrong-chain | refused | reverted | 19397 | [`fcbddb6935b9b450…`](https://explorer.testnet.lez.logos.co/transaction/fcbddb6935b9b4501deadc02b9acb326600558c604d7ef0d162844f0345583db) | E7209 | 100290 / 100290 |
| attest-predicate-false | refused | reverted | 19534 | [`7c12add0f6cb8f83…`](https://explorer.testnet.lez.logos.co/transaction/7c12add0f6cb8f83bf61d651276791580cd5a09bce0381a72becedef27b1e15c) | E7208 | 100290 / 100290 |
| attest-slot-not-covered | refused | reverted | 19721 | [`19be290878d91691…`](https://explorer.testnet.lez.logos.co/transaction/19be290878d91691a5a720b4fa5dcfdabe21aeb3b326d70759491915f30d3bca) | E7207 | 334693 / 334693 |
| attest-unrecorded-header | refused | reverted | 19736 | [`345fc37dd43ca767…`](https://explorer.testnet.lez.logos.co/transaction/345fc37dd43ca7672f740e1b50444867fea5e6df033a9ff2bc433cc432854664) | E7292 | 100290 / 100290 |
| u1-begin | applied | applied | 19780 | [`f7bc0360db006954…`](https://explorer.testnet.lez.logos.co/transaction/f7bc0360db006954ca8f66a25d8a0498270f727d88eec982e9bf2a600e749cd5) | gas=5473086 | 5473086 / 6020394 |
| u1-finish-before-miller | refused | reverted | 20011 | [`73de61646bcfdff1…`](https://explorer.testnet.lez.logos.co/transaction/73de61646bcfdff137b010f6a16553a737303bfeb09e4aef82cd99d562f216bc) | E7295 | 4145066 / 4145066 |
| u1-miller | applied | applied | 21861 | [`88c03e2d5a48ac32…`](https://explorer.testnet.lez.logos.co/transaction/88c03e2d5a48ac32e21cd9b940ab67d3af162e5b43b9f3aa97910108988a7125) | gas=4217572 | 4217572 / 4269747 |
| u1-finish | applied | applied | 21874 | [`d414caa45b380502…`](https://explorer.testnet.lez.logos.co/transaction/d414caa45b38050298cf4b36c26c19c3230111c1eb15efc63638a12f76107d35) | gas=3768242 | 3768242 / 3815924 |

What it shows: the reproducible binary deployed; `Init` from the mainnet
checkpoint; two consumer attestations accepted against the checkpoint's header
(execution block 26,170,219: an ERC-20 `Transfer` log by receipt proof, and the
WETH `balanceOf` slot of the Uniswap v3 USDC/WETH pool by `eth_getProof`);
update 1 (period 1881) verified across `Begin`, `Miller`, `Finish`, its three
steps charged 5,473,086, 4,217,572 and 3,768,242 gas, as measured off chain;
and six refusals.

What it does not show, and why: update 1's finalized header is the
checkpoint's own (slot 15,409,152); what it adds is the verified handoff to the
period-1882 committee (`next_committee` in the instance). The first new header
record comes with update 2, and the attestations under block 26,197,200 need
updates 2 to 4: about 38M more gas, about 310M of the testnet token at today's
base fee of 8 per gas, where the payer started with 191M and holds 5.4M now.
Those steps, and the refusals that cost a whole `Begin` each, ran on the local
sequencer below.

Two things went wrong in the run and are in the manifest as they happened: the
first try at update 1's `Miller` was never sent (the endpoint dropped the
client's read of the job account; the client now retries reads), so the
client's next step, `Finish`, was refused by its pre-check and not sent, and
the following one, a deliberate duplicate `Finish`, landed before `Miller` had
run and was refused with `E7295` (Miller not run) instead of the duplicate's
`E7294`; it is recorded as that. The run was resumed with `RESUME=1`:
`Miller` and `Finish` then applied. Transcripts:
[`transcript-part1.txt`](../evidence/testnet/transcript-part1.txt),
[`transcript-part2.txt`](../evidence/testnet/transcript-part2.txt).

## The local v0.3.1 sequencer run

`sequencer_service` at `1a003bfb` (`--features standalone`, debug configuration),
the v0.3.0 wallet, port 3047. 36 transactions, 22 applied and 14 refused;
verifier 49 checks, 0 fail ([`verify.txt`](../evidence/local/verify.txt)),
mutation test 7 of 7 caught ([`mutation-test.txt`](../evidence/local/mutation-test.txt)),
transcript [`transcript.txt`](../evidence/local/transcript.txt). It mirrors
`executor-tests/tests/program.rs`:

- `Init`; a second `Init` (`E7291`);
- attestations against the checkpoint's header, accepted (log, storage) and
  refused: another chain (`E7209`), a false predicate (`E7208`), a slot the
  proof does not cover (`E7207`), a header never recorded (`E7292`);
- fabricated updates refused at `Begin`, before any job exists: participation
  341 of 512 (`E7205`), one byte of the signature altered (`E7203`), the
  finalized header moved one epoch (`E7202`);
- update 1 (`Begin`, `Miller`, `Finish`); the same update again: `Begin`
  (`E7293`, the instance moved), `Miller` and `Finish` (`E7294`, the job is spent);
- a real signature over another header in update 2: `Begin` and `Miller` apply,
  `Finish` refuses (`E7203`) and the instance is unchanged;
- updates 2, 3 and 4 (periods 1882 and 1883 with handoffs, 1884 finality only),
  to the finalized execution block 26,197,200, slot 15,436,224;
- attestations under block 26,197,200: the `Transfer` log (90,708 gas) and the
  WETH balance (304,267 gas), and another chain's query refused (`E7209`);
- an instance initialised with Sepolia's genesis validators root: a mainnet
  update's `Begin` and `Miller` apply, `Finish` refuses (`E7203`), the
  instance does not move.

`Init`, every update step and the two attestations under block 26,197,200 were
charged on chain exactly the gas `measure_lez` reports for them
([`raw/measure-lez-2026-10-15.txt`](raw/measure-lez-2026-10-15.txt)).

## Reproduce

```console
cargo build --release --manifest-path cli/Cargo.toml
# a v0.3.1 standalone sequencer and a v0.3.0 wallet holding a funded key, then:
LEE_WALLET_HOME_DIR=... PAYER=... RPC=http://127.0.0.1:3040 DEPLOY=1 SCENARIO=full scripts/e2e.sh
scripts/verify-onchain.sh --manifest evidence/local/e2e.tsv --rpc http://127.0.0.1:3040
```
