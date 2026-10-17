# sextant_lc on a LEZ v0.3 sequencer

Two reproducible Docker builds of the program, deployed and driven from the
committed mainnet vectors by the client in `cli/` and `scripts/e2e.sh`:

- **v2** (ImageID `ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928`,
  `E7206` and Gloas) on the **public LEZ testnet** (https://testnet.lez.logos.co,
  sequencer v0.3.1), program
  `Ebe8rifvjyvwWUXnk7bsKeTwuyCAFSRMFuPMVHE8CbUB`, the full chain to period
  1884 ([The v2 testnet run](#the-v2-testnet-run)):
  [`evidence/testnet-v2/run.tsv`](../evidence/testnet-v2/run.tsv), 23
  transactions (17 applied, 6 refused);
- the earlier binary, before `E7206` and Gloas (ImageID `fa229eddbae15b2a20126e37e03fa82a2b42c7c98f74001a7d49e93fafe205c8`),
  program `A89TcYmWKXrzGkTUzLAxVExAB6HxSD6yf3dvjWMoiFzw`, on the **public LEZ
  testnet** (sequencer v0.3.1 `1a003bfb`), the full chain to period 1884:
  [`evidence/testnet/run.tsv`](../evidence/testnet/run.tsv), 24 transactions
  (17 applied, 7 refused);
- on a **local standalone v0.3.1 sequencer** (the same `1a003bfb` build), the
  whole chain the vectors hold:
  [`evidence/local/e2e.tsv`](../evidence/local/e2e.tsv), 36 transactions.

Re-check either from a clean clone, with nothing but python3:

```console
scripts/verify-onchain.sh --manifest evidence/testnet-v2/run.tsv          # the v2 run (36 checks)
scripts/mutation-test-verifier.sh --manifest evidence/testnet-v2/run.tsv  # the verifier fails on each of 7 corruptions
scripts/verify-onchain.sh                         # the first run (main's binary), against https://testnet.lez.logos.co
scripts/mutation-test-verifier.sh                 # the same over the first run's manifest
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

A block rewrite on the testnet can move a transaction to another block (the
verifier reports it, it is not a failure) or lose it from the hash index:
`getTransaction` then returns null for a transaction that is in a block. The
verifier then scans the blocks around the recorded one for a public
transaction of this program whose hash (SHA-256 of its bytes after the variant
tag) is the recorded one. Found, applied, and with every `# final` line of the
run holding, it is reported as a distinct status: applied, index lost after a
block rewrite, effect proven by the final state; its charge is then checked
like any other. Not found, claimed refused, or any final line off, and it
fails; the mutation test corrupts each of those for every such transaction and
requires that transaction's own line to fail.

## The v2 testnet run

Program header [`Ebe8rifvjyvwWUXnk7bsKeTwuyCAFSRMFuPMVHE8CbUB`](https://explorer.testnet.lez.logos.co/account/Ebe8rifvjyvwWUXnk7bsKeTwuyCAFSRMFuPMVHE8CbUB),
ImageID `ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928`
(651,932 bytes, sha256 `58a600a4…`): the `DOCKER=1` build, compared with
`cmp` against the committed binary before it was sent. Payer
`9nqn7xA7z54QZPHs8wWn5VzTeXTgbwq8SREr38tVK9aw`; instance id
`mainnet-v2-10171005` (instance account
`FyVTHTU4RepnCm8QbP7BUSm6Z9M9VPkMmMGM4W128UCH`, checkpoint header record
`Sgad8d8XmzNkYp9PxBoAJma66sYfwnboEaVofucPE3Y`, final header record
`En6hFJ5yr1yTmfQec7SbXCXUXvBiuwyBygqtj4AyJFo8`). Run on 2026-10-17, blocks
29,280 to 29,308, then, resumed at 19:44 UTC, blocks 32,290 to 32,296.
Verifier output:
[`evidence/testnet-v2/verify.txt`](../evidence/testnet-v2/verify.txt) (36
checks, 0 fail); mutation test (7 of 7 caught):
[`evidence/testnet-v2/mutation-test.txt`](../evidence/testnet-v2/mutation-test.txt).
Transcripts: [`transcript-part1.txt`](../evidence/testnet-v2/transcript-part1.txt)
(deploy, `SCENARIO=testnet`),
[`transcript-part2.txt`](../evidence/testnet-v2/transcript-part2.txt)
(`RESUME=1 SCENARIO=testnet-rest UPDATES="2 3"`),
[`transcript-part3.txt`](../evidence/testnet-v2/transcript-part3.txt)
(`RESUME=1 SCENARIO=testnet-rest UPDATES=4`).

| deployment | transaction |
|---|---|
| segment6 | [`3952262f74bdb5a8…`](https://explorer.testnet.lez.logos.co/transaction/3952262f74bdb5a81d8c742bf389951fff2159529e6b8b88a25b42d7eac8bf3b) |
| segment5 | [`917101817b51979a…`](https://explorer.testnet.lez.logos.co/transaction/917101817b51979a51f688adac56adf070019e3882e0c50f3beeae7c4e4b32de) |
| segment4 | [`57241caf369270ab…`](https://explorer.testnet.lez.logos.co/transaction/57241caf369270ab1755e9421ea55f1b1d2b65a72e642c2a035747e802b5765e) |
| segment3 | [`c7d4fc4ca0fa8373…`](https://explorer.testnet.lez.logos.co/transaction/c7d4fc4ca0fa8373c5c06ac6267b9017a336e08716e072e8390df7859efc4773) |
| segment2 | [`0891a911a1b0cbaf…`](https://explorer.testnet.lez.logos.co/transaction/0891a911a1b0cbaf7a6df096bd0e203d355dbe4f033921c07c42382086ec4b0a) |
| segment1 | [`8c944729fdcf7fac…`](https://explorer.testnet.lez.logos.co/transaction/8c944729fdcf7facc4afc19840c65a924676ced18e116b5f3c857bbd7199a169) |
| segment0 | [`8b4d0d0260423ebf…`](https://explorer.testnet.lez.logos.co/transaction/8b4d0d0260423ebf75bb51d6dae171b86b2286f47e3a9827b75d6d889e06e631) |
| header | [`3eefcfc6805a8764…`](https://explorer.testnet.lez.logos.co/transaction/3eefcfc6805a87649ad81f205204bc341aff153b37485d426a41678d542d6abb) |

| step | expected | verdict | block | transaction | pre-check | charged gas / limit |
|---|---|---|---:|---|---|---:|
| init | applied | applied | 29280 | [`e841867d66a7f27a…`](https://explorer.testnet.lez.logos.co/transaction/e841867d66a7f27a7b3b633b38a4d70ead5da01d21537a16489a9bde47721701) | gas=1835474 | 1835474 / 1863828 |
| attest-checkpoint-transfer-log | applied | applied | 29281 | [`2400b5f6fe590074…`](https://explorer.testnet.lez.logos.co/transaction/2400b5f6fe5900746f93f8f1d1e9800734d2dbc69469d1520c1a98d6f1dca3ac) | gas=91384 | 91384 / 102297 |
| attest-checkpoint-weth-balance | applied | applied | 29282 | [`1517a7c95f333e71…`](https://explorer.testnet.lez.logos.co/transaction/1517a7c95f333e7128e5629f5766e9a0f9ca874f08646bca9bebb6679a0f8a7b) | gas=304478 | 304478 / 317522 |
| attest-wrong-chain | refused | included-shared-block | 29290 | [`e510f032321a0ed1…`](https://explorer.testnet.lez.logos.co/transaction/e510f032321a0ed18e1e7a0ddf845551e38962ca97309ea1bf2350be56347114) | E7209 | block 29290 charged 496152 (see below) / 100290 |
| attest-predicate-false | refused | reverted | 29291 | [`b7968fa6ed23a9ae…`](https://explorer.testnet.lez.logos.co/transaction/b7968fa6ed23a9ae8c0fb03fae7dc6e4e4d8d72bd67de49f0ec14374d84de2f3) | E7208 | 100290 / 100290 |
| attest-slot-not-covered | refused | reverted | 29292 | [`372b61d363f75687…`](https://explorer.testnet.lez.logos.co/transaction/372b61d363f7568795d6ba2423b4323e342be422e0fcc706a710c9f9276fde8b) | E7207 | 334693 / 334693 |
| attest-unrecorded-header | refused | reverted | 29293 | [`24a52ad5c32072a1…`](https://explorer.testnet.lez.logos.co/transaction/24a52ad5c32072a10591334acd40ce6a8834002756a99bc610c5678453d945eb) | E7292 | 100290 / 100290 |
| u1-begin | applied | applied | 29294 | [`54c7c8c9c103f07f…`](https://explorer.testnet.lez.logos.co/transaction/54c7c8c9c103f07f6171ad178ad6dce6c957e886ea0d76587df58d53fdebefdc) | gas=5474785 | 5474785 / 5539532 |
| u1-miller | applied | applied | 29296 | [`50c01142a83b11cb…`](https://explorer.testnet.lez.logos.co/transaction/50c01142a83b11cb0fbf8c0c30ab6a0c46d14e91d5a597e8e88bc1a790003c84) | gas=4217768 | 4217768 / 4269945 |
| u1-finish | applied | applied | 29297 | [`b8432ed7777200a9…`](https://explorer.testnet.lez.logos.co/transaction/b8432ed7777200a907824824c2186c9d5c6c4860c8c1053729d135b413a8dd63) | gas=3769621 | 3769621 / 3817317 |
| u2-begin | applied | applied | 29301 | [`552d0dd84b64b04e…`](https://explorer.testnet.lez.logos.co/transaction/552d0dd84b64b04e8d0f780580a456eb668a1567d1e81b564ec3f3cb1c3db25d) | gas=5346523 | 5346523 / 5409988 |
| u2-miller | applied | applied | 29303 | [`77ff35f926a82d7e…`](https://explorer.testnet.lez.logos.co/transaction/77ff35f926a82d7ee6d527bf88f01b0e3119bc12d565ca69bd310d558bfd6bb3) | gas=4217768 | 4217768 / 4269945 |
| u2-finish | applied | applied | 29304 | [`e17bfe494757d504…`](https://explorer.testnet.lez.logos.co/transaction/e17bfe494757d50401bb25dfe85f6b3b3a7d760a0385437e05f90ba73c96d6a6) | gas=3769208 | 3769208 / 3816900 |
| u3-begin | applied | applied | 29305 | [`0d7569188d3f712e…`](https://explorer.testnet.lez.logos.co/transaction/0d7569188d3f712e3333bbf17bc1a181287cba7854eba6938a4bf3f8d831ae57) | gas=5390598 | 5390598 / 5454503 |
| u3-miller | applied | applied | 29307 | [`2ce5fe9311262113…`](https://explorer.testnet.lez.logos.co/transaction/2ce5fe93112621138ae0320ed3cda4f264255030cbab6b0e7c31252db4bebebd) | gas=4217768 | 4217768 / 4269945 |
| u3-finish | applied | applied | 29308 | [`ea82c407a48500a3…`](https://explorer.testnet.lez.logos.co/transaction/ea82c407a48500a3f2d8c0269802a702d9ca2ade3fc7bc40f016b574ed00478b) | gas=3769208 | 3769208 / 3816900 |
| u4-begin | applied | applied | 32290 | [`7937b2d71b993167…`](https://explorer.testnet.lez.logos.co/transaction/7937b2d71b993167fec2e6ff5d6ec91e7895d51035a46e1bc613e4c2e0e18fe9) | gas=3664393 | 3664393 / 3711036 |
| u4-miller | applied | applied | 32291 | [`7a336425cd196139…`](https://explorer.testnet.lez.logos.co/transaction/7a336425cd1961390ed431f845670d1e418886d7c8ab1f346e9de0c8a806a5a2) | gas=4217768 | 4217768 / 4269945 |
| u4-finish | applied | applied | 32292 | [`c016b5b23ed83571…`](https://explorer.testnet.lez.logos.co/transaction/c016b5b23ed83571d28ec8a17e6059458672ba9582ba8cbec179d6569f72f0e8) | gas=3767505 | 3767505 / 3815180 |
| attest-final-transfer-log | applied | applied | 32293 | [`55dd4b133af9164a…`](https://explorer.testnet.lez.logos.co/transaction/55dd4b133af9164a915e4ccf350ea2c4bb20b37c6e74fd27b66999548da29e1b) | gas=90919 | 90919 / 101828 |
| attest-final-weth-balance | applied | applied | 32294 | [`5523506f140a3f91…`](https://explorer.testnet.lez.logos.co/transaction/5523506f140a3f91be1e7b763932828efcbd866d825e986afe3c45f2a13e88b8) | gas=304478 | 304478 / 317522 |
| attest-final-wrong-chain | refused | reverted | 32295 | [`f5c372d223125d6e…`](https://explorer.testnet.lez.logos.co/transaction/f5c372d223125d6eb221f3147a2af4bd7de39812e8d8b1d22514a4606ad0fe37) | E7209 | 100290 / 100290 |
| u4-finish-again | refused | reverted | 32296 | [`074f11fa49c7addd…`](https://explorer.testnet.lez.logos.co/transaction/074f11fa49c7addd7680c369c7b306ee8e7f5e6cd4b0adb1c98a4a0fcd80e91b) | E7294 | 4145066 / 4145066 |

What it shows: the v2 binary deployed (seven segments and a header, 4,990,592
of the testnet token, storage only); `Init` from the mainnet checkpoint with
the timestamp window `E7206` declares; the two consumer attestations against
the checkpoint's header accepted; four refusals: another chain's query
(`E7209`), a false predicate (`E7208`), a slot the proof does not cover
(`E7207`), a header never recorded (`E7292`); updates 1 to 4 (periods 1881,
1882 and 1883 with committee handoffs, 1884 finality only), each across
`Begin`, `Miller`, `Finish`, to period 1884, the finalized execution block
26,197,200 (instance 403 bytes, digest `5a9dffc3…`; final header record
`En6h…`, 120 bytes); the two attestations against that last header (the
`Transfer` log, 90,919 gas, and the WETH balance, 304,478 gas) and another
chain's query refused (`E7209`); the duplicate `Finish` of update 4 refused
(`E7294`, the job is spent): six refusals in all. Every applied step was
charged on chain exactly the gas `measure_lez` reports for v2
([`raw/measure-lez-2026-10-17-v2.txt`](raw/measure-lez-2026-10-17-v2.txt)),
which is within 2,000 gas of the first deployment's step by step. Every
send waited for an execution base fee of 8 (`BASE_FEE_MAX=8`), so no step
paid a raised fee.

A block rewrite after the run moved the two checkpoint attestations into block
29,290, with `attest-wrong-chain`, which the client had already recorded as
`included-shared-block` (so the client's part 1 ends in `FAIL` on that line,
as in the first run). The verifier reports all three as included, their
charges not separable. Their sum is in the block all the same: block
29,290's execution gas, 496,152, is exactly 91,384 + 304,478 + the refusal's
whole limit, 100,290; and its storage gas, 10,636, is their three sizes
(1,680 + 7,276 + 1,680). The mutation test applies its verdict and charge
corruptions to transactions charged alone in their block, where the verifier
checks the charge.

Not sent, to fit the payer's balance in parts 1 and 2 (376,092,084 before
the run; 350,988,528 spent; 25,103,556 left): `init-again` (`E7291`, 16.4M as
a refusal charged its whole limit) and `u1-finish-again` (`E7294`, 33.2M).
Each skip is recorded in the manifest. The payer was then topped up to
425,103,556, and part 3 sent the rest of the chain at a base fee of 8, on
2026-10-17, before the checkpoint's timestamp window closed (2026-10-25 15:50
UTC):

| step | cost (testnet token) |
|---|---:|
| update 4 (period 1884, finality only): `Begin`, `Miller`, `Finish` | 93,432,248 |
| attestations against the last header (log, storage) and another chain's query refused | 4,050,088 |
| `u4-finish-again` refused (`E7294`), charged its whole limit | 33,169,608 |
| part 3 | 130,651,944 |
| the whole run, deployment included | 481,640,472 |

The payer holds 294,451,612 after it. Part 3 was run with:

```console
LEE_WALLET_HOME_DIR=~/logos-bedrock/lez-wallet-home PAYER=9nqn7xA7z54QZPHs8wWn5VzTeXTgbwq8SREr38tVK9aw \
RPC=https://testnet.lez.logos.co SEXTANT_PROGRAM=Ebe8rifvjyvwWUXnk7bsKeTwuyCAFSRMFuPMVHE8CbUB \
INSTANCE=mainnet-v2-10171005 RESUME=1 SCENARIO=testnet-rest UPDATES=4 UPDATE_MIN=100000000 \
BASE_FEE_MAX=8 OUT=evidence/testnet-v2/run.tsv scripts/e2e.sh
```

## The public testnet run (main's binary)

Payer `9nqn7xA7z54QZPHs8wWn5VzTeXTgbwq8SREr38tVK9aw`; instance id
`mainnet-10152211` (instance account `3T51gKhDkckqi3XuvPdN9Wj1wckAQouDMg9CsfBXG2iZ`,
checkpoint header record `H6rGJgtLU67pBchitybgTfi8UdMpH3geS1jK2bMRsdV7`, final
header record `ERpzfMGRxgm4yZDSghkkHK1u81w5J7PYB7AsZLmouagv`).
Verifier output: [`evidence/testnet/verify.txt`](../evidence/testnet/verify.txt)
(37 checks, 0 fail); mutation test (15 of 15 caught):
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
| u2-begin | applied | applied | 25788 | [`dcf68b9402c6d7c1…`](https://explorer.testnet.lez.logos.co/transaction/dcf68b9402c6d7c1e659ec2fff1e87dc3ddbf529ebcb8cc137f703f5db14357c) | gas=5344557 | 5344557 / 5408002 |
| u2-miller | applied | applied | 25798 | [`28f93ac488eb426f…`](https://explorer.testnet.lez.logos.co/transaction/28f93ac488eb426f92ce7b620d87aae74e0195ff172ee9dffab9b0605a6dcb0e) | gas=4217572 | 4217572 / 4269747 |
| u2-finish | applied | applied | 25799 | [`c057b7369bc5e503…`](https://explorer.testnet.lez.logos.co/transaction/c057b7369bc5e503c72bbeb9beb4698552e3bcbdb62143b3d1898cc40a7786c8) | gas=3767512 | 3767512 / 3815187 |
| u3-begin | applied | applied | 25800 | [`01bf9c26609a370d…`](https://explorer.testnet.lez.logos.co/transaction/01bf9c26609a370d5827cfaea7cedced69075dbf777d1c05ff3d8daad33b2f71) | gas=5388603 | 5388603 / 5452489 |
| u3-miller | applied | applied | 25801 | [`5a9f698e04dd2e22…`](https://explorer.testnet.lez.logos.co/transaction/5a9f698e04dd2e22e9d293c44733af0a54f5486cd5200e79b726ec6933778343) | gas=4217572 | 4217572 / 4269747 |
| u3-finish | applied | applied | 25802 | [`3b2b06f66334c424…`](https://explorer.testnet.lez.logos.co/transaction/3b2b06f66334c4245aebacd1889b444a89eaa191e5a73bf4fde8f534da569b56) | gas=3767512 | 3767512 / 3815187 |
| u4-begin | applied | applied | 25804 | [`327613bf856c3625…`](https://explorer.testnet.lez.logos.co/transaction/327613bf856c3625408f6208ca5c56e45555e43876d023f9223f49e296e7c83f) | gas=3662548 | 3662548 / 3709173 |
| u4-miller | applied | applied | 25805 | [`89ba6202aa481c82…`](https://explorer.testnet.lez.logos.co/transaction/89ba6202aa481c8242d79b7d01b9aeba7f39214ef5cd19fba2d581add459ff4a) | gas=4217572 | 4217572 / 4269747 |
| u4-finish | applied | applied | 25806 | [`e84df17848e5d190…`](https://explorer.testnet.lez.logos.co/transaction/e84df17848e5d190d7512e3bdf195367fa528c19ef28a96b7bda921fac66f279) | gas=3765844 | 3765844 / 3813502 |
| attest-final-transfer-log | applied | included-shared-block | 25805 | [`34a592585f680316…`](https://explorer.testnet.lez.logos.co/transaction/34a592585f680316697c797fe0d92721e111501a94234b0a567e7e11b48de7ea) | gas=90708 | 90708 (block 25805 charged 3856552 = u4-finish 3765844 + 90708) / 101615 |
| attest-final-weth-balance | applied | applied | 25814 | [`3c8b4fea45d1d00d…`](https://explorer.testnet.lez.logos.co/transaction/3c8b4fea45d1d00de5847998dcff7d2dbb601621ec13640a0b602bd18c1b3dae) | gas=304267 | 304267 / 317309 |
| attest-final-wrong-chain | refused | reverted | 25821 | [`74edea40a8d5be16…`](https://explorer.testnet.lez.logos.co/transaction/74edea40a8d5be16e58fce7abce464531c1e38e4c2bb091ae093012c2a4be622) | E7209 | 100290 / 100290 |

What it shows: the reproducible binary deployed; `Init` from the mainnet
checkpoint; two consumer attestations accepted against the checkpoint's header
(execution block 26,170,219: an ERC-20 `Transfer` log by receipt proof, and the
WETH `balanceOf` slot of the Uniswap v3 USDC/WETH pool by `eth_getProof`);
the full chain of the vectors: updates 1 to 4 (periods 1881, 1882 and 1883
with committee handoffs, 1884 finality only), each across `Begin`, `Miller`,
`Finish`, to the finalized execution block 26,197,200 (instance 379 bytes,
digest `8955da4f…`, the same bytes the local run ends with); the two
attestations against that last header (the `Transfer` log, 90,708 gas, and the
WETH balance, 304,267 gas) and another chain's query refused (`E7209`); and
seven refusals in all. Every step was charged on chain the gas measured off
chain ([`BENCHMARKS.md`](BENCHMARKS.md)).

Two things went wrong in the first part of the run and are in the manifest as
they happened: the first try at update 1's `Miller` was never sent (the
endpoint dropped the client's read of the job account; the client now retries
reads), so the client's next step, `Finish`, was refused by its pre-check and
not sent, and the following one, a deliberate duplicate `Finish`, landed
before `Miller` had run and was refused with `E7295` (Miller not run) instead
of the duplicate's `E7294`; it is recorded as that. The run was resumed with
`RESUME=1`: `Miller` and `Finish` then applied. The payer's balance then
covered update 1 only; once topped up, updates 2 to 4 and the attestations
under the last header ran with `RESUME=1 SCENARIO=testnet-rest`. The duplicate
`Finish` of update 4 was skipped: its refusal would be charged its whole limit,
more than the balance left. Transcripts:
[`transcript-part1.txt`](../evidence/testnet/transcript-part1.txt),
[`transcript-part2.txt`](../evidence/testnet/transcript-part2.txt),
[`transcript-part3.txt`](../evidence/testnet/transcript-part3.txt).

Since the run, block rewrites on the testnet moved seven of its transactions
to a nearby block, put eight in blocks shared with other charged
transactions (inclusion is then checked, the charge is not separable), and
lost `u4-miller` (`89ba6202…`, now in block 25804) and `u4-finish`
(`e84df178…`, now in block 25805) from the hash index. Both are found by the
verifier's block scan, and the final state proves their effect: the instance
holds the period-1884 record and the final header record `ERpz…` exists with
the bytes the run left. The client recorded `attest-final-transfer-log` as
`included-shared-block` (block 25805, shared with `u4-finish`): the block's
execution gas, 3,856,552, is exactly `u4-finish`'s 3,765,844 plus the
attestation's pre-checked 90,708. The client reads a charge only from a block
that holds the transaction alone, so it recorded `included-shared-block` and
counted that line as a failure, which is why
`transcript-part3.txt` ends in `FAIL`; the verifier reads the same block and
reports the transaction as included, its charge not separable.

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

## Redeploying v2

Branch `v2`'s binary (ImageID
`ad6fbedb983da6b6d75b287da354ce3041905d152d4e576ec318871eddfaa928`, `E7206`
and Gloas) changes the instance's wire format, so it is a new program, not an
upgrade of `A89TcYmW…`, which stays as it is: its header records remain
attestable. The plan, and where it stands:

1. Done: the `DOCKER=1` build, after `cmp` against the committed binary,
   deployed as `Ebe8rifvjyvwWUXnk7bsKeTwuyCAFSRMFuPMVHE8CbUB`.
2. Done to period 1884: a mainnet instance, `Init`, updates 1 to 4 and the
   attestations against the last header, with `verify-onchain.sh` and the
   mutation test over the new manifest
   ([The v2 testnet run](#the-v2-testnet-run)).
3. Not started: a Sepolia instance (Gloas) and a Hoodi instance from their
   vectors, with attestations against their last headers.

One deadline: `Init`, `Begin` and `Finish` now declare a timestamp window that
closes two weeks after the store's finalized header, so the committed
checkpoints stop being usable on a sequencer at 2026-10-25 15:50 UTC
(mainnet, slot 15,409,152; the mainnet instance reached period 1884 before
it, on 2026-10-17), 2026-10-27 02:02 UTC (Hoodi) and 2026-10-27
09:44 UTC (Sepolia). After those, fresh checkpoints have to be fetched
(`scripts/fetch-vectors.py` for Hoodi and Sepolia; it has no mainnet
endpoints yet). The budget per instance, at a base fee of 8 and counting each
transaction's bytes as storage gas: about 52M gas and 415M of the testnet
token for a four-update chain (13.4M gas and about 108M per update with a
handoff, 11.6M gas and about 93M for a finality-only one), plus about 15M for
`Init`.

## Reproduce

```console
cargo build --release --manifest-path cli/Cargo.toml
# a v0.3.1 standalone sequencer and a v0.3.0 wallet holding a funded key, then:
LEE_WALLET_HOME_DIR=... PAYER=... RPC=http://127.0.0.1:3040 DEPLOY=1 SCENARIO=full scripts/e2e.sh
scripts/verify-onchain.sh --manifest evidence/local/e2e.tsv --rpc http://127.0.0.1:3040
```
