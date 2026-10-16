# A consumer program: `erc20_receiver`

F.7 asks for a LEZ program that acts on a verified Ethereum fact in the same
transaction. `programs/erc20_receiver` is the smallest one that does
something with it: it credits a recipient for ERC-20 `Transfer` logs, once
each. It follows the pattern of decision D5 ([`DECISIONS.md`](DECISIONS.md)):
the consumer verifies nothing itself and calls sextant_lc's `Attest`.

## What a claim does

`Claim { receiver, slot, block_number, from, amount, proof }` says "the log at
`proof`'s position is a `Transfer` of `amount` by `receiver.token`, from `from`
to `receiver.recipient`, in Ethereum block `block_number`". It takes three
accounts, and the transaction succeeds or fails as a whole:

1. **The header record** (sextant_lc's shard, read only through
   `Plan::inspect`): it must exist for `slot`, and its chain id and block
   number must be the claimed ones. A claim against a header the light client
   never recorded is refused here (`E7392`), and so is one that names another
   block (`E7393`).
2. **The nullifier**, a PDA at `sha256("nullifier" ‖ receiver ‖ statement_id)`:
   it must be empty, and the claim writes it (`E7391` on a replay). The
   statement identifier is sextant's (decision D6): chain, block number,
   transaction index, log index and the log's content. The consumer computes
   it from the claim without verifying anything; every field that enters it
   is pinned to the proven log by a predicate of step 4, so one transfer has
   exactly one nullifier per receiver.
3. **The receiver**, a PDA at `sha256("receiver" ‖ borsh(Receiver))`: the
   count of claims and the 256-bit total credited. Its address commits to the
   whole configuration, including which sextant_lc deployment and instance it
   trusts, so a receiver bound to another light client is another account and
   cannot spend this receiver's nullifiers.
4. **The chained call** to sextant_lc: `Attest { instance_id, slot, query }`
   over the same header row, with five predicates (`LogAddress` = token,
   `LogTopic(0)` = `Transfer`, `LogTopic(1)` = from, `LogTopic(2)` =
   recipient, `LogDataWord(0)` = amount). sextant_lc verifies the receipt proof
   against the record's receipts root and refuses with its own typed code
   (`E7208` predicate false, `E7207` proof not under the record's root) if
   anything does not hold; the consumer's writes of steps 2 and 3 are then discarded.

The light-client guest is the deployed one on `main` (ImageID `fa229edd…`) and
`ad6fbedb…` on branch `v2`, where `Claim` costs 171,404 gas instead of 171,193;
the consumer is a
second guest, `artifacts/programs/v0.3/erc20_receiver.bin`, 339,432 bytes,
ImageID `dfe1163b5209cc6c7a9cf2efd510d4fa27da63d94dbb365da8a9ce4710faec09`, built in
RISC Zero's pinned Docker builder (`DOCKER=1 scripts/build-guests.sh
receiver`, checked byte for byte in CI like sextant_lc). It runs in the
executor tests only; it is not deployed on the testnet.

## Tests

`executor-tests/tests/receiver.rs`, both binaries through `lee::V03State`, on
the committed mainnet vectors (USDC transfers in tx 16 of block 26,170,219,
under the checkpoint's header, and in tx 2 of block 26,197,200, under the
header four updates later), each transaction signed by a fresh account:

| test | what it shows |
|---|---|
| `a_transfer_is_credited_once_and_its_replay_is_refused` | the claim lands and credits; the nullifier holds sextant's own `statement::evaluate` identifier; the replay is refused (`E7391`) and credits nothing; a second light-client instance of the same chain yields the same identifier (F.6), and a receiver bound to it has its own nullifier |
| `a_wrong_predicate_is_refused_by_attest_and_nothing_is_credited` | a larger amount, another recipient, another token: refused by the chained `Attest` (`E7208`); another chain id: refused by the header binding (`E7393`); nothing is written, and the genuine claim lands afterwards |
| `a_claim_against_an_unrecorded_header_is_refused` | before the updates that finalize block 26,197,200, its transfer is refused (`E7392`); presented under the checkpoint's header, refused for the block number (`E7393`) or, with that header's number, for the proof (`E7207`); after the four updates the same claim lands, once |

F.6 on its own: `host/tests/statement.rs`,
`f6_the_statement_identifier_is_identical_for_the_same_header_and_statement`
(the same header and statement, rebuilt independently, with or without
predicates, under another beacon slot; a storage fact at two blocks with the
same state) and `f6_the_statement_identifier_differs_for_different_state`
(two transfers, two logs of one receipt, the same log under another block
number, another chain, a storage slot whose value moved).

## Gas

`cargo run --release --manifest-path executor-tests/Cargo.toml --bin measure_receiver`,
[`raw/measure-receiver-2026-10-16.txt`](raw/measure-receiver-2026-10-16.txt).
The gas of a `Claim` is the whole transaction: the consumer's plan, its three
applies, and sextant_lc's chained `Attest` plan and apply. "The same `Attest`
alone" is sextant_lc's instruction with the same five predicates, sent on its
own; the difference is what the consumer adds.

| transfer claimed | `Claim` gas (with the chained `Attest`) | share of the 10,000,000 cap | the same `Attest` alone | the consumer's own share |
|---|---:|---:|---:|---:|
| tx 16 of block 26,170,219 (checkpoint header) | 171,193 | 1.7% | 98,953 | 72,240 |
| tx 2 of block 26,197,200 (after four updates) | 171,368 | 1.7% | 99,359 | 72,009 |

The `Claim` instruction is 1,482 and 1,451 bytes (the receipt proof is most of
it); a nullifier account holds 112 bytes, a receiver 40. A refused claim is
charged its whole gas limit, like every refused transaction on v0.3
([`ONCHAIN.md`](ONCHAIN.md)).

## What it is not

A demonstration of the composition, not a token bridge: it credits a number,
it moves no LEZ asset, and nothing on Ethereum locks the transferred funds. A
log with more than three topics or more than 32 bytes of data (not an ERC-20
`Transfer`) still gets one deterministic nullifier, but not sextant's
identifier for that log. Running it against a sequencer, and a private-path
claim, are milestone items.
