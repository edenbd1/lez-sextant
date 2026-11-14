# RFP-021 requirements, one by one

Every hard requirement of RFP-021 (Trustless Ethereum State Attestation for
LEZ), under the RFP's own numbering, against what this repository shows on
`main` on 2026-11-14. The program is `sextant_lc` on LEZ v0.3 (public testnet
sequencer v0.3.1); LEZ testnet 0.4 is not targeted yet.

**Status**, exactly one per row:

- **Met**: the testable statement is shown by the evidence cited, as it
  stands. The remaining-work column may still note hardening or a restatement
  on testnet 0.4.
- **Partial**: some of the requirement is shown, some is not; the
  remaining-work column says what is missing and in which milestone.
- **Planned in Mx**: nothing in this repository satisfies it yet; it is
  delivered in milestone Mx.

**Milestones**: M0 reuse assessment, measurements, design, threat model; M1
light-client program on testnet; M2 attestation path, private path, reference
consumers; M3 Logos core module, CLI, update daemon, IDL; M4 testnet 0.4,
end-to-end CI, benchmarks, documentation, catalog; M5 audit remediation and
re-verification.

**Where the evidence runs**, tagged in every row:

- *testnet*: the public LEZ testnet, recorded in `evidence/testnet*/` and
  [`ONCHAIN.md`](ONCHAIN.md), re-checkable from a clean clone with
  `scripts/verify-onchain.sh --manifest <run.tsv>`.
- *local*: a local standalone v0.3.1 sequencer (`evidence/local/`).
- *executor*: the committed program binaries through `lee::V03State`, the
  state machine the v0.3 sequencer applies, without a sequencer
  (`executor-tests/`).
- *native*: the verification core compiled for the host (`host/tests/`).

Test names are Rust test functions; `cargo test` runs them (host and executor
suites, both in CI).

## Functionality

| ID | requirement | status | evidence | remaining work |
|---|---|---|---|---|
| F.1 | Light client inside the program: from a checkpoint, verify updates and committee handoffs, check the sync-committee aggregate itself | Met | `core/src/lc.rs`; *native* `the_real_chain_verifies_from_the_checkpoint`; *executor* `the_real_chain_advances_through_three_handoffs_each_step_under_the_cap`, `hoodi_runs_through_the_binary_and_attests`, `sepolia_gloas_runs_through_the_binary_and_attests`; *testnet* mainnet instance, updates 1 to 4, handoffs at periods 1881 to 1883 ([`evidence/testnet-v2/run.tsv`](../evidence/testnet-v2/run.tsv), e.g. `Begin` of update 1 [`54c7c8c9…`](https://explorer.testnet.lez.logos.co/transaction/54c7c8c9c103f07f6171ad178ad6dce6c957e886ea0d76587df58d53fdebefdc)); Sepolia instance, Gloas signatures, to period 1388 ([`evidence/testnet-v2-sepolia/run.tsv`](../evidence/testnet-v2-sepolia/run.tsv)); *native* the official consensus-specs light-client vectors (v1.7.0-beta.4, `single_merkle_proof` and `sync`, Electra, Fulu, Gloas): 27 cases, 21 pass, 6 pass within the finalized-only scope, 0 fail ([`spec-tests/`](../spec-tests/README.md)) | Instances advance from committed vectors only; following a live chain is the daemon (Usability #3, M3) |
| F.2 | Accept only finalized headers; reject any other | Met | *native* `a_header_that_is_not_finalized_is_refused`; *executor* `a_fabricated_update_never_gets_a_job` (`E7202`); *local* the finalized header moved one epoch, refused `E7202` ([`evidence/local/e2e.tsv`](../evidence/local/e2e.tsv)) | The refusal is not sent on the public testnet |
| F.3 | Inclusion of an account, a storage slot and a receipt log under a finalized header; execution roots come from that header, never the caller | Partial | `core/src/mpt.rs`; roots only from the header record `Finish` writes (`programs/sextant/src/lib.rs`); *native* `an_account_and_a_storage_slot_verify_under_the_finalized_state_root`, `a_receipt_log_verifies_under_the_finalized_receipts_root`, `a_tampered_or_misrooted_proof_is_refused`, `the_finalized_block_is_the_one_the_proofs_are_for`; *testnet* a `Transfer` log [`55dd4b13…`](https://explorer.testnet.lez.logos.co/transaction/55dd4b133af9164a915e4ccf350ea2c4bb20b37c6e74fd27b66999548da29e1b) and a WETH balance slot [`5523506f…`](https://explorer.testnet.lez.logos.co/transaction/5523506f140a3f91be1e7b763932828efcbd866d825e986afe3c45f2a13e88b8) attested | The account is verified as the first half of the storage proof, but no test or transaction attests an account field (`AccountBalance`, `AccountNonce`) on its own (M2) |
| F.4 | Predicate over the verified state; at least equality and inequality; expressed by the consumer without changing the module | Met | `core/src/statement.rs` (`=`, `≠`, `<`, `≤`, `>`, `≥`, carried in the `Attest` query); *executor* `attestations_verify_and_refuse_with_typed_codes`, `attestations_verify_against_the_checkpoint_header`, `a_wrong_predicate_is_refused_by_attest_and_nothing_is_credited`; *testnet* false predicate refused `E7208` [`b7968fa6…`](https://explorer.testnet.lez.logos.co/transaction/b7968fa6ed23a9ae8c0fb03fae7dc6e4e4d8d72bd67de49f0ec14374d84de2f3) | |
| F.5 | Statement binds network and chain id; refused by a verifier configured for another chain; tested on mainnet and a testnet with the same contract address | Partial | Chain id in every header record and query (`E7209`); signing domain binds the genesis validators root; *native* `another_chain_is_refused`, `hoodi_and_mainnet_instances_refuse_each_other`, `sepolia_and_mainnet_instances_refuse_each_other`, `a_hoodi_statement_is_refused_by_a_mainnet_consumer`; *testnet* a mainnet-instance query as another chain [`f5c372d2…`](https://explorer.testnet.lez.logos.co/transaction/f5c372d223125d6eb221f3147a2af4bd7de39812e8d8b1d22514a4606ad0fe37) and a Sepolia statement asked as mainnet [`ba26cf3d…`](https://explorer.testnet.lez.logos.co/transaction/ba26cf3df674b7173e9f39bd8d2b1c9801efa43730ff4c87ce95fd7445b787cb), both `E7209` | The same-contract-address test is missing: the mainnet and Sepolia WETH proofs are for different addresses (M2) |
| F.6 | Deterministic, collision-resistant statement identifier from the attested state, for a consumer's nullifier | Met | `core/src/statement.rs`, decision D6 ([`DECISIONS.md`](DECISIONS.md)); *native* `f6_the_statement_identifier_is_identical_for_the_same_header_and_statement`, `f6_the_statement_identifier_differs_for_different_state`; *executor* `a_transfer_is_credited_once_and_its_replay_is_refused` (nullifier keyed on it) | `Attest` returns no data on v0.3; a consumer computes the identifier with `sextant-core`, as `erc20_receiver` does |
| F.7 | A LEZ program on testnet with a published interface; inclusion and predicate inside the consuming transaction; nothing acted on from an earlier transaction | Partial | Program on the public testnet, `Ebe8rifv…` ([`ONCHAIN.md`](ONCHAIN.md#the-v2-testnet-run)); interface: `Instruction` in `programs/sextant/src/lib.rs`; `erc20_receiver` calls `Attest` as a chained call in its own transaction, *executor* only ([`CONSUMER.md`](CONSUMER.md)); no recorded-statement path exists | Reference consumers on the testnet and the chained-call or inspect decision (D5) (M2); the IDL (M3) |
| F.8 | No new correlation signal; public inputs limited to what the consumer exposes; holds over full event and state diffs | Partial | `Attest` writes no account and emits no event (`Effect::Check` and the `Attest` arm in `programs/sextant/src/lib.rs`) | The header record read is a public trace of which header was used; reading the latest record and reaching older blocks through historical proofs; a test over the full event and state diff, including a private transaction (M2) |
| F.9 | Checkpoint, chain and finality parameters written at `Init`, never changed; a core-module API to verify a checkpoint against public sources | Partial | No instruction rewrites the configuration (`Instruction` in `programs/sextant/src/lib.rs`); *executor* `the_configuration_is_written_once`; *testnet* second `Init` refused `E7291` on the earlier binary [`c4b6c79c…`](https://explorer.testnet.lez.logos.co/transaction/c4b6c79cec2fe1aeb2da775f941755250f4578d22dde3904ec0376cf483a5f8b) | `verifyCheckpoint` on the Logos Ethereum core module does not exist; the gap and the change are in [`ETH-CORE-MODULE.md`](ETH-CORE-MODULE.md) (M3) |
| F.10 | An instance past the weak-subjectivity period is replaced, not refreshed; document when and how a consumer migrates | Partial | `E7206` and a timestamp window on `Init`, `Begin`, `Finish` (decision D9); *native* `a_store_older_than_the_weak_subjectivity_bound_is_refused`; *executor* `a_store_past_the_weak_subjectivity_bound_refuses_updates_with_e7206`, `the_sequencer_clock_refuses_a_stale_store_and_records_stay_attestable`; *testnet* the v2 program declares the window; window closing dates per instance in [`ONCHAIN.md`](ONCHAIN.md#redeploying-v2) | No `E7206` refusal sent on chain; the consumer-facing note on when to replace an instance and how to migrate (M1) |
| F.11 | Advancing is permissionless: no access control, role or registration; an account with no prior relationship can advance | Met | No step checks its signer (`plan` in `programs/sextant/src/lib.rs`); *executor* every step signed by a fresh account (`executor-tests/src/lib.rs`, `the_real_chain_advances_through_three_handoffs_each_step_under_the_cap`) | On the testnet every run used one payer; a run by an unrelated second account would show the same on chain (M1) |
| F.12 | Supplying and submitting update material are liveness roles; every off-chain participant identified, safety or liveness stated | Partial | Every byte of update material and every proof is verified in the program (F.1, F.3), so a supplier can only withhold | The participant list with safety or liveness for each, in the trust-assumptions document (M4) |
| F.13 | No instruction rewrites an initialised instance's checkpoint or chain configuration | Met | The five instructions (`Init`, `Begin`, `Miller`, `Finish`, `Attest`); `Finish` replaces only the store, checked against the digest of the stored instance; *executor* `the_configuration_is_written_once`; *testnet* `E7291` [`c4b6c79c…`](https://explorer.testnet.lez.logos.co/transaction/c4b6c79cec2fe1aeb2da775f941755250f4578d22dde3904ec0376cf483a5f8b) | |
| F.14 | The same program, unmodified, serves any Ethereum-consensus chain, mainnet or testnet | Met | Chain configuration (chain id, genesis validators root, fork schedule, Gloas epoch) fixed per instance at `Init`; *testnet* one program `Ebe8rifv…` with mainnet, Sepolia and Hoodi instances ([`evidence/testnet-v2/`](../evidence/testnet-v2/), [`evidence/testnet-v2-sepolia/`](../evidence/testnet-v2-sepolia/), [`evidence/testnet-v2-hoodi/`](../evidence/testnet-v2-hoodi/)) | Fork versions read from the beacon state instead of the configuration (D7, M1) |
| F.15 | Independent instances coexist; a consumer binds to one; a statement from one is never accepted by a consumer bound to another | Partial | Instance id in every PDA; *executor* `the_configuration_is_written_once` (two instances side by side), `a_transfer_is_credited_once_and_its_replay_is_refused` (a receiver bound to a second instance); *testnet* four instances under `Ebe8rifv…` ([`ONCHAIN.md`](ONCHAIN.md)) | A negative test: a consumer bound to one instance presenting another instance's record (M1) |

## Usability

| ID | requirement | status | evidence | remaining work |
|---|---|---|---|---|
| Usability #1 | A Logos core module: produce, verify, submit an update, read an instance's configuration | Planned in M3 | What the module needs from the Logos Ethereum core module: [`ETH-CORE-MODULE.md`](ETH-CORE-MODULE.md) | The module |
| Usability #2 | CLI: produce an attestation for a `(chain, contract, slot or log, predicate)` tuple, dry-run with the on-chain codes, submit an update, read configuration | Partial | `cli/` (`sextant`): `init`, `begin`, `miller`, `finish`, `attest`, `show`; every transaction pre-checked through `lee::V03State`, returning the program's codes | Works from committed vectors only; no arbitrary tuple, no explicit dry-run command (M3) |
| Usability #3 | Update-submitting Logos module and headless daemon: follows Ethereum through the core module, detects lag, submits, configurable endpoints, structured logs, clean shutdown, operator journey | Planned in M3 | `scripts/e2e.sh` drives the program from vectors; it is not a daemon | The module, the daemon, the operator journey |
| Usability #4 | IDL with SPEL | Planned in M3 | | The IDL and a check against the program's encoding |
| Usability #5 | Clear, actionable errors for every listed failure mode | Met | Stable codes and messages in `programs/sextant/src/lib.rs` (`message`): `E7201` malformed, `E7202` not finalized, `E7203` signature, `E7204` handoff, `E7206` stale, `E7207` inclusion, `E7208` predicate, `E7209` chain id; tests assert the codes (*executor* `executor-tests/tests/program.rs`); on chain, the client's pre-check reports the code ([`ONCHAIN.md`](ONCHAIN.md#how-a-verdict-is-read-from-the-chain)) | Carried through the module and CLI (Usability #1, #2) |
| Usability #6 | Reference consumers: an ERC-20 transfer and a native ether transfer to a given contract | Partial | `programs/erc20_receiver/`: token, sender, recipient, amount from the log, nullifier on the statement id; *executor* `executor-tests/tests/receiver.rs` ([`CONSUMER.md`](CONSUMER.md)) | The native ether consumer (transaction proofs); both on the testnet (M2) |

## Reliability

| ID | requirement | status | evidence | remaining work |
|---|---|---|---|---|
| Reliability #1 | Deterministic verdicts, reproducible from the test suite | Met | Committed vectors (`vectors/`); host and executor suites in CI (`.github/workflows/ci.yml`); *native* `both_libraries_agree_on_every_real_update`; the gas tables re-run in CI (`measure_lez`, `measure_receiver`); the consensus-specs light-client vectors, sha256-pinned, in CI (`spec-tests`, [`spec-tests/`](../spec-tests/README.md)) | |
| Reliability #2 | A rejected attestation consumes nothing; the consumer can retry | Met | `Attest` writes nothing; *executor* `a_bad_signature_is_refused_at_finish_and_nothing_moves`, `a_wrong_predicate_is_refused_by_attest_and_nothing_is_credited` (the genuine claim lands afterwards); *testnet* each refusal verified to change nothing ([`ONCHAIN.md`](ONCHAIN.md#how-a-verdict-is-read-from-the-chain)) | |
| Reliability #3 | A statement over a finalized header stays valid; later rotations never invalidate it | Met | Header records written once, never modified (decision D4); *executor* `the_sequencer_clock_refuses_a_stale_store_and_records_stay_attestable`, `a_stalled_instance_resumes_without_repair` | |
| Reliability #4 | Handoff tracking survives interruption: resume from the last verified state, never from the checkpoint, never an unverified handoff | Partial | Tracked state lives on chain; a `Begin` built against a moved store is refused (`E7293`); *testnet* the mainnet run resumed in three parts from the instance's own state (`RESUME=1`, [`evidence/testnet-v2/transcript-part2.txt`](../evidence/testnet-v2/transcript-part2.txt)) | Restart behaviour of the off-chain component (M3) |
| Reliability #5 | Ethereum RPC failures leave off-chain components recoverable, without duplicated work | Planned in M3 | | The daemon's retry and resume |
| Reliability #6 | Integrate mature, audited primitives; state what is reused, rewritten, and the audit-surface consequence | Partial | blst through RISC Zero's accelerated fork, audit status stated (D1); reuse assessed in brief (D8) ([`DECISIONS.md`](DECISIONS.md)) | The written assessment of r0vm-helios, SP1 Helios and Helios with its audit-surface consequences (M0) |
| Reliability #7 | A stalled instance keeps safety and resumes when anyone submits, with no repair and no gap | Met | *executor* `a_stalled_instance_resumes_without_repair`; *testnet* the mainnet instance resumed about 3,000 blocks after update 3 ([`ONCHAIN.md`](ONCHAIN.md#the-v2-testnet-run)) | |
| Reliability #8 | A duplicate or already-applied update is refused cleanly, never double-applied | Met | Job id binds the store and the update (D2); *native* `an_applied_update_is_refused_as_a_duplicate`; *executor* `a_competing_operator_is_refused_cleanly`; *testnet* duplicate `Finish` refused `E7294` [`074f11fa…`](https://explorer.testnet.lez.logos.co/transaction/074f11fa49c7addd7680c369c7b306ee8e7f5e6cd4b0adb1c98a4a0fcd80e91b); *local* `E7293`, `E7294` ([`evidence/local/e2e.tsv`](../evidence/local/e2e.tsv)) | |
| Reliability #9 | The submitter checks an update is still needed just before submitting | Planned in M3 | | Part of the daemon |
| Reliability #10 | Per-instance varied deferral so cost does not land on the fastest party; strategy and latency effect documented | Planned in M3 | | Part of the daemon, with its documentation |
| Reliability #11 | Statement submissions independent: several private transactions per block; result computable before inclusion | Partial | `Attest` reads one immutable header record and writes nothing (D4) | Shown in private transactions (M2) |
| Reliability #12 | CI green on the default branch | Met | `.github/workflows/ci.yml`: host tests, consensus-spec vectors, executor tests and gas tables, reproducible Docker rebuild of both binaries, client build, link check; green on `main` | |

## Performance

| ID | requirement | status | evidence | remaining work |
|---|---|---|---|---|
| Performance #1 | Attestation verification and predicate in one transaction at the budget in force; else document the shortfall by component | Partial | `Attest` 90,708 to 304,267 gas, at most 3% of the 10M cap; `Claim` with chained `Attest` 171,193 gas ([`BENCHMARKS.md`](BENCHMARKS.md), [`CONSUMER.md`](CONSUMER.md), `docs/raw/measure-lez-2026-10-15.txt`); *testnet* charged the same | Restated on the testnet 0.4 budget (M4) |
| Performance #2 | Cost per action (tracking, each statement type): cycles, gas, proof time, proof size; reproducible | Partial | [`BENCHMARKS.md`](BENCHMARKS.md) sections 1 to 3, raw output in `docs/raw/`: cycles and gas for `Init`, every update step and both statement types, and the worst update the program accepts (342 of 512 signers with a handoff: `Begin` 7,389,387, 73.9% of the cap, *executor*); real proofs of `Begin`, `Miller`, `Finish`, `Attest` (log) with time and receipt size (`docs/raw/prove-2026-10-16.txt`) | Proof time and size for `Init` and the storage statement; transaction statements (M2); all restated on 0.4 (M4) |
| Performance #3 | Amortised per-attestation tracking cost at the recommended cadence, separate from verification | Partial | [`BENCHMARKS.md`](BENCHMARKS.md) section 5: about 13.4M gas per period minimum, about 11.6M per extra header, attestations 0.09M to 0.3M | A recommended cadence and the per-attestation share under stated consumer volumes (M4) |
| Performance #4 | User-device proving practical on Basecamp desktop hardware: wall-clock and peak memory, mid-range laptop and declared minimum, including a private transaction | Partial | The consumer step (`Attest` apply, 56,291 user cycles) proves in 48.4 s on one machine (Apple M4 Pro, CPU) ([`BENCHMARKS.md`](BENCHMARKS.md) section 3) | A full private transaction; peak memory; a mid-range laptop and a declared minimum (M2) |
| Performance #5 | End-to-end latency: finality wait, update availability, on-chain verification | Partial | Components stated, not measured ([`BENCHMARKS.md`](BENCHMARKS.md) section 5) | Measured end to end against a live chain (M4) |
| Performance #6 | CPU, RAM and time of every off-chain component | Planned in M4 | | Measured with the daemon |
| Performance #7 | Growth rate and storage cost of accumulating state, projected over one and five years | Partial | Instance bounded (at most 435 bytes on v2), job released at `Finish`, header records 120 bytes each, growth per year at two cadences ([`BENCHMARKS.md`](BENCHMARKS.md) section 5) | Storage cost in gas and token; both projections at both cadences (M4) |
| Performance #8 | Cycle delta between in-program BLS12-381 and a hypothetical precompile; precompile public-only | Met | [`BENCHMARKS.md`](BENCHMARKS.md) section 6: 9.58M of 12.6M cycles are BLS12-381; about 3.0M would remain; public-only stated | |
| Performance #9 | No action's cost scales with accumulated storage | Met | Every action reads at most the instance and one header record (D4; [`BENCHMARKS.md`](BENCHMARKS.md) section 5) | |

## Supportability

| ID | requirement | status | evidence | remaining work |
|---|---|---|---|---|
| Supportability #1 | Deployed and tested on LEZ testnet 0.4, attesting public Ethereum testnet state | Partial | *testnet* (v0.3.1): Sepolia and Hoodi instances with attestations under their headers ([`ONCHAIN.md`](ONCHAIN.md#sepolia-and-hoodi-on-the-v2-program)) | The port to testnet 0.4 (M4) |
| Supportability #2 | End-to-end tests against a standalone sequencer and an Ethereum test network or local fork, in CI | Partial | `scripts/e2e.sh` against a local standalone sequencer, on recorded mainnet, Sepolia and Hoodi data (*local* [`evidence/local/`](../evidence/local/)) | Not in CI; not against a live test network or local fork (M4) |
| Supportability #3 | In-repo documentation of the core module for a consuming program | Partial | [`CONSUMER.md`](CONSUMER.md) (composing `Attest` from a consumer) | The integration guide for the core module (M4) |
| Supportability #4 | "Recommended Consumer Pattern": nullifier on the statement id, chain-binding check, each typed code, refuse rather than fall back | Partial | [`CONSUMER.md`](CONSUMER.md) shows the nullifier and the header and chain binding in `erc20_receiver` | The named section, with handling of every code and the refuse-don't-fall-back rule (M4) |
| Supportability #5 | In-repo documentation of the CLI and operator-facing components | Partial | README "Reproduce" and [`ONCHAIN.md`](ONCHAIN.md#reproduce) for the prototype client and `scripts/e2e.sh` | User and operator journeys for the CLI and daemon (M3, M4) |
| Supportability #6 | Trust-assumptions document | Planned in M4 | | |
| Supportability #7 | The operator role: cost, cadence, starting without permission, requirements, concurrency, stall detection, no obligation | Planned in M3 | Per-update cost on the testnet in [`ONCHAIN.md`](ONCHAIN.md#redeploying-v2) | The operator guide |
| Supportability #8 | Independent audit of consensus and inclusion verification, report published | Planned in M5 | | The audit after M4; remediation and the published report in M5 |
| Supportability #9 | Modules published in the team's own catalog from the Logos template | Planned in M4 | | |
| Supportability #10 | Built and released with `logos-modules-release-action` | Planned in M4 | | |
| Supportability #11 | Design decision log, current at each milestone | Met | [`DECISIONS.md`](DECISIONS.md), D1 to D9 | Kept current |

## Verification Security

| ID | requirement | status | evidence | remaining work |
|---|---|---|---|---|
| Verification Security #1 | A fabricated chain (self-consistent header and inclusion proof over never-finalized state) is refused, tested explicitly | Partial | *native* `a_fabricated_chain_is_refused`: execution and finality branches verify, the signature does not; *executor* `a_bad_signature_is_refused_at_finish_and_nothing_moves` (a real signature over another header); *local* the same at `Finish`, `E7203` | The fabricated chain as such, with an inclusion proof under its root, through the program binary (M1) |
| Verification Security #2 | Refuse: an un-handed-off committee, low participation, an unfinalized header, a tampered root, another chain id, a predicate the proof does not cover | Met | *native* `a_committee_never_handed_off_is_refused`, `participation_below_two_thirds_is_refused`, `a_header_that_is_not_finalized_is_refused`, `a_tampered_execution_root_is_refused`, `another_chain_is_refused`; *executor* `a_fabricated_update_never_gets_a_job`, `attestations_verify_and_refuse_with_typed_codes`, `a_full_committee_and_the_two_thirds_floor_each_fit_every_step_under_the_cap` (341 of 512 refused `E7205`); *testnet* slot not covered `E7207` [`372b61d3…`](https://explorer.testnet.lez.logos.co/transaction/372b61d363f7568795d6ba2423b4323e342be422e0fcc706a710c9f9276fde8b), unrecorded header `E7292` [`24a52ad5…`](https://explorer.testnet.lez.logos.co/transaction/24a52ad5c32072a10591334acd40ce6a8834002756a99bc610c5678453d945eb), another chain `E7209` (F.5); *local* `E7205`, `E7203`, `E7202` | The update-side refusals are not sent on the public testnet |
| Verification Security #3 | No verification reachable through a `ProgramId` in mutable state; migration documented; consumers told the same rule | Partial | Verification is compiled into `sextant_lc`; `erc20_receiver` names it in its receiver PDA's seed, fixed at creation ([`CONSUMER.md`](CONSUMER.md)) | The migration mechanism and the consumer rule, written down (M4) |
| Verification Security #4 | Failure modes of a compromised or colluding committee, and consumer-side bounds | Planned in M4 | | In the trust-assumptions document |
| Verification Security #5 | User and developer docs state the trustless model and the liveness-only role of off-chain participants | Planned in M4 | | |
| Verification Security #6 | An update is accepted on validity alone, never on the submitter's identity | Met | No signer check (`programs/sextant/src/lib.rs`); *executor* fresh accounts on every step, invalid updates refused (`a_fabricated_update_never_gets_a_job`) | |

## Soft requirements

Not counted below.

| ID | requirement | status | evidence | remaining work |
|---|---|---|---|---|
| Soft #1 | Recorded-statement account sharing one core with the direct path | Planned in M2 | | |
| Soft #2 | Batching several attestations over one header | Planned in M2 | | |
| Soft #3 | Historical state under older headers | Planned in M2 | | |
| Soft #4 | Predicates over several attested values in one statement | Partial | A query carries several predicates, all of which must hold (`core/src/statement.rs`); `erc20_receiver` uses five over one log | Values from several proofs under one header (M2) |
| Soft #5 | Operator incentive that keeps submission permissionless | Planned in M3 | | |

## Platform dependencies and licence

Not counted below.

| item | status | evidence | remaining work |
|---|---|---|---|
| Event emission (LP-0012) | Partial | `Begin` and `Miller` emit `JobStep`, `Finish` emits `Advanced`; `Attest` emits nothing by design (`programs/sextant/src/lib.rs`) | `Init` emits none; no test reads the events (M1) |
| Ethereum access through the Logos Ethereum core module | Planned in M3 | Vectors fetched from public endpoints (`scripts/fetch-vectors.py`); the module's coverage and gaps in [`ETH-CORE-MODULE.md`](ETH-CORE-MODULE.md) | Light-client objects, `eth_getProof` and `verifyCheckpoint` through the module |
| MIT and Apache-2.0 | Met | `LICENSE-MIT`, `LICENSE-APACHE` | |

## Count

59 hard requirements: Functionality 15, Usability 6, Reliability 12,
Performance 9, Supportability 11, Verification Security 6.

| status | count |
|---|---:|
| Met | 19 |
| Partial | 26 |
| Planned in M3 | 7 |
| Planned in M4 | 6 |
| Planned in M5 | 1 |
