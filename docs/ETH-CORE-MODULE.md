# The Logos Ethereum core module, and what Sextant takes from it

RFP-021 requires that "any Ethereum-side interaction, including fetching
headers, update material, and inclusion proofs, must use the Logos Ethereum
core module, including its verified proxy features". That module is
[`logos-co/logos-verified-proxy-module`](https://github.com/logos-co/logos-verified-proxy-module)
(`verified_proxy_module`, v0.1.4, read at `68a3543`, 2026-10-14). It wraps
Nimbus' `libverifproxy` (`status-im/nimbus-eth1` pinned at `f7bb258`), the C
library form of `nimbus_verified_proxy`.

This note records what the module exposes today, what Sextant's update daemon
and CLI need from it, the gaps, and how we close them.

## What the module is

- An in-process Nimbus beacon light client. It is anchored on a configured
  `trustedBlockRoot` and syncs forward. Every `eth_*` answer from an untrusted
  execution provider is verified against the execution header the light client
  has verified. Networks: `mainnet`, `sepolia`, `hoodi`. OP-Stack networks
  (`op_*`) are optional.
- Its Logos API (`verified_proxy_impl.h`): `configure`, `getConfig`,
  `defaultConfig(network)`, `start`, `stop`, `ok`, `status`,
  `supportedNetworks`, `fetchFinalizedRoot(beaconUrl)`, `rpc(method, params)`,
  and 30 typed `eth*` wrappers plus 30 `op*` mirrors. It emits
  `proxyStarted`, `proxyStopped` and `proxyStateChanged`. All calls are
  synchronous and bounded by `queueTimeoutMs + callTimeoutMs`.
- It also has an optional loopback JSON-RPC endpoint (`httpServer`,
  127.0.0.1:8545). Requests sent there go through the same verified path.
- The method table (`tools/rpc_methods.json`, generated from the library's
  dispatch) has 31 `eth_*` methods: `chainId`, `blockNumber`, `syncing`,
  `getBalance`, `getStorageAt`, `getTransactionCount`, `getCode`,
  `getBlockByHash/Number`, the uncle and transaction-count methods,
  `getTransactionBy*`, `call`, `createAccessList`, `estimateGas`,
  `getBlockReceipts`, `getTransactionReceipt`, `getLogs`, the filter methods,
  the fee methods, and `sendRawTransaction`.

### How a Logos module consumes it

The pattern already in production is `logos-evm-eth-rpc-module`
(`eth_rpc_module`). It declares `verified_proxy_module` as an optional
dependency in `metadata.json` and calls it through the generated typed client:
`verified_proxy_module::VerifiedProxyModuleClient::new().rpc_with_timeout(method, params, budget)`
for calls, and `status_with_timeout` for the readiness gate. `rpc` answers a
`{success, value, error}` envelope, and `status` answers the bare object.
Sextant's Logos module (Usability #1, #3) uses the same client. The headless
daemon does the same through `logoscore`, or points a plain JSON-RPC client at
the module's loopback endpoint.

### Building and running it on macOS

It is a Nix flake (`nativeSystems` includes `aarch64-darwin`):

```console
~/logos-monitor/bin/nixb .#unit-tests   # mocked libverifproxy, fast
~/logos-monitor/bin/nixb .#default      # the plugin; builds libverifproxy (Nim 2.2.12) from nimbus-eth1 f7bb258, ~25 min cold
lm methods ./result/lib/verified_proxy_module_plugin.so
logoscore call verified_proxy_module configure 'json:{"network":"sepolia","trustedBlockRoot":"0x…"}'
logoscore call verified_proxy_module start
logoscore call verified_proxy_module ethGetBlockByNumber finalized false
```

Its doc-test (`doctests/verified-proxy-runtime.test.yaml`) does exactly this
against live Sepolia (`lodestar-sepolia.chainsafe.io` plus
`ethereum-sepolia-rpc.publicnode.com`). It passed in CI on 2026-10-14, which
was after Sepolia's Gloas fork (see below). The module therefore follows a
post-Gloas testnet today. We have not built it locally in this pass: build it
only via `nixb`, one Nix build at a time.

## What Sextant needs, against what the module gives

| Sextant needs | Who uses it | Through the module today? |
|---|---|---|
| `LightClientBootstrap(root)` | `Init` (CLI) | **No.** The library fetches it internally (beacon transport endpoint `getLightClientBootstrap`) and verifies it against `trustedBlockRoot`, but no method returns it. |
| `LightClientUpdate`s by range | daemon, every handoff | **No.** Internal only (`getLightClientUpdatesByRange`). |
| `LightClientFinalityUpdate` | daemon | **No.** Internal only (`getLightClientFinalityUpdate`). There is no exported getter for the finalized slot either (module README, "Known limitations"). |
| Finalized execution block (number, hash, `stateRoot`, `receiptsRoot`) | CLI, to pick the block an attestation is made at | **Yes.** `ethGetBlockByNumber("finalized", false)` is verified against the light client's header. |
| RLP execution header (Gloas, see below) | daemon, with each update | **Yes, indirectly.** `ethGetBlockByHash(hash, false)` is verified; the header is re-encoded from its fields and must hash to `hash` (`scripts/fetch-vectors.py` does this). |
| `eth_getProof` (account plus storage nodes) | CLI, storage attestations | **No.** It is not in the method table. The library calls `eth_getProof` itself to answer `eth_getStorageAt`, `eth_getBalance` and `eth_getCode`, then returns only the verified value and drops the nodes. |
| Block receipts, to build a receipt proof | CLI, log attestations | **Yes.** `ethGetBlockReceipts(blockTag)` is verified (the library recomputes `receiptsRoot`). The receipt-trie proof is then built locally (`scripts/receipt_proof.py`) and re-checked against the same root. |
| Checkpoint check (F.9: anyone can verify an instance's checkpoint against public sources) | consumers, UIs | **No.** `fetchFinalizedRoot` asks one beacon node for its finalized root and is documented as "not a trust anchor". |

In short, the module serves headers, receipts and storage values with
verification. It does not expose the two things Sextant's guest consumes: the
consensus-layer light-client objects and raw `eth_getProof` nodes.

## The extension point that already exists

`libverifproxy`'s C ABI (`nimbus_verified_proxy/library/verifproxy.h` at
`f7bb258`) lets the host supply the transports:

```c
Context *startVerifProxy(char *configJson,
                         ExecutionTransportProc executionTransport,
                         BeaconTransportProc beaconTransport);
/* beaconCtxEndpoint(): "getLightClientBootstrap" {"block_root"} |
   "getLightClientUpdatesByRange" {"start_period","count"} |
   "getLightClientOptimisticUpdate" | "getLightClientFinalityUpdate";
   the response is the beacon-API JSON (RestJson-decoded by the library). */
```

The module passes `nullptr, nullptr` (`proxy_runtime.cpp:367`), so the library
uses its built-in HTTP clients. If the module supplies a beacon transport, it
sees every bootstrap, update and finality update the light client consumes, as
beacon-API JSON. That is the format Sextant's host already decodes
(`host/src/lib.rs`). A module-supplied execution transport would also see the
`eth_getProof` calls the library makes for its own verification.

## How we close the gap (deliverable, upstreamed as PRs to the module)

1. **Light-client objects.** Add `lightClientBootstrap(blockRoot)`,
   `lightClientUpdatesByRange(startPeriod, count)` and
   `lightClientFinalityUpdate()`. They are served from a module-supplied
   `BeaconTransportProc` that performs the GET against the configured
   `beaconApiUrls` (the module already links curl for `fetchFinalizedRoot`)
   and caches what the light client accepted. A caller then receives the
   objects that the module's own light client verified, not a second
   unverified fetch. Sextant's program re-verifies them anyway (sync-committee
   signature, handoff and finality branch). This gives the safety; the module
   gives the RFP's single Ethereum access path and the shared endpoint
   configuration.
2. **`ethGetProof(address, slots, blockTag)`.** The module returns the raw
   proof only after checking `keccak(accountProof[0])` against the verified
   header's `stateRoot` (and the slot value against `eth_getStorageAt`). The
   cleaner upstream form is an `eth_getProof` method in Nimbus'
   `engine/rpc_frontend.nim`. The engine already fetches and verifies that
   proof for `eth_getStorageAt`.
3. **`verifyCheckpoint(root)` (F.9).** This answers whether `root` is a
   finalized block on the chain this module's light client follows. The light
   client should be anchored on a root obtained independently of the instance
   under review.
4. **Sextant side.** The update daemon is a Logos module that calls 1 and the
   verified `ethGetBlockByHash`. The CLI calls 2, `ethGetBlockReceipts` and
   `ethGetBlockByNumber("finalized")`. Endpoint configuration (consensus and
   execution URLs, Usability #3) is the module's own `configure`.

Until 1 to 3 land, the daemon fetches the light-client objects and proofs from
the same `beaconApiUrls` and `executionApiUrls` the module is configured with
(`getConfig`). It cross-checks the result against the module's verified
`ethGetBlockByNumber("finalized")`, so a disagreement surfaces as an error
before anything is submitted.

## Public testnets: Gloas is already live

Both RFP-eligible testnets are on, or about to reach, Gloas (ePBS, EIP-7732).
Gloas changes the light-client header:

| Chain | Fork now | Gloas (`GLOAS_FORK_EPOCH`) |
|---|---|---|
| Sepolia (11155111) | Gloas | epoch 353,024, 2026-10-06 13:53 UTC |
| Hoodi (560048) | Fulu | epoch 132,352, 2026-10-26 17:42 UTC |
| Mainnet | Fulu | not scheduled |

From Gloas, `LightClientHeader` carries `execution_block_hash` (the bid's
`parent_block_hash`, proven at gindex 2856 under `body_root`), not the
`ExecutionPayloadHeader`. The state-level gindices also move (EIP-7688):
finalized root 735, current committee 2945, next committee 2946. A program that
only knows the Electra shapes refuses every Gloas update. By the time LEZ
testnet 0.4 is up (Supportability #1), both testnets will be Gloas. See
`docs/DECISIONS.md` and `core/src/lc.rs` for how Sextant handles it: the chain
configuration carries the Gloas epoch, and a Gloas header comes with the RLP
execution header that hashes to its `execution_block_hash`.

## Endpoint notes (free public endpoints, 2026-10-16)

- `ethereum-sepolia-rpc.publicnode.com` and `1rpc.io/sepolia` refuse
  `eth_getProof` at the finalized block ("distance to target block exceeds
  maximum proof window"). The module README notes the same.
  `sepolia.gateway.tenderly.co` refuses it by number but serves it by
  `{"blockHash": …}` (EIP-1898).
- Sepolia bootstraps: `lodestar-sepolia.chainsafe.io` keeps only recent ones.
  `unstable.sepolia.beacon-api.nimbus.team` serves bootstraps for historical
  periods. `ethereum-sepolia-beacon-api.publicnode.com` (Lighthouse
  v8.3.0-rc.0) stopped serving light-client data at the last pre-Gloas slot.
- Hoodi: `ethereum-hoodi-beacon-api.publicnode.com` serves historical
  bootstraps. Lodestar agrees on every update; it differs only in checksummed
  address case.
