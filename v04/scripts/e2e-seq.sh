#!/usr/bin/env bash
# sextant_lc on a local LEZ v0.4.0-rc3 standalone sequencer (mock Bedrock):
#   1. a sequencer home from LEZ's networks/local.json, its genesis funding the
#      driver's fee payer (seq_drive pubkey), 2 s blocks, no gossip; the
#      sequencer runs with RISC0_DEV_MODE=0, so it accepts no fake receipt;
#   2. seq_drive deploy: v04/artifacts/sextant_lc.bin through the program loader;
#   3. seq_drive run: Init from the Sepolia checkpoint of vectors/sepolia-v04,
#      a stale mainnet checkpoint refused by the sequencer's clock, attacks on the
#      first update (a tampered signature refused at Finish, participation below
#      the floor at Begin), every update (three handoffs and a finality update,
#      each Begin, Miller, Finish), replays, attestations and their refusals;
#      every block saved;
#   4. seq_drive private: a second instance, its update 1 as ONE
#      privacy-preserving transaction (the whole verification, pairing included,
#      proven client-side, about 30 minutes with RISC0_DEV_MODE=0) paying its fee
#      in-proof from a private payer funded at genesis, then a private
#      attestation against that instance's record index;
#   5. seq_drive verify: every verdict re-read from the blocks, every
#      public transaction replayed on rc3's state machine, every private one's
#      receipt verified against the privacy circuit, the instances and the
#      header records read back against the native verifier.
# Needs SEQ (the sequencer_service binary of logos-execution-zone v0.4.0-rc3,
# built with --features standalone) and LEZ (that checkout, for networks/local.json).
#   SEQ=... LEZ=... v04/scripts/e2e-seq.sh [RUN]
# STEPS (default "run private") picks the drives; RISC0_DEV_MODE=1 (sequencer
# and prover) checks the flow with fake receipts in minutes.
# Nothing here reaches a public network.
set -euo pipefail
cd "$(dirname "$0")/../.."
: "${SEQ:?set SEQ to the v0.4.0-rc3 sequencer_service binary (standalone)}"
: "${LEZ:?set LEZ to the logos-execution-zone v0.4.0-rc3 checkout}"
RUN="${1:-${TMPDIR:-/tmp}/sextant-v04-e2e}"
PORT="${PORT:-3078}"; METRICS_PORT="${METRICS_PORT:-9478}"
export RISC0_DEV_MODE="${RISC0_DEV_MODE:-0}"
STEPS="${STEPS:-run private}"
rm -rf "$RUN"; mkdir -p "$RUN"
# The binary under test, copied so a rebuild during the run cannot change it.
cp "${SEXTANT_BIN:-v04/artifacts/sextant_lc.bin}" "$RUN/sextant_lc.bin"
export SEXTANT_BIN="$RUN/sextant_lc.bin"
DRIVE=(cargo run -q --release -j "${JOBS:-4}" --manifest-path v04/executor-tests/Cargo.toml --bin seq_drive --)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

PAYER=$("${DRIVE[@]}" pubkey)
"$SEQ" setup "$RUN/seq" --config "$LEZ/lez/sequencer/service/networks/local.json" \
  --funding-public-key 2e03b2eff5a45478e7e79668d2a146cf2c5c7925bce927f2b1c67f2ab4fc0d26 --create-channel > "$RUN/setup.log"
python3 - "$RUN/seq/sequencer_config.json" "$PAYER" "$METRICS_PORT" <<'PY'
import json, sys
p, payer, metrics = sys.argv[1:]
c = json.load(open(p))
c["block_create_timeout"] = "2s"
c["metrics_listen_address"] = f"127.0.0.1:{metrics}"
c["gossip"] = None
c["genesis"]["actions"][0]["supply_account"]["recipient"] = {"identified": {"key": payer}}
# The genesis keeps local.json's two private supplies: the private path's fee
# payers (seq_drive payers), whose pending credits its transactions claim.
json.dump(c, open(p, "w"), indent=1)
PY
RUST_LOG=info,risc0_zkvm=warn,kameo=warn "$SEQ" start "$RUN/seq" --rpc-listen-address "127.0.0.1:$PORT" > "$RUN/sequencer.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 60); do
  curl -sf -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"checkHealth","params":[]}' "http://127.0.0.1:$PORT" > /dev/null && break
  sleep 1
done
echo "# sequencer up on $PORT (RISC0_DEV_MODE=$RISC0_DEV_MODE)"
"${DRIVE[@]}" deploy "http://127.0.0.1:$PORT" "$RUN"
for step in $STEPS; do
  "${DRIVE[@]}" "$step" "http://127.0.0.1:$PORT" "$RUN" | tee "$RUN/$step.txt"
done
"${DRIVE[@]}" verify "http://127.0.0.1:$PORT" "$RUN" | tee "$RUN/verify.txt"
echo "# done: $RUN/manifest.tsv, $RUN/verify.txt, $RUN/blocks/"
