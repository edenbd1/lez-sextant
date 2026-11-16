#!/usr/bin/env bash
# scripts/verify-onchain.sh over every public testnet run, against
# evidence/archive/: every LEZ testnet JSON-RPC answer it reads, recorded from
# the public endpoint while it still served the runs (scripts/rpc-archive.py).
# The LEZ testnet is reset when it moves to 0.4; after that, this is how the
# same verifier, unchanged, re-checks the runs. Every transaction and block
# hash is still recomputed from the bytes; what the archive adds is only that
# the bytes are the ones the public endpoint served on the date in
# evidence/archive/RECORDED.
#
#   scripts/verify-archived.sh             re-check from the archive (offline)
#   scripts/verify-archived.sh --record    re-record it from the live endpoint
set -uo pipefail
cd "$(dirname "$0")/.."
A=evidence/archive
MODE=serve
case "${1:-}" in
  --record) MODE=record ;;
  "") ;;
  *) echo "usage: $0 [--record]" >&2; exit 2 ;;
esac
PORT="${LEZ_PORT:-8647}"
MANIFESTS=(evidence/testnet/run.tsv evidence/testnet-v2/run.tsv evidence/testnet-v2-sepolia/run.tsv
           evidence/testnet-v2-hoodi/run.tsv evidence/testnet-v2-sepolia-portage/run.tsv)
PID=
cleanup() { [ -n "$PID" ] && kill "$PID" 2>/dev/null || true; }
trap cleanup EXIT
mkdir -p "$A"
if [ $MODE = record ]; then
  T=$(mktemp -d)
  python3 scripts/rpc-archive.py record https://testnet.lez.logos.co "$T/lez.jsonl" "$PORT" & PID=$!
else
  python3 scripts/rpc-archive.py serve "$A/lez.jsonl.gz" "$PORT" & PID=$!
fi
sleep 2
fail=0
for m in "${MANIFESTS[@]}"; do
  echo "##### $m"
  scripts/verify-onchain.sh --manifest "$m" --rpc "http://127.0.0.1:$PORT" || fail=1
done
if [ $MODE = record ]; then
  if [ $fail = 0 ]; then
    sort -u "$T/lez.jsonl" | gzip -9n > "$A/lez.jsonl.gz"
    date -u +%Y-%m-%dT%H:%M:%SZ > "$A/RECORDED"
    echo "# recorded: $(zcat < $A/lez.jsonl.gz | wc -l | tr -d ' ') LEZ answers"
  else
    echo "# not recorded: the live re-check failed" >&2
  fi
fi
echo "##### $( [ $fail = 0 ] && echo PASS || echo FAIL ) ($MODE)"
exit $fail
