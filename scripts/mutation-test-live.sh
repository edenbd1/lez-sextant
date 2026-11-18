#!/usr/bin/env bash
# Mutation test for the live run's replay (host/src/bin/follow): corrupt a copy of
# a chain's directory in ways a lying beacon node could, and require the replay
# to refuse each one. A check never seen failing is not a check.
#
#   scripts/mutation-test-live.sh [sepolia|mainnet]   (default sepolia)
set -uo pipefail
cd "$(dirname "$0")/.."
chain="${1:-sepolia}"; id=$([ "$chain" = mainnet ] && echo 1 || echo 11155111)
FOLLOW="${FOLLOW_BIN:-host/target/release/follow}"
[ -n "${FOLLOW_BIN:-}" ] || cargo build --quiet --release --manifest-path host/Cargo.toml --bin follow || exit 1
src="evidence/live-run/$chain"; mut="evidence/.live-mutation-$chain"
trap 'rm -rf "$mut"' EXIT
# The first applied update: the one each mutation targets.
target=$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    j=json.loads(l)
    if j.get("verdict")=="applied": print(j["file"]); break' "$src/verdicts.jsonl")
[ -n "$target" ] || { echo "no applied update yet in $src"; exit 2; }
caught=0; total=0
mutate() { # label python-expression-on-d (the update's data) | special
  local label="$1" expr="$2"
  rm -rf "$mut"; cp -R "$src" "$mut"
  python3 - "$mut/updates/$target" "$expr" <<'PY'
import json, sys
p, expr = sys.argv[1], sys.argv[2]
j = json.load(open(p)); d = j["data"]
def flip(h, i=10):
    b = bytearray(bytes.fromhex(h[2:])); b[i] ^= 1; return "0x" + b.hex()
exec(expr)
json.dump(j, open(p, "w"))
PY
  total=$((total + 1))
  v=$("$FOLLOW" "$mut" "$id" | python3 -c 'import json,sys
t=sys.argv[1]
for l in sys.stdin:
    j=json.loads(l)
    if j.get("file")==t: print(j["verdict"], j.get("error","")); break' "$target")
  case "$v" in refused*) caught=$((caught + 1)); echo "  caught   $label: $v" ;; *) echo "  MISSED   $label: $v" ;; esac
}
echo "== $chain, mutating $target"
mutate "signature bit flipped"            'd["sync_aggregate"]["sync_committee_signature"]=flip(d["sync_aggregate"]["sync_committee_signature"])'
mutate "participation bit flipped"        'b=bytearray(bytes.fromhex(d["sync_aggregate"]["sync_committee_bits"][2:])); b[0]^=1; d["sync_aggregate"]["sync_committee_bits"]="0x"+b.hex()'
mutate "finalized state root changed"     'd["finalized_header"]["beacon"]["state_root"]=flip(d["finalized_header"]["beacon"]["state_root"])'
mutate "finality branch changed"          'd["finality_branch"][0]=flip(d["finality_branch"][0])'
mutate "attested header slot moved"       'd["attested_header"]["beacon"]["slot"]=str(int(d["attested_header"]["beacon"]["slot"])+1)'
mutate "signature slot moved to next period" 'd["signature_slot"]=str((int(d["signature_slot"])//8192+1)*8192+5)'
mutate "below participation (half the bits cleared)" 'b=bytearray(bytes.fromhex(d["sync_aggregate"]["sync_committee_bits"][2:])); b[:40]=bytes(40); d["sync_aggregate"]["sync_committee_bits"]="0x"+b.hex()'
echo "== $caught of $total caught"
[ "$caught" = "$total" ]
