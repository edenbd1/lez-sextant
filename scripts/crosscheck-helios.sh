#!/usr/bin/env bash
# Cross-check the live run against an independent light client: replay each chain's
# bootstrap and updates (evidence/live-run/<chain>/) through Helios' consensus-core
# (a16z/helios 0.12.0, crosscheck-helios/) and require, file by file, the verdict
# Sextant's replay recorded in verdicts.jsonl, the same finalized header (slot,
# hash-tree root) and the same execution block (number, state root, receipts root).
# Then corrupt the first applied update as scripts/mutation-test-live.sh does and
# require Helios not to apply any of the corruptions either. Test-only: Helios is
# never part of the guest or the program.
#
#   scripts/crosscheck-helios.sh [DIR]    DIR holds sepolia/ and mainnet/ (default evidence/live-run)
set -uo pipefail
cd "$(dirname "$0")/.."
root="${1:-evidence/live-run}"
BIN="${CROSSCHECK_BIN:-${CARGO_TARGET_DIR:-crosscheck-helios/target}/release/crosscheck-helios}"
[ -n "${CROSSCHECK_BIN:-}" ] || cargo build --quiet --release --manifest-path crosscheck-helios/Cargo.toml || exit 1
fail=0
for chain in sepolia mainnet; do
  src="$root/$chain"
  [ -d "$src" ] || { echo "== $chain: no $src"; fail=1; continue; }
  echo "== $chain: Helios against Sextant's verdicts"
  if "$BIN" "$src" > "/tmp/crosscheck-$chain.jsonl"; then
    python3 - "/tmp/crosscheck-$chain.jsonl" <<'PY'
import json, sys
n = {}
last = None
for l in open(sys.argv[1]):
    j = json.loads(l); k = j.get("helios"); n[k] = n.get(k, 0) + 1
    if j.get("store"): last = j["store"]
print("  same verdict on every file:", ", ".join("%d %s" % (v, k) for k, v in sorted(n.items())))
print("  last finalized: slot %s root %s, execution block %s state root %s" % (
    last["finalized_slot"], last["finalized_root"], last["block_number"], last["state_root"]))
PY
  else
    grep DISAGREE "/tmp/crosscheck-$chain.jsonl"; echo "  FAIL: Helios and Sextant disagree"; fail=1; continue
  fi
  target=$(python3 -c 'import json,sys
for l in open(sys.argv[1]):
    j=json.loads(l)
    if j.get("verdict")=="applied": print(j["file"]); break' "$src/verdicts.jsonl")
  [ -n "$target" ] || { echo "  no applied update yet"; continue; }
  mut=$(mktemp -d); trap 'rm -rf "$mut"' EXIT
  caught=0; total=0
  mutate() {
    local label="$1" expr="$2"
    rm -rf "$mut/c"; cp -R "$src" "$mut/c"
    python3 - "$mut/c/updates/$target" "$expr" <<'PY'
import json, sys
p, expr = sys.argv[1], sys.argv[2]
j = json.load(open(p)); d = j["data"]
def flip(h, i=10):
    b = bytearray(bytes.fromhex(h[2:])); b[i] ^= 1; return "0x" + b.hex()
exec(expr)
json.dump(j, open(p, "w"))
PY
    total=$((total + 1))
    v=$("$BIN" "$mut/c" --only-helios | python3 -c 'import json,sys
t=sys.argv[1]
for l in sys.stdin:
    j=json.loads(l)
    if j.get("file")==t: print(j["helios"], j.get("error",""))' "$target")
    case "$v" in applied*) echo "    APPLIED  $label";; *) caught=$((caught + 1)); echo "    not applied  $label: $v";; esac
  }
  echo "  corrupting $target (the mutations of scripts/mutation-test-live.sh):"
  mutate "signature bit flipped"            'd["sync_aggregate"]["sync_committee_signature"]=flip(d["sync_aggregate"]["sync_committee_signature"])'
  mutate "participation bit flipped"        'b=bytearray(bytes.fromhex(d["sync_aggregate"]["sync_committee_bits"][2:])); b[0]^=1; d["sync_aggregate"]["sync_committee_bits"]="0x"+b.hex()'
  mutate "finalized state root changed"     'd["finalized_header"]["beacon"]["state_root"]=flip(d["finalized_header"]["beacon"]["state_root"])'
  mutate "finality branch changed"          'd["finality_branch"][0]=flip(d["finality_branch"][0])'
  mutate "attested header slot moved"       'd["attested_header"]["beacon"]["slot"]=str(int(d["attested_header"]["beacon"]["slot"])+1)'
  mutate "signature slot moved to next period" 'd["signature_slot"]=str((int(d["signature_slot"])//8192+1)*8192+5)'
  mutate "below participation (half the bits cleared)" 'b=bytearray(bytes.fromhex(d["sync_aggregate"]["sync_committee_bits"][2:])); b[:40]=bytes(40); d["sync_aggregate"]["sync_committee_bits"]="0x"+b.hex()'
  echo "  $caught of $total corruptions not applied by Helios"
  [ "$caught" = "$total" ] || fail=1
done
echo "== $( [ $fail = 0 ] && echo PASS || echo FAIL )"
exit $fail
