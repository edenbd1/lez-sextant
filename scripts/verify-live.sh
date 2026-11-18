#!/usr/bin/env bash
# Re-check the unattended light-client run in evidence/live-run/ (scripts/live-follow.py).
#
#   scripts/verify-live.sh                       offline: replay and compare
#   scripts/verify-live.sh --online              also check the finalized headers against
#                                                the beacon chain and the last execution
#                                                block against an execution endpoint
#   scripts/verify-live.sh --online --beacon-sepolia URL --exec-sepolia URL ...
#                                                other endpoints (e.g. scripts/rpc-archive.py
#                                                serving a recording)
#
# What is checked, per chain directory:
# - the replay: host/src/bin/follow (sextant-core, the verifier the sextant_lc guest
#   runs) from the bootstrap through every update in updates/ gives exactly the
#   committed verdicts.jsonl, and ends in the committed state.json;
# - completeness: every update fetch.jsonl says was saved is in updates/;
# - no update was refused (a refused one would mean a beacon node served something
#   that does not verify), and the store advanced;
# - (--online) the bootstrap root, and the root of every header the replay finalized,
#   is the canonical beacon block root at its slot; the last finalized execution block
#   has the state root the store holds.
set -uo pipefail
cd "$(dirname "$0")/.."
ONLINE=0
beacon_sepolia=https://lodestar-sepolia.chainsafe.io; exec_sepolia=https://ethereum-sepolia-rpc.publicnode.com
beacon_mainnet=https://lodestar-mainnet.chainsafe.io; exec_mainnet=https://ethereum-rpc.publicnode.com
while [ $# -gt 0 ]; do
  case "$1" in
    --online) ONLINE=1; shift ;;
    --beacon-sepolia) beacon_sepolia="${2:?}"; shift 2 ;;
    --exec-sepolia) exec_sepolia="${2:?}"; shift 2 ;;
    --beacon-mainnet) beacon_mainnet="${2:?}"; shift 2 ;;
    --exec-mainnet) exec_mainnet="${2:?}"; shift 2 ;;
    *) echo "usage: $0 [--online] [--beacon-<chain> URL] [--exec-<chain> URL]" >&2; exit 2 ;;
  esac
done
FOLLOW="${FOLLOW_BIN:-host/target/release/follow}"
if [ -z "${FOLLOW_BIN:-}" ]; then
  cargo build --quiet --release --manifest-path host/Cargo.toml --bin follow || exit 1
fi
fail=0
for dir in evidence/live-run/*/; do
  chain=$(basename "$dir"); id=$([ "$chain" = mainnet ] && echo 1 || echo 11155111)
  echo "== $chain ($dir)"
  "$FOLLOW" "${dir%/}" "$id" > "/tmp/verify-live-$chain.jsonl" || { echo "  FAIL replay"; fail=1; continue; }
  python3 - "$dir" "/tmp/verify-live-$chain.jsonl" "$ONLINE" "$(eval echo "\$beacon_$chain")" "$(eval echo "\$exec_$chain")" <<'PY' || fail=1
import json, os, sys, urllib.request
d, replay, online, beacon, execu = sys.argv[1], sys.argv[2], sys.argv[3] == "1", sys.argv[4], sys.argv[5]
bad = 0
def ok(c, msg):
    global bad
    print("  %s %s" % ("ok  " if c else "FAIL", msg)); bad += 0 if c else 1
lines = [json.loads(l) for l in open(replay) if l.startswith("{")]
final, verdicts = lines[-1], lines[:-1]
committed = [json.loads(l) for l in open(os.path.join(d, "verdicts.jsonl"))]
# The run may have ticked since verdicts.jsonl was last written: compare the common prefix.
ok(verdicts[:len(committed)] == committed, "replay reproduces the %d committed verdicts" % len(committed))
st = json.load(open(os.path.join(d, "state.json")))
replayed_at = {l["file"]: l for l in verdicts}
last_committed = [l for l in committed if "store" in l][-1]["store"]
ok(all(st[k] == last_committed[k] for k in ("finalized_slot", "finalized_root", "block_number", "state_root")),
   "state.json is the store after the last committed verdict (slot %s)" % st["finalized_slot"])
saved = []
for l in open(os.path.join(d, "fetch.jsonl")):
    saved += json.loads(l).get("saved", [])
present = set(os.listdir(os.path.join(d, "updates")))
ok(all(f in present for f in saved), "all %d updates fetch.jsonl records as saved are in updates/" % len(saved))
refused = [l for l in verdicts if l["verdict"] == "refused"]
ok(not refused, "no update refused (%d applied, %d unchanged)" % (sum(l["verdict"] == "applied" for l in verdicts),
   sum(l["verdict"] == "unchanged" for l in verdicts)))
boot = verdicts[0]["store"]
ok(final["store"]["finalized_slot"] > boot["finalized_slot"] or len(verdicts) < 3,
   "the store advanced: slot %d -> %d, period %d -> %d" % (boot["finalized_slot"], final["store"]["finalized_slot"],
   boot["period"], final["store"]["period"]))
first = min(json.loads(l)["time"] for l in open(os.path.join(d, "fetch.jsonl")))
last = max(json.loads(l)["time"] for l in open(os.path.join(d, "fetch.jsonl")))
print("  run from %s to %s" % (first, last))
if online:
    def get(u):
        r = urllib.request.Request(u, headers={"accept": "application/json", "user-agent": "sextant-verify-live"})
        return json.loads(urllib.request.urlopen(r, timeout=60).read())
    def rpc(u, m, p):
        r = urllib.request.Request(u, data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                                   headers={"content-type": "application/json", "user-agent": "sextant-verify-live"})
        return json.loads(urllib.request.urlopen(r, timeout=60).read())["result"]
    roots = {}
    for l in verdicts:
        if "store" in l:
            roots[l["store"]["finalized_slot"]] = l["store"]["finalized_root"]
    good = 0
    for slot, root in sorted(roots.items()):
        r = get("%s/eth/v1/beacon/headers/%d" % (beacon, slot))["data"]["root"]
        good += r == root
        if r != root:
            print("  FAIL slot %d: replay finalized %s, the beacon chain has %s" % (slot, root, r)); bad += 1
    ok(good == len(roots), "%d finalized headers are the canonical beacon blocks at their slots (%s)" % (len(roots), beacon))
    b = rpc(execu, "eth_getBlockByNumber", [hex(final["store"]["block_number"]), False])
    ok(b["stateRoot"] == final["store"]["state_root"], "execution block %d has the state root the store holds (%s)" % (final["store"]["block_number"], execu))
sys.exit(1 if bad else 0)
PY
done
echo "== $([ $fail = 0 ] && echo PASS || echo FAIL)"
exit $fail
