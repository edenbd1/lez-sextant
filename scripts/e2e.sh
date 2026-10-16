#!/usr/bin/env bash
# Drive sextant_lc on a LEZ v0.3 sequencer from the committed mainnet vectors,
# the way executor-tests/tests/program.rs drives it through lee::V03State:
# deploy, Init from the checkpoint, the three transactions of each
# sync-committee update, consumer attestations, and refusals that must fail.
#
#   SCENARIO=full     (default) every update the vectors hold (periods 1881 to
#                     1884), attestations against the last header, and the
#                     refusals that need applied steps first (a resigned
#                     update refused at Finish, another chain's instance)
#   RESUME=1          continue the run recorded in $OUT (same SEXTANT_PROGRAM and
#                     INSTANCE) from update 1's Miller step, appending to it
#   SCENARIO=testnet  what the public testnet payer can fund (a refusal is
#                     charged its whole gas limit): Init, update 1 (period
#                     1881), attestations against the checkpoint's header, the
#                     refusals that cost an Attest or an Init, and the duplicate
#                     Finish if the balance still covers it
#
# Needs: cli/target/release/sextant, LEE_WALLET_HOME_DIR holding PAYER's key,
# and DEPLOY=1 or SEXTANT_PROGRAM. Writes $OUT, one line per transaction:
#   label expected verdict block tx attempts precheck gas_limit charged_gas
# On LEZ v0.3 a public transaction the program refuses is still included in a
# block: it changes nothing, and its payer is charged the whole gas limit. An
# accepted one is charged the cycles it used. So every transaction here is
# included, and its verdict is read back from the chain: `applied` (charged
# exactly the pre-checked gas, below its limit, and for Init/Begin/Miller/
# Finish the accounts changed) or `reverted` (charged exactly its limit,
# nothing changed). Refusals are sent with the gas limit of the honest
# instruction of the same kind, so running out of gas cannot explain them.
set -uo pipefail
cd "$(dirname "$0")/.."

: "${LEE_WALLET_HOME_DIR:?the v0.3 wallet home holding the key of the payer}"
: "${PAYER:?base58 id of the account that pays every fee}"
export SEXTANT_RPC="${RPC:-http://127.0.0.1:3040}" SEXTANT_PAYER="$PAYER"
CLI="${CLI:-cli/target/release/sextant}"
OUT="${OUT:-evidence/local/e2e.tsv}"
SCENARIO="${SCENARIO:-full}"
INSTANCE="${INSTANCE:-mainnet-$(date -u +%m%d%H%M)}"
WAIT_APPLY="${WAIT_APPLY:-240}"
WAIT_REFUSE="${WAIT_REFUSE:-60}"
export SEXTANT_INSTANCE="$INSTANCE"
mkdir -p "$(dirname "$OUT")"
jget() { python3 -c 'import json,sys
v=json.loads(sys.argv[1])
for k in sys.argv[2].split("."): v=(v or {}).get(k)
print("" if v is None else v)' "$1" "$2"; }

if [ "${DEPLOY:-0}" = 1 ]; then
  line="$("$CLI" --wait "$WAIT_APPLY" deploy | grep '^{' | tail -1)"
  echo "$line"
  SEXTANT_PROGRAM="$(jget "$line" header)"
  DEPLOYED="$line"
fi
: "${SEXTANT_PROGRAM:?deploy first (DEPLOY=1) or set SEXTANT_PROGRAM}"
export SEXTANT_PROGRAM
IMG="$("$CLI" image-id)"; IMGID="$(jget "$IMG" image_id)"
if [ "${RESUME:-0}" = 1 ]; then
  # Continue a run whose manifest is $OUT: the final-state lines it ends with are
  # superseded by the ones this part writes.
  [ -f "$OUT" ] || { echo "RESUME=1 needs the manifest $OUT"; exit 2; }
  grep -v '^# final ' "$OUT" > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
  echo "# resumed ($SCENARIO) against $SEXTANT_RPC, $(date -u +%Y-%m-%dT%H:%M:%SZ), $IMGID" | tee -a "$OUT"
else
  {
  echo "# sextant_lc run ($SCENARIO) against $SEXTANT_RPC, $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "# program $SEXTANT_PROGRAM $IMGID"
  echo "# binary $IMG"
  echo "# payer $PAYER instance $INSTANCE"
  } | tee "$OUT"
fi
if [ -n "${DEPLOYED:-}" ]; then
  python3 - "$DEPLOYED" >> "$OUT" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
for s in d.get("sent", []):
    what, h = s.split(":")
    print(f"# deploy {what} {h}")
PY
fi

fail=0
check() { # label got want
  if [ "$2" = "$3" ]; then echo "  ok  $1: $2"; echo "# check ok: $1 = $2" >> "$OUT"
  else echo "  FAIL $1: got $2, want $3"; echo "# check FAIL: $1: $2 != $3" >> "$OUT"; fail=1; fi
}
attempts_of() { python3 -c 'import json,sys;print(",".join(json.loads(sys.argv[1]).get("attempts") or []) or "-")' "$1"; }
# step label expected(applied|E72xx) -- cli args...
step() {
  local label="$1" expect="$2"; shift 3
  local line verdict pre want wait="$WAIT_APPLY" force=()
  if [ "$expect" != applied ]; then wait="$WAIT_REFUSE"; force=(--force); fi
  line="$("$CLI" --label "$label" --wait "$wait" ${force[@]+"${force[@]}"} "$@" 2>/tmp/sextant-e2e.err | grep '^{' | tail -1)"
  [ -n "$line" ] || line="$(python3 -c 'import json,sys;print(json.dumps({"verdict":"error","error":sys.stdin.read().strip()[-300:]}))' < /tmp/sextant-e2e.err)"
  echo "$line"
  verdict="$(jget "$line" verdict)"
  pre="$(jget "$line" precheck.gas)"; [ -n "$pre" ] && pre="gas=$pre" || pre="$(jget "$line" precheck.refused | cut -c1-5)"
  want=applied; [ "$expect" = applied ] || want=refused
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$label" "$want" "$verdict" "$(jget "$line" block)" "$(jget "$line" tx)" \
    "$(attempts_of "$line")" "${pre:--}" "$(jget "$line" gas_limit)" "$(jget "$line" block_gas_exec)" >> "$OUT"
  echo "# line $label $line" >> "$OUT"
  case "$expect:$verdict:$pre" in
    (applied:applied:gas=*) echo "  ok  $label: applied ($pre)" ;;
    (E72*:reverted:"$expect") echo "  ok  $label: refused ($pre), included and charged its whole limit, nothing changed" ;;
    (*) echo "  FAIL $label: $verdict ($pre), expected $expect"; fail=1 ;;
  esac
}
show() { "$CLI" show; }
IDS="$("$CLI" ids)"
INST="$(jget "$IDS" instance)"; CKPT="$(jget "$IDS" checkpoint_header)"; FINAL="$(jget "$IDS" final_header)"
[ "${RESUME:-0}" = 1 ] || echo "# accounts instance $INST checkpoint_header $CKPT final_header $FINAL" >> "$OUT"

if [ "${RESUME:-0}" != 1 ]; then
echo "== 1. Init from the committed mainnet bootstrap (slot 15,409,152), once"
step init applied -- init
check "instance at the checkpoint" "$(jget "$(show)" slot)" 15409152
step init-again E7291 -- init

echo "== 2. the consumer check, against the checkpoint's header (execution block 26,170,219)"
step attest-checkpoint-transfer-log applied -- attest --at checkpoint --kind log
step attest-checkpoint-weth-balance applied -- attest --at checkpoint --kind storage
step attest-wrong-chain E7209 -- attest --at checkpoint --kind log --chain-id 11155111
step attest-predicate-false E7208 -- attest --at checkpoint --kind log --negate
step attest-slot-not-covered E7207 -- attest --at checkpoint --kind storage --wrong-slot
step attest-unrecorded-header E7292 -- attest --at checkpoint --kind log --slot-offset 1

if [ "$SCENARIO" = full ]; then
  echo "== 3. fabricated updates never open a job"
  step begin-below-participation E7205 -- begin 1 --tamper participation
  step begin-altered-signature E7203 -- begin 1 --tamper bitflip
  step begin-header-not-finalized E7202 -- begin 1 --tamper moved
fi

fi

echo "== 4. update 1 (period 1881, committee handoff): Begin, Miller, Finish"
[ "${RESUME:-0}" = 1 ] || step u1-begin applied -- begin 1
step u1-miller applied -- miller 1
step u1-finish applied -- finish 1
# Update 1's finalized header is the checkpoint's own: what it adds is the
# verified handoff to the period-1882 committee, which update 2 needs.
S="$(show)"
check "after update 1: finalized slot unchanged" "$(jget "$S" slot)" 15409152
check "after update 1: next committee recorded" "$( [ -n "$(jget "$S" next_committee)" ] && echo yes || echo no)" yes

echo "== 5. the same update again: nothing is applied twice"
if [ "$SCENARIO" = full ]; then
  step u1-begin-again E7293 -- begin 1
  step u1-miller-again E7294 -- miller 1
  step u1-finish-again E7294 -- finish 1
elif [ "$("$CLI" balance)" -gt "${FINISH_AGAIN_MIN:-45000000}" ]; then
  step u1-finish-again E7294 -- finish 1
else
  echo "  (skipped: the payer cannot fund a refused Finish, charged its whole 4.1M gas limit)"
  echo "# skipped u1-finish-again: payer balance $("$CLI" balance)" >> "$OUT"
fi

if [ "$SCENARIO" = full ]; then
  echo "== 6. a real signature over another header passes Begin and Miller, and is refused at Finish"
  step u2-resigned-begin applied -- begin 2 --tamper resigned
  step u2-resigned-miller applied -- miller 2 --tamper resigned
  step u2-resigned-finish E7203 -- finish 2 --tamper resigned
  check "instance unmoved by the forged update" "$(jget "$(show)" digest)" "$(jget "$S" digest)"

  echo "== 7. updates 2 to 4 (periods 1882, 1883 with handoffs; 1884 finality only)"
  for n in 2 3 4; do
    step "u$n-begin" applied -- begin $n
    step "u$n-miller" applied -- miller $n
    step "u$n-finish" applied -- finish $n
  done
  S="$(show)"
  check "final period" "$(jget "$S" period)" 1884
  check "final execution block" "$(jget "$S" block_number)" 26197200

  echo "== 8. the consumer check against the last header (execution block 26,197,200)"
  step attest-final-transfer-log applied -- attest --at final --kind log
  step attest-final-weth-balance applied -- attest --at final --kind storage
  step attest-final-wrong-chain E7209 -- attest --at final --kind log --chain-id 11155111

  echo "== 9. another chain's configuration: a mainnet update cannot advance it"
  WRONG="wrong-chain-${INSTANCE#mainnet-}"
  SEXTANT_INSTANCE="$WRONG" step wrong-chain-init applied -- --wrong-chain init
  SEXTANT_INSTANCE="$WRONG" step wrong-chain-u1-begin applied -- --wrong-chain begin 1
  SEXTANT_INSTANCE="$WRONG" step wrong-chain-u1-miller applied -- --wrong-chain miller 1
  SEXTANT_INSTANCE="$WRONG" step wrong-chain-u1-finish E7203 -- --wrong-chain finish 1
  check "wrong-chain instance unmoved" "$(jget "$(SEXTANT_INSTANCE="$WRONG" "$CLI" show)" slot)" 15409152
fi

echo "== final state: the instance and the header records, as the run left them"
python3 - "$SEXTANT_RPC" "$SEXTANT_PROGRAM" "$INST" "$CKPT" "$FINAL" "$SCENARIO" >> "$OUT" <<'PY'
import hashlib, json, sys, urllib.request
rpc, prog, *accts = sys.argv[1:6]
scenario = sys.argv[6]
def shard(a):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "getAccount", "params": [a]}).encode()
    r = json.load(urllib.request.urlopen(urllib.request.Request(rpc, body, {"Content-Type": "application/json"}), timeout=25))
    return bytes((((r.get("result") or {}).get("data") or {}).get("shards") or {}).get(prog, []))
for a in accts:
    b = shard(a)
    if b or a == accts[0]:
        print(f"# final {a} {len(b)} {hashlib.sha256(b).hexdigest()}")
PY
grep '^# final' "$OUT"
echo "== $( [ $fail = 0 ] && echo PASS || echo FAIL ): $(grep -cv '^#' "$OUT") transactions in $OUT"
exit $fail
