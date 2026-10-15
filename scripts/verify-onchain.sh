#!/usr/bin/env bash
# Re-check a recorded run of sextant_lc against a LEZ v0.3 sequencer, from its
# manifest, with nothing but curl-level JSON-RPC (no wallet, no build).
#
#   scripts/verify-onchain.sh                                   # the public testnet run
#   scripts/verify-onchain.sh --manifest evidence/local/e2e.tsv --rpc http://127.0.0.1:3040
#
# A manifest is what scripts/e2e.sh writes: one line per transaction
#   label expected verdict block tx attempts precheck gas_limit charged_gas
# and comment lines, of which these are checked:
#   # program <header> <image-id>     the program_loader header names this ImageID
#   # deploy <what> <hash>            the deployment transaction resolves
#   # final <account> <len> <sha256>  the account's sextant_lc shard is these bytes now
#
# What is checked:
# - the header account's program_loader shard names the ImageID of the committed binary;
# - every transaction resolves by hash to a block (one found in another block than
#   recorded was moved by a block rewrite: reported, not failed);
# - what the chain charged it. On LEZ v0.3 a public transaction whose program
#   refuses is still included, changes nothing, and is charged its whole gas limit;
#   an accepted one is charged the cycles it used. The gas limit is read from the
#   transaction's own bytes, the charged gas from the `Distribute` summary of the
#   block's fee transaction (gas_used_exec, gas_used_stor). When gas_used_stor is
#   exactly this transaction's size, it is the block's only charged transaction
#   and gas_used_exec is its own: `applied` needs it equal to the recorded
#   pre-checked gas and below the limit, `refused` needs it equal to the limit.
#   A block shared with other charged transactions is reported as such, and the
#   transaction is then checked for inclusion only;
# - every `final` line: the instance and header records hold exactly the recorded bytes;
# - a random hash does not resolve, or the endpoint answers anything.
#
# Needs python3. Exits non-zero on any mismatch.
set -uo pipefail
cd "$(dirname "$0")/.."
MANIFEST="evidence/testnet/run.tsv"
RPC="https://testnet.lez.logos.co"
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) MANIFEST="${2:?}"; shift 2 ;;
    --rpc) RPC="${2:?}"; shift 2 ;;
    *) echo "usage: $0 [--manifest FILE] [--rpc URL]" >&2; exit 2 ;;
  esac
done
[ -f "$MANIFEST" ] || { echo "no manifest at $MANIFEST"; exit 3; }

python3 - "$MANIFEST" "$RPC" <<'PY'
import base64, hashlib, json, secrets, struct, sys, urllib.request

manifest, rpc = sys.argv[1], sys.argv[2]

def call(method, param):
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": [param]}).encode()
    req = urllib.request.Request(rpc, body, {"Content-Type": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.load(r)
        except Exception:
            if attempt == 2:
                raise

def block_of(tx):
    res = call("getTransaction", tx).get("result")
    if isinstance(res, list) and len(res) > 1:
        return str(res[1] if not isinstance(res[1], dict) else res[1].get("height"))
    return None

FEE = "2TsGdKDWTY92X4vSBZzjzemZpThhyqNEdZJj3xBrQ9AZ"  # fee_core::fee_account_id()
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def unb58(s):
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    return n.to_bytes(32, "big")

def u32(b, o):
    return struct.unpack_from("<I", b, o)[0]

def gas_limit_of(tx):
    # borsh LeeTransaction::Public(PublicTransaction { message: Message { program_account_id,
    # shard_selectors, nonces, instruction_data, fee: Option<FeeDeclaration { payer, gas_limit, .. }> }, .. })
    assert tx[0] == 0, "not a public transaction"
    o = 1 + 32
    o += 4 + 64 * u32(tx, o)
    o += 4 + 16 * u32(tx, o)
    o += 4 + u32(tx, o)
    assert tx[o] == 1, "a fee-exempt transaction"
    return struct.unpack_from("<Q", tx, o + 1 + 32)[0]

def fee_summary(block):
    # The block's fee transaction: program FEE, 4 shard selectors, no nonce, instruction
    # data borsh(Distribute { summary: { gas_used_exec: u64, gas_used_stor: u64, .. }, .. }).
    raw = base64.b64decode(call("getBlock", block)["result"])
    i = raw.find(unb58(FEE) + struct.pack("<I", 4))
    assert i >= 0, f"block {block} has no fee transaction"
    o = i + 32 + 4 + 4 * 64
    assert u32(raw, o) == 0 and u32(raw, o + 4) == 65 and raw[o + 8] == 0, "unexpected fee instruction"
    return struct.unpack_from("<QQ", raw, o + 9)

def shard(account, program):
    res = call("getAccount", account).get("result") or {}
    return bytes(((res.get("data") or {}).get("shards") or {}).get(program, []))

LOADER = "JAQ5MVHbCkSYRzXunsrNuM2m1LS859PGveHfoYPAmcvZ"  # [0xFE; 32], program_loader
ok = bad = moved = 0
def report(good, text):
    global ok, bad
    if good:
        ok += 1; print(f"  ok   {text}")
    else:
        bad += 1; print(f"  FAIL {text}")

program = None
print(f"sextant_lc against {rpc}, from {manifest}")
applied = refused = shared = 0
for line in open(manifest):
    line = line.rstrip("\n")
    if line.startswith("# program "):
        _, _, program, image = line.split()[:4]
        h = shard(program, LOADER)
        got = h[:32].hex() if len(h) >= 32 else ""
        report(got == image, f"program header {program[:12]}… names ImageID {image[:16]}…" + ("" if got == image else f" (chain has {got or 'nothing'})"))
    elif line.startswith("# deploy "):
        _, _, what, tx = line.split()[:4]
        b = block_of(tx)
        report(b is not None, f"deploy {what}: {tx[:16]}… in block {b}")
    elif line.startswith("# final "):
        _, _, account, length, want = line.split()[:5]
        b = shard(account, program)
        report(hashlib.sha256(b).hexdigest() == want and len(b) == int(length), f"final state of {account[:12]}…: {length} bytes as the run left them")
    elif line and not line.startswith("#"):
        cols = line.split("\t") + [""] * 9
        label, expected, verdict, block, tx, attempts, pre = cols[:7]
        if tx in ("", "-"):
            report(False, f"{label}: no transaction recorded ({verdict})")
            continue
        res = call("getTransaction", tx).get("result")
        if not (isinstance(res, list) and len(res) > 1):
            report(False, f"{label}: {tx[:16]}… NOT FOUND on chain")
            continue
        found = str(res[1] if not isinstance(res[1], dict) else res[1].get("height"))
        if found != block:
            moved += 1
        where = f"block {found}" + ("" if found == block else f" (recorded in {block}: moved by a block rewrite)")
        mine = base64.b64decode(res[0])
        limit = gas_limit_of(mine)
        exec_gas, stor_gas = fee_summary(int(found))
        if expected == "applied":
            applied += 1
        else:
            refused += 1
        if stor_gas != len(mine):
            shared += 1
            report(True, f"{label}: {expected}, included in {where}; block shared with other charged transactions, charge not separable")
            continue
        if expected == "applied":
            want = int(pre.split("=")[1]) if pre.startswith("gas=") else -1
            report(exec_gas == want and exec_gas < limit,
                   f"{label}: applied, {tx[:16]}… in {where}, charged {exec_gas} gas = the pre-checked gas, below its limit {limit}" if exec_gas == want and exec_gas < limit
                   else f"{label}: expected applied, charged {exec_gas} gas (pre-checked {want}, limit {limit})")
        else:
            report(exec_gas == limit,
                   f"{label}: refused ({pre}), {tx[:16]}… in {where}, charged its whole limit {limit}" if exec_gas == limit
                   else f"{label}: expected refused, charged {exec_gas} gas against a limit of {limit}")

ctl = secrets.token_hex(32)
report(block_of(ctl) is None, f"control: a random hash ({ctl[:12]}…) does not resolve")
print(f"{ok} checks pass, {bad} fail ({applied} applied and {refused} refused transactions in the manifest"
      + (f"; {shared} in blocks shared with other charged transactions" if shared else "")
      + (f"; {moved} moved by a block rewrite since the run" if moved else "") + ")")
sys.exit(1 if bad else 0)
PY
