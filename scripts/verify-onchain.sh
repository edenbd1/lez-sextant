#!/usr/bin/env bash
# Re-check a recorded run of sextant_lc against a LEZ v0.3 sequencer, from its
# manifest, with nothing but curl-level JSON-RPC (no wallet, no build).
#
#   scripts/verify-onchain.sh                                   # the public testnet run
#   scripts/verify-onchain.sh --manifest evidence/local/e2e.tsv --rpc http://127.0.0.1:3040
#
# A manifest is what scripts/e2e.sh writes: one line per transaction
#   label  expected(applied|refused)  verdict  block  tx  attempts  precheck
# and comment lines, of which these are checked:
#   # program <header> <image-id>     the program_loader header names this ImageID
#   # deploy <what> <hash>            the deployment transaction resolves
#   # final <account> <len> <sha256>  the account's sextant_lc shard is these bytes now
#
# What is checked:
# - the header account's program_loader shard names the ImageID of the committed binary;
# - every `applied` transaction resolves by hash to a block (one found in another
#   block than recorded was moved by a block rewrite: reported, not failed, since
#   what it did is pinned by the final-state lines);
# - every `refused` transaction: none of its attempts resolves. On v0.3.1 a public
#   transaction whose program refuses fails settlement and is left out of the block
#   (lez/chain_state/src/apply.rs, `fee action failed`), so a refusal never resolves;
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
import hashlib, json, secrets, sys, urllib.request

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
applied = refused = 0
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
        cols = line.split("\t")
        label, expected, verdict, block, tx, attempts = cols[:6]
        hashes = [h for h in attempts.split(",") if h and h != "-"] or ([tx] if tx not in ("", "-") else [])
        if expected == "applied":
            applied += 1
            found = block_of(tx) if tx not in ("", "-") else None
            if found is not None and found != block:
                moved += 1
            report(verdict == "applied" and found is not None,
                   f"{label}: applied, {tx[:16]}… in block {block}" + ("" if found is None or found == block else f" (now in block {found}: moved by a block rewrite)") + ("" if found is not None else " (NOT FOUND on chain)"))
        else:
            refused += 1
            landed = [(h, block_of(h)) for h in hashes]
            landed = [(h, b) for h, b in landed if b is not None]
            report(verdict in ("not-included", "rejected") and not landed,
                   f"{label}: refused, none of {len(hashes)} attempt(s) resolves" + ("" if not landed else f" (BUT {landed[0][0][:16]}… is in block {landed[0][1]})"))

ctl = secrets.token_hex(32)
report(block_of(ctl) is None, f"control: a random hash ({ctl[:12]}…) does not resolve")
print(f"{ok} checks pass, {bad} fail ({applied} applied and {refused} refused transactions in the manifest" + (f"; {moved} moved by a block rewrite since the run" if moved else "") + ")")
sys.exit(1 if bad else 0)
PY
