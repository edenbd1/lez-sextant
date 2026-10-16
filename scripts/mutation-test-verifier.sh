#!/usr/bin/env bash
# The verifier is only evidence if it fails when the record is wrong. Each
# mutation below corrupts one thing in a copy of a manifest; verify-onchain.sh
# must exit non-zero on every one, and zero on the manifest as recorded.
#
#   scripts/mutation-test-verifier.sh [--manifest FILE] [--rpc URL]
set -uo pipefail
cd "$(dirname "$0")/.."
MANIFEST="evidence/testnet/run.tsv"; RPC="https://testnet.lez.logos.co"
while [ $# -gt 0 ]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2 ;;
    --rpc) RPC="$2"; shift 2 ;;
    *) echo "usage: $0 [--manifest FILE] [--rpc URL]"; exit 2 ;;
  esac
done
T="$(mktemp -d)"
fake="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
mutate() { # mutation name
  python3 - "$MANIFEST" "$T/$1.tsv" "$1" "$fake" <<'PY'
import sys
src, dst, how, fake = sys.argv[1:5]
lines = open(src).read().splitlines()
rows = [i for i, l in enumerate(lines) if l and not l.startswith("#")]
def cols(i): return lines[i].split("\t")
def put(i, c): lines[i] = "\t".join(c)
if how == "fake-hash":            # an applied transaction's hash replaced by one never sent
    i = next(i for i in rows if cols(i)[1] == "applied"); c = cols(i); c[4] = fake; c[5] = fake; put(i, c)
elif how == "refusal-as-applied":  # a refused transaction claimed as applied
    i = next(i for i in rows if cols(i)[1] == "refused"); c = cols(i); c[1] = "applied"; c[2] = "applied"; c[6] = "gas=" + c[7]; put(i, c)
elif how == "applied-as-refused":  # an applied transaction claimed as refused
    i = next(i for i in rows if cols(i)[1] == "applied"); c = cols(i); c[1] = "refused"; c[2] = "reverted"; put(i, c)
elif how == "wrong-gas":           # an applied transaction's pre-checked gas off by one
    i = next(i for i in rows if cols(i)[1] == "applied"); c = cols(i); c[6] = "gas=%d" % (int(c[6][4:]) + 1); put(i, c)
elif how == "final-state":         # the instance's recorded final bytes altered
    i = next(i for i, l in enumerate(lines) if l.startswith("# final ")); p = lines[i].split(); p[4] = "0" * 64; lines[i] = " ".join(p)
elif how == "image-id":            # another ImageID claimed for the deployed program
    i = next(i for i, l in enumerate(lines) if l.startswith("# program ")); p = lines[i].split(); p[3] = "0" * 64; lines[i] = " ".join(p)
elif how == "deploy-hash":         # a deployment transaction never sent
    i = next(i for i, l in enumerate(lines) if l.startswith("# deploy ")); p = lines[i].split(); p[3] = fake; lines[i] = " ".join(p)
open(dst, "w").write("\n".join(lines) + "\n")
PY
}
fail=0
./scripts/verify-onchain.sh --manifest "$MANIFEST" --rpc "$RPC" > "$T/clean.out" 2>&1 \
  && echo "  ok   the recorded manifest verifies ($(tail -1 "$T/clean.out"))" || { echo "  FAIL the recorded manifest does not verify"; fail=1; }
for m in fake-hash refusal-as-applied applied-as-refused wrong-gas final-state image-id deploy-hash; do
  if [ "$m" = deploy-hash ] && ! grep -q '^# deploy ' "$MANIFEST"; then continue; fi
  mutate "$m"
  if ./scripts/verify-onchain.sh --manifest "$T/$m.tsv" --rpc "$RPC" > "$T/$m.out" 2>&1; then
    echo "  FAIL mutation $m was NOT caught"; fail=1
  else
    echo "  ok   mutation $m caught: $(grep -m1 FAIL "$T/$m.out" | sed 's/^ *FAIL *//' | cut -c1-110)"
  fi
done
exit $fail
