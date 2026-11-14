#!/usr/bin/env bash
# The consensus-spec light-client vectors spec-tests/ runs, from the pinned
# release of ethereum/consensus-specs, sha256-checked.
#
#   scripts/fetch-spec-tests.sh           # (re)vendor them into spec-tests/vectors/
#   scripts/fetch-spec-tests.sh --check   # the vendored files are the release's, byte for byte
#   SPEC_TARBALLS=<dir> scripts/fetch-spec-tests.sh ...   # from tarballs already downloaded
#
# Vendored: mainnet single_merkle_proof and minimal sync, for Electra, Fulu and
# Gloas (sextant supports Electra and later). Not vendored: update_ranking and
# data_collection, which test a full node's best-update selection and
# serving, not a light client's verification (spec-tests/README.md).
set -euo pipefail

TAG=v1.7.0-beta.4
# preset, its tarball's sha256 (as the release lists it), the suite taken from it
PINS="mainnet 67762986572372a08d3b182535aa760433c86e174e14e0bbd756f350dd19398c single_merkle_proof
minimal 26d09aea70c62ed235a120a95082d544ab1c2e6fe36bd35ea1bd5da62f3b7b68 sync"
FORKS="electra fulu gloas"

root=$(cd "$(dirname "$0")/.." && pwd)
dest=$root/spec-tests/vectors
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

mkdir -p "$work/out"
echo "$PINS" | while read -r preset want suite; do
  tgz=$work/$preset.tar.gz
  # SPEC_TARBALLS=<dir>: tarballs already downloaded (still sha256-checked).
  if [ -n "${SPEC_TARBALLS:-}" ]; then cp "$SPEC_TARBALLS/$preset.tar.gz" "$tgz"
  else curl -fsSL -o "$tgz" "https://github.com/ethereum/consensus-specs/releases/download/$TAG/$preset.tar.gz"; fi
  got=$(sha256 "$tgz")
  [ "$got" = "$want" ] || { echo "$preset.tar.gz: sha256 $got, expected $want" >&2; exit 1; }
  paths=""
  for f in $FORKS; do paths="$paths tests/$preset/$f/light_client/$suite"; done
  # shellcheck disable=SC2086
  tar -xzf "$tgz" -C "$work/out" $paths
  rm "$tgz"
done

if [ "${1:-}" = "--check" ]; then
  diff -r "$work/out/tests" "$dest/tests" && echo "spec-tests/vectors: identical to $TAG"
else
  rm -rf "$dest/tests"
  mkdir -p "$dest"
  mv "$work/out/tests" "$dest/tests"
  echo "spec-tests/vectors: vendored from $TAG"
fi
