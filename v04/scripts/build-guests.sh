#!/usr/bin/env bash
# Build sextant_lc for LEZ v0.4.0-rc3 (v04/programs/sextant) with the local
# RISC Zero toolchains (rzup: rust, cpp) and the flags `cargo risczero build`
# uses, and pack it as the R0BF binary LEZ loads (v04/executor-tests `pack`):
#   v04/artifacts/sextant_lc.bin
# Local paths are remapped (the repository to `.`, the cargo home to /cargo)
# so none lands in the binary.
#   v04/scripts/build-guests.sh            local toolchains
#   DOCKER=1 v04/scripts/build-guests.sh   RISC Zero's pinned builder (reproducible)
set -euo pipefail
cd "$(dirname "$0")/../.."
ROOT=$(pwd -P)
OUT=v04/artifacts/sextant_lc.bin
if [ "${DOCKER:-0}" = 1 ]; then
  RISC0_DOCKER_CONTAINER_TAG=r0.1.91.1 cargo risczero build --manifest-path v04/programs/sextant/Cargo.toml
  cp v04/programs/sextant/target/riscv32im-risc0-zkvm-elf/docker/sextant_lc.bin "$OUT"
else
  FLAGS=$(printf '%s\x1f' -C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings \
    -C panic=abort --cfg 'getrandom_backend="custom"' \
    "--remap-path-prefix=$ROOT=." "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo")
  FLAGS=${FLAGS%$'\x1f'}
  TC="${RISC0_RUST:-$(ls -d "$HOME"/.risc0/toolchains/v1.*-rust-* | sort -V | tail -1)/bin}"
  CC_RV="${RISC0_CC:-$(ls -d "$HOME"/.risc0/toolchains/v*-cpp-*/riscv32im-*/bin/riscv32-unknown-elf-gcc | sort -V | tail -1)}"
  (cd v04/programs/sextant && RUSTC="$TC/rustc" CARGO_ENCODED_RUSTFLAGS="$FLAGS" CC=/no_cc RISC0_FEATURE_bigint2= \
    CC_riscv32im_risc0_zkvm_elf="$CC_RV" CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib" \
    cargo build -j "${JOBS:-4}" --release --target riscv32im-risc0-zkvm-elf --bin sextant_lc)
  cargo run -q --release -j "${JOBS:-4}" --manifest-path v04/executor-tests/Cargo.toml --bin pack -- \
    v04/programs/sextant/target/riscv32im-risc0-zkvm-elf/release/sextant_lc "$OUT"
fi
cargo run -q --release -j "${JOBS:-4}" --manifest-path v04/executor-tests/Cargo.toml --bin image_id -- "$OUT"
