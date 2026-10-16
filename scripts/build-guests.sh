#!/usr/bin/env bash
# Build both benchmark guests (accelerated and stock) with the RISC Zero Rust
# toolchain installed by rzup, the same flags `cargo risczero build` uses.
#   scripts/build-guests.sh [accelerated|stock|lez|receiver]   (default: accelerated and stock)
#   DOCKER=1 scripts/build-guests.sh lez   the program with RISC Zero's pinned builder
#                                          (reproducible: this is the committed binary)
#   DOCKER=1 scripts/build-guests.sh receiver   the same for the erc20_receiver consumer
set -euo pipefail
cd "$(dirname "$0")/.."
FLAGS=$(printf '%s\x1f' -C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings \
  -C panic=abort --cfg 'getrandom_backend="custom"')
FLAGS=${FLAGS%$'\x1f'}
build() { # dir bin  (local toolchains, looked up only when a local build runs)
  local TC CC_RV
  TC="${RISC0_RUST:-$(ls -d "$HOME"/.risc0/toolchains/v1.*-rust-* | sort -V | tail -1)/bin}"
  # blst is C: the RISC Zero C toolchain (rzup install cpp), as risc0-build sets it up.
  CC_RV="${RISC0_CC:-$(ls -d "$HOME"/.risc0/toolchains/v*-cpp-* | sort -V | tail -1)/riscv32im-osx-arm64/bin/riscv32-unknown-elf-gcc}"
  (cd "$1" && RUSTC="$TC/rustc" CARGO_ENCODED_RUSTFLAGS="$FLAGS" CC=/no_cc RISC0_FEATURE_bigint2= \
    CC_riscv32im_risc0_zkvm_elf="$CC_RV" CFLAGS_riscv32im_risc0_zkvm_elf="-march=rv32im -nostdlib" \
    cargo build -j "${JOBS:-4}" --release --target riscv32im-risc0-zkvm-elf --bin "$2")
  ls -l "$1/target/riscv32im-risc0-zkvm-elf/release/$2"
  [ -z "${3:-}" ] || cp "$1/target/riscv32im-risc0-zkvm-elf/release/$2" "$3"
}
for w in ${@:-accelerated stock}; do
  case $w in
    accelerated) build guest sextant_bench artifacts/bench/sextant_bench.accelerated.elf ;;
    stock) build guest-stock sextant_bench_stock artifacts/bench/sextant_bench.stock.elf ;;
    lez) if [ "${DOCKER:-0}" = 1 ]; then
           # Run from the repository root: the Docker context is the working
           # directory, and the program depends on ../../core.
           RISC0_DOCKER_CONTAINER_TAG=r0.1.91.1 cargo risczero build --manifest-path programs/sextant/Cargo.toml
           cp programs/sextant/target/riscv32im-risc0-zkvm-elf/docker/sextant_lc.bin artifacts/programs/v0.3/sextant_lc.bin
           cargo run -q --release --manifest-path executor-tests/Cargo.toml --bin image_id -- artifacts/programs/v0.3/sextant_lc.bin
           continue
         fi
         build programs/sextant sextant_lc
         cargo run -q --release --manifest-path executor-tests/Cargo.toml --bin pack -- \
           programs/sextant/target/riscv32im-risc0-zkvm-elf/release/sextant_lc artifacts/programs/v0.3/sextant_lc.bin ;;
    receiver) if [ "${DOCKER:-0}" = 1 ]; then
           RISC0_DOCKER_CONTAINER_TAG=r0.1.91.1 cargo risczero build --manifest-path programs/erc20_receiver/Cargo.toml
           cp programs/erc20_receiver/target/riscv32im-risc0-zkvm-elf/docker/erc20_receiver.bin artifacts/programs/v0.3/erc20_receiver.bin
           cargo run -q --release --manifest-path executor-tests/Cargo.toml --bin image_id -- artifacts/programs/v0.3/erc20_receiver.bin
           continue
         fi
         build programs/erc20_receiver erc20_receiver
         cargo run -q --release --manifest-path executor-tests/Cargo.toml --bin pack -- \
           programs/erc20_receiver/target/riscv32im-risc0-zkvm-elf/release/erc20_receiver artifacts/programs/v0.3/erc20_receiver.bin ;;
  esac
done
