#!/usr/bin/env bash
# Build both benchmark guests (accelerated and stock) with the RISC Zero Rust
# toolchain installed by rzup, the same flags `cargo risczero build` uses.
#   scripts/build-guests.sh [accelerated|stock|lez]   (default: accelerated and stock)
set -euo pipefail
cd "$(dirname "$0")/.."
TC="${RISC0_RUST:-$(ls -d "$HOME"/.risc0/toolchains/v1.*-rust-* | sort -V | tail -1)/bin}"
FLAGS=$(printf '%s\x1f' -C passes=lower-atomic -C link-arg=-Ttext=0x00200800 -C link-arg=--fatal-warnings \
  -C panic=abort --cfg 'getrandom_backend="custom"')
FLAGS=${FLAGS%$'\x1f'}
# blst is C: the RISC Zero C toolchain (rzup install cpp), as risc0-build sets it up.
CC_RV="${RISC0_CC:-$(ls -d "$HOME"/.risc0/toolchains/v*-cpp-* | sort -V | tail -1)/riscv32im-osx-arm64/bin/riscv32-unknown-elf-gcc}"
build() { # dir bin
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
    lez) build programs/sextant sextant_lc
         cargo run -q --release --manifest-path executor-tests/Cargo.toml --bin pack -- \
           programs/sextant/target/riscv32im-risc0-zkvm-elf/release/sextant_lc artifacts/programs/v0.3/sextant_lc.bin ;;
  esac
done
