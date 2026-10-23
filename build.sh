#!/usr/bin/env bash
# Build otaripper (with direct-flash patch) for arm64 recovery use. Run from the otaripper source dir.
#
#   MODE=musl    (default) fully static aarch64 binary, no libc dependency
#   MODE=android dynamic bionic binary via Android NDK (x86-64 Linux host only)
#   CPU=v82      (default) ARMv8.2 baseline: SD865+/Peridot and newer; crashes on SD845/855-class chips
#   CPU=generic  plain ARMv8.0, runs on any arm64 device
#   CPU=poco     Poco F6 / SD 8s Gen 3 (ARMv9.2, SVE off): ARMv9 chips only
#   LTO=fat     (default) faster runtime
#   FEATURES=lite (default) offline only, drops HTTP client (smaller); FEATURES=full keeps URL streaming
set -euo pipefail

MODE="${MODE:-musl}"
CPU="${CPU:-v82}"
LTO="${LTO:-fat}"
FEATURES="${FEATURES:-lite}"

case "$CPU" in
  v82)
    CFLAGS_CPU="-march=armv8.2-a+crc+crypto+dotprod -mtune=cortex-a76"
    RUST_CPU="-C target-cpu=generic -C target-feature=+crc,+aes,+sha2,+dotprod,+fp16"
    ;;
  generic)
    CFLAGS_CPU="-mcpu=generic"
    RUST_CPU="-C target-cpu=generic"
    ;;
  poco)
    CFLAGS_CPU="-mcpu=cortex-a720+nosve"
    RUST_CPU="-C target-cpu=cortex-a720 -C target-feature=-sve,-sve2"
    ;;
  *) echo "CPU must be v82, generic or poco"; exit 1;;
esac

case "$FEATURES" in
  lite) FEAT_ARGS="--no-default-features";;
  full) FEAT_ARGS="";;
  *) echo "FEATURES must be lite or full"; exit 1;;
esac

export CFLAGS="-O3 ${CFLAGS_CPU} -fno-semantic-interposition"
export CARGO_PROFILE_RELEASE_LTO="$LTO"

case "$MODE" in
  musl)
    TARGET=aarch64-unknown-linux-musl
    rustup target add "$TARGET"
    command -v cargo-zigbuild >/dev/null || cargo install --locked cargo-zigbuild
    command -v zig >/dev/null || { echo "zig not found: pipx install ziglang && ln -sf ~/.local/bin/python-zig ~/.local/bin/zig"; exit 1; }
    export RUSTFLAGS="${RUST_CPU} -C target-feature=+crt-static -C relocation-model=static"
    cargo zigbuild --release --target "$TARGET" $FEAT_ARGS
    ;;
  android)
    : "${NDK:?set NDK to your android-ndk dir}"
    TARGET=aarch64-linux-android
    BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
    [ -d "$BIN" ] || { echo "NDK prebuilt not found at $BIN (x86-64 Linux host required)"; exit 1; }
    rustup target add "$TARGET"
    export CC_aarch64_linux_android="$BIN/aarch64-linux-android30-clang"
    export AR_aarch64_linux_android="$BIN/llvm-ar"
    export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$BIN/aarch64-linux-android30-clang"
    export LZMA_API_STATIC=1
    export RUSTFLAGS="${RUST_CPU}"
    cargo build --release --target "$TARGET" $FEAT_ARGS
    ;;
  *) echo "MODE must be musl or android"; exit 1;;
esac

OUT="target/$TARGET/release/otaripper"
file "$OUT" || true
ls -l "$OUT"
