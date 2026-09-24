#!/usr/bin/env bash
#
# Build the easytier-ios static library slices for the Flutter iOS client.
#
# This script only runs on macOS: it needs the Apple SDK (aarch64-apple-ios*,
# x86_64-apple-ios targets) plus `lipo`. Run it from the EasyTier repository
# root or from this crate directory.
#
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
#   ./build-xcframework.sh
#
# Output (workspace target directory + ./xcframework/sim):
#   target/aarch64-apple-ios/release/libeasytier_ios.a  (device)
#   xcframework/sim/libeasytier_ios.a                   (simulator, lipo merged)

set -euo pipefail

CRATE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The crate lives in a workspace; build artifacts land in the workspace root
# target directory regardless of the current directory.
WORKSPACE_ROOT="$(cd "${CRATE_DIR}/../.." && pwd)"
TARGET_DIR="${WORKSPACE_ROOT}/target"
OUT_DIR="${CRATE_DIR}/xcframework"

if [[ "$(uname)" != "Darwin" ]]; then
    echo "error: build-xcframework.sh must run on macOS (needs Apple SDK, lipo)" >&2
    exit 1
fi

cd "${WORKSPACE_ROOT}"

# The Rust iOS targets emit a `___chkstk_darwin` stack-probe call but do not
# link the compiler-rt archive that provides it. Point the linker at the
# matching device or simulator archive shipped inside the Xcode toolchain.
CLANG_BIN="$(xcrun --find clang)"          # .../Toolchains/XcodeDefault.xctoolchain/usr/bin/clang
TOOLCHAIN_USR="${CLANG_BIN%/bin/clang}"    # .../XcodeDefault.xctoolchain/usr
CLANG_RT_DIR="$(cd "${TOOLCHAIN_USR}/lib/clang" && cd "$(ls | sort -V | tail -1)/lib/darwin" && pwd)"
CLANG_RT_RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-L${CLANG_RT_DIR}"
echo "==> using libclang_rt from ${CLANG_RT_DIR}"

# kcp-sys's bindgen rejects the `-sim` in the aarch64-apple-ios-sim target
# triple; give bindgen an explicit simulator target so the C bindings build.
SIM_SDK="$(xcrun --sdk iphonesimulator --show-sdk-path)"

echo "==> building aarch64-apple-ios (device)"
RUSTFLAGS="${CLANG_RT_RUSTFLAGS} -C link-arg=-lclang_rt.ios" \
    cargo build -p easytier-ios --release --target aarch64-apple-ios

echo "==> building aarch64-apple-ios-sim (Apple Silicon simulator)"
BINDGEN_EXTRA_CLANG_ARGS="--target=arm64-apple-ios17.0-simulator -isysroot ${SIM_SDK}" \
    RUSTFLAGS="${CLANG_RT_RUSTFLAGS} -C link-arg=-lclang_rt.iossim" \
    cargo build -p easytier-ios --release --target aarch64-apple-ios-sim

echo "==> building x86_64-apple-ios (Intel simulator)"
BINDGEN_EXTRA_CLANG_ARGS="--target=x86_64-apple-ios17.0-simulator -isysroot ${SIM_SDK}" \
    RUSTFLAGS="${CLANG_RT_RUSTFLAGS} -C link-arg=-lclang_rt.iossim" \
    cargo build -p easytier-ios --release --target x86_64-apple-ios

rm -rf "${OUT_DIR}"
mkdir -p "${OUT_DIR}/sim"

echo "==> lipo: merge simulator slices"
lipo -create \
    "${TARGET_DIR}/aarch64-apple-ios-sim/release/libeasytier_ios.a" \
    "${TARGET_DIR}/x86_64-apple-ios/release/libeasytier_ios.a" \
    -output "${OUT_DIR}/sim/libeasytier_ios.a"

echo "==> done:"
echo "  device:    ${TARGET_DIR}/aarch64-apple-ios/release/libeasytier_ios.a"
echo "  simulator: ${OUT_DIR}/sim/libeasytier_ios.a"
