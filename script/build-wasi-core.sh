#!/usr/bin/env bash

set -Eeuo pipefail

readonly binaryen_version=131
readonly binaryen_release="version_${binaryen_version}"
readonly script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
readonly repository_root=$(cd -- "${script_dir}/.." && pwd)
cd "$repository_root"
readonly target_dir="${CARGO_TARGET_DIR:-target}"
readonly raw_artifact="${target_dir}/wasm32-wasip1/release/easytier_core.wasm"
readonly artifact="${target_dir}/wasm32-wasip1/release/easytier_core_go_host.wasm"
readonly core_features="proxy-smoltcp-stack,ring-crypto,wasi-crypto-offload"

sha256_file() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        echo "sha256sum or shasum is required" >&2
        return 1
    fi
}

resolve_binaryen_asset() {
    local operating_system machine
    operating_system=$(uname -s)
    machine=$(uname -m)

    case "$machine" in
        x86_64 | amd64) machine=x86_64 ;;
        aarch64 | arm64) machine=arm64 ;;
        *)
            echo "unsupported Binaryen host architecture: ${machine}" >&2
            return 1
            ;;
    esac

    case "$operating_system" in
        Linux)
            if [[ "$machine" == arm64 ]]; then
                binaryen_platform=aarch64-linux
                binaryen_sha256=ba991f677edd9a21d2bc96c0144bc8ac5b112d4d98a3eb266e075e22e557df2a
            else
                binaryen_platform=x86_64-linux
                binaryen_sha256=b5bf1f0eaf17c63ee588ff7a5954dc8f6ce2c26989051c66f24dfe9ece3e46db
            fi
            ;;
        Darwin)
            binaryen_platform="${machine}-macos"
            if [[ "$machine" == arm64 ]]; then
                binaryen_sha256=e441b48dc22163d209b4f05e44dc7210909b01237642b6c9ae48fd710a3ef83e
            else
                binaryen_sha256=d209fadd8a894bdaf3bd3612a23c32a0af184d2f4a979b8c789e6e4f6a4de883
            fi
            ;;
        MINGW* | MSYS* | CYGWIN*)
            binaryen_platform="${machine}-windows"
            binaryen_executable=.exe
            if [[ "$machine" == arm64 ]]; then
                binaryen_sha256=e3eaed3d43bcbba867895e55f5e3e9fcfebf776bc4ed6ee59cae071f083cedb9
            else
                binaryen_sha256=2f4edac1703a2f695254d6ff52ede03481e67db1f094915763d863158c17d9bc
            fi
            ;;
        *)
            echo "unsupported Binaryen host operating system: ${operating_system}" >&2
            return 1
            ;;
    esac
}

download_wasm_opt() {
    local archive archive_name archive_url cache_dir digest temporary
    resolve_binaryen_asset
    archive_name="binaryen-${binaryen_release}-${binaryen_platform}.tar.gz"
    archive_url="https://github.com/WebAssembly/binaryen/releases/download/${binaryen_release}/${archive_name}"
    cache_dir="${target_dir}/binaryen/${binaryen_release}-${binaryen_platform}"
    archive="${cache_dir}/${archive_name}"
    wasm_opt="${cache_dir}/binaryen-${binaryen_release}/bin/wasm-opt${binaryen_executable:-}"
    if [[ -x "$wasm_opt" ]]; then
        return
    fi

    mkdir -p "$cache_dir"
    if [[ -f "$archive" ]]; then
        digest=$(sha256_file "$archive")
    fi
    if [[ ${digest:-} != "$binaryen_sha256" ]]; then
        command -v curl >/dev/null || {
            echo "curl is required to download Binaryen" >&2
            return 1
        }
        temporary="${archive}.$$"
        trap 'rm -f "${temporary:-}" "${optimized:-}"' EXIT
        curl --fail --location --output "$temporary" "$archive_url"
        digest=$(sha256_file "$temporary")
        if [[ "$digest" != "$binaryen_sha256" ]]; then
            echo "Binaryen archive SHA-256 mismatch: ${digest}" >&2
            return 1
        fi
        mv "$temporary" "$archive"
    fi
    tar -xzf "$archive" -C "$cache_dir"
    if [[ ! -x "$wasm_opt" ]]; then
        echo "wasm-opt is missing from Binaryen archive" >&2
        return 1
    fi
}

wasm_opt=${WASM_OPT:-}
if [[ -z "$wasm_opt" ]]; then
    download_wasm_opt
fi
version=$("$wasm_opt" --version)
if [[ "$version" != *"version ${binaryen_version} "* ]]; then
    echo "wasm-opt ${binaryen_version} is required, got: ${version}" >&2
    exit 1
fi

cargo build --release --target wasm32-wasip1 -p easytier-core \
    --features "$core_features"

optimized="${artifact}.wasm-opt.$$"
trap 'rm -f "${temporary:-}" "${optimized:-}"' EXIT
"$wasm_opt" -O4 \
    --enable-bulk-memory \
    --enable-bulk-memory-opt \
    --enable-nontrapping-float-to-int \
    "$raw_artifact" \
    -o "$optimized"
mv "$optimized" "$artifact"
echo "built ${artifact} with ${version}"
