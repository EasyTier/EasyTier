#!/bin/sh
set -eu

# Restrict the unstable panic policy to target crates in this mini build.
if [ "${EASYTIER_MINI_SMALL_RUSTC_WRAPPER:-}" = "1" ]; then
    mini_rustc=$1
    shift
    for mini_arg in "$@"; do
        if [ "$mini_arg" = "${EASYTIER_MINI_SMALL_TARGET:-}" ]; then
            exec "$mini_rustc" "$@" -Zunstable-options -Cpanic=immediate-abort \
                -Cforce-unwind-tables=no -Zlocation-detail=none -Zfmt-debug=none
        fi
    done
    exec "$mini_rustc" "$@"
fi

mini_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mini_repo_dir=$(CDPATH= cd -- "$mini_script_dir/../.." && pwd)
mini_target=${1:-x86_64-unknown-linux-musl}
if [ "$#" -gt 0 ]; then
    shift
fi

case "$mini_target" in
    -h|--help)
        echo "usage: $0 [x86_64-unknown-linux-musl] [cargo build options...]"
        exit 0
        ;;
    x86_64-unknown-linux-musl) ;;
    *)
        echo "usage: $0 [x86_64-unknown-linux-musl] [cargo build options...]" >&2
        echo "For MIPS, use build-mips.sh instead." >&2
        exit 2
        ;;
esac

mini_sysroot=$(rustc --print sysroot)
if [ ! -f "$mini_sysroot/lib/rustlib/src/rust/library/Cargo.toml" ]; then
    echo "Missing Rust sources; run: rustup component add rust-src" >&2
    exit 1
fi
if [ -n "${RUSTC_WRAPPER:-}" ]; then
    echo "Unset RUSTC_WRAPPER before using the mini size wrapper." >&2
    exit 1
fi
if ! command -v ld.lld >/dev/null 2>&1; then
    echo "Missing ld.lld; install the LLVM lld linker." >&2
    exit 1
fi
if ! command -v readelf >/dev/null 2>&1; then
    echo "Missing readelf; install binutils for static-link verification." >&2
    exit 1
fi

cd "$mini_repo_dir"
mini_no_defaults=--no-default-features
mini_target_dir=${CARGO_TARGET_DIR:-target}
mini_expect_target_dir=0
for mini_arg in "$@"; do
    if [ "$mini_expect_target_dir" = "1" ]; then
        mini_target_dir=$mini_arg
        mini_expect_target_dir=0
        continue
    fi
    case "$mini_arg" in
        --target-dir) mini_expect_target_dir=1 ;;
        --target-dir=*) mini_target_dir=${mini_arg#--target-dir=} ;;
    esac
    if [ "$mini_arg" = "--no-default-features" ]; then
        mini_no_defaults=
    fi
done
export CARGO_TARGET_DIR="$mini_target_dir"
# Cargo must fingerprint the size flags, not just the wrapper's pathname.
if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    mini_separator=$(printf '\037')
    export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS}${mini_separator}-Ctarget-feature=+crt-static${mini_separator}-Zunstable-options${mini_separator}-Cpanic=immediate-abort${mini_separator}-Cforce-unwind-tables=no${mini_separator}-Zlocation-detail=none${mini_separator}-Zfmt-debug=none"
else
    export RUSTFLAGS="${RUSTFLAGS:-} -Ctarget-feature=+crt-static -Zunstable-options -Cpanic=immediate-abort -Cforce-unwind-tables=no -Zlocation-detail=none -Zfmt-debug=none"
fi
EASYTIER_MINI_SMALL_RUSTC_WRAPPER=1 \
    EASYTIER_MINI_SMALL_TARGET="$mini_target" \
    RUSTC_BOOTSTRAP=1 \
    RUSTC_WRAPPER="$mini_script_dir/build-small.sh" \
    cargo rustc --locked --profile mini --target "$mini_target" \
        -Z build-std=std \
        -Z build-std-features=optimize_for_size \
        -p easytier-mini ${mini_no_defaults:+--no-default-features} \
        --features tun,low-memory,strip-logs \
        "$@" -- -C link-arg=-fuse-ld=lld

mini_binary="$mini_target_dir/$mini_target/mini/easytier-nano"
mini_headers=$(LC_ALL=C readelf --program-headers --wide "$mini_binary")
mini_dynamic=$(LC_ALL=C readelf --dynamic --wide "$mini_binary")
case "$mini_headers" in
    *INTERP*)
        echo "Refusing non-static binary: ELF interpreter present." >&2
        exit 1
        ;;
esac
case "$mini_dynamic" in
    *"(NEEDED)"*)
        echo "Refusing non-static binary: external shared libraries required." >&2
        exit 1
        ;;
esac
printf 'Verified static binary: %s (%s bytes)\n' "$mini_binary" "$(wc -c < "$mini_binary")"
