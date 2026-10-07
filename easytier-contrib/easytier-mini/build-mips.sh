#!/bin/sh
set -eu

# Cargo invokes this same file as a rustc wrapper during compact MIPS builds.
# Applying immediate-abort here keeps the size policy scoped to easytier-mini;
# normal MIPS builds elsewhere in the workspace retain their panic behavior.
if [ "${EASYTIER_MINI_MIPS_RUSTC_WRAPPER:-}" = "1" ]; then
    mini_rustc=$1
    shift
    for mini_rustc_arg in "$@"; do
        case "$mini_rustc_arg" in
            mips-unknown-linux-musl|mipsel-unknown-linux-musl)
                exec "$mini_rustc" "$@" \
                    -Zunstable-options \
                    -Cpanic=immediate-abort \
                    -Cforce-unwind-tables=no \
                    -Zlocation-detail=none \
                    -Zfmt-debug=none
                ;;
        esac
    done
    exec "$mini_rustc" "$@"
fi

mini_script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mini_repo_dir=$(CDPATH= cd -- "$mini_script_dir/../.." && pwd)
mini_requested_target=${1:-all}
cd "$mini_repo_dir"

build_mips_target() {
    mini_target=$1
    mini_toolchain=$2
    if ! command -v readelf >/dev/null 2>&1; then
        echo "Missing readelf; install binutils for static-link verification." >&2
        exit 1
    fi
    PATH="$mini_repo_dir/musl_gcc/$mini_toolchain/bin:$PATH" \
        CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-target}" \
        EASYTIER_MINI_MIPS_RUSTC_WRAPPER=1 \
        RUSTC_BOOTSTRAP=1 \
        RUSTC_WRAPPER="$mini_script_dir/build-mips.sh" \
        cargo build \
            --locked \
            --manifest-path "$mini_repo_dir/Cargo.toml" \
            --profile mini \
            --target "$mini_target" \
            -Z build-std=std \
            -Z build-std-features=optimize_for_size \
            -p easytier-mini \
            --no-default-features \
            --features tun,low-memory,strip-logs

    mini_binary="${CARGO_TARGET_DIR:-target}/$mini_target/mini/easytier-nano"
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
}

case "$mini_requested_target" in
    all)
        build_mips_target mips-unknown-linux-musl mips-unknown-linux-muslsf
        build_mips_target mipsel-unknown-linux-musl mipsel-unknown-linux-muslsf
        ;;
    mips|mips-unknown-linux-musl)
        build_mips_target mips-unknown-linux-musl mips-unknown-linux-muslsf
        ;;
    mipsel|mipsel-unknown-linux-musl)
        build_mips_target mipsel-unknown-linux-musl mipsel-unknown-linux-muslsf
        ;;
    -h|--help)
        echo "usage: $0 [all|mips|mipsel]"
        ;;
    *)
        echo "unsupported MIPS target: $mini_requested_target" >&2
        exit 2
        ;;
esac
