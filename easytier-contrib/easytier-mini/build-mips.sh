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
                    -Cpanic=immediate-abort
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
    PATH="$mini_repo_dir/musl_gcc/$mini_toolchain/bin:$PATH" \
        EASYTIER_MINI_MIPS_RUSTC_WRAPPER=1 \
        RUSTC_BOOTSTRAP=1 \
        RUSTC_WRAPPER="$mini_script_dir/build-mips.sh" \
        cargo build \
            --manifest-path "$mini_repo_dir/Cargo.toml" \
            --profile mini \
            --target "$mini_target" \
            -Z build-std=std \
            -Z build-std-features=optimize_for_size \
            -p easytier-mini
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
