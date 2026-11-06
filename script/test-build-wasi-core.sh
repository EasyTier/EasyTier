#!/usr/bin/env bash

set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repository_root=$(cd -- "${script_dir}/.." && pwd)
readonly script_dir repository_root
cd "$repository_root"

# Use the same pinned Binaryen as build-wasi-core.sh, but stub Cargo to avoid
# compiling the core for each fixture. WASM_OPT may point at its cached binary.
wasm_opt=$(command -v "${WASM_OPT:-wasm-opt}") || {
    echo "Set WASM_OPT to the Binaryen 131 wasm-opt executable." >&2
    exit 1
}
wasm_opt=$(cd -- "$(dirname -- "$wasm_opt")" && pwd)/$(basename -- "$wasm_opt")
temporary=$(mktemp -d)
readonly wasm_opt temporary
trap 'rm -rf "$temporary"' EXIT
mkdir -p "$temporary/bin"
cat > "$temporary/bin/cargo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
mkdir -p "${CARGO_TARGET_DIR}/wasm32-wasip1/release"
cp "$WASI_TEST_INPUT" "${CARGO_TARGET_DIR}/wasm32-wasip1/release/easytier_core.wasm"
EOF
chmod +x "$temporary/bin/cargo"

run_case() {
    local name="$1" expected="$2" fixture="$3"
    shift 3
    local case_dir="${temporary}/${name}" status=0
    local artifact="${case_dir}/target/wasm32-wasip1/release/easytier_core_go_host.wasm"
    mkdir -p "$(dirname -- "$artifact")"
    printf '%s\n' "$fixture" > "${case_dir}/input.wat"
    printf 'previous validated artifact\n' > "$artifact"
    cp "$artifact" "${case_dir}/previous.wasm"

    PATH="${temporary}/bin:$PATH" WASM_OPT="$wasm_opt" \
        CARGO_TARGET_DIR="${case_dir}/target" WASI_TEST_INPUT="${case_dir}/input.wat" \
        bash "${script_dir}/build-wasi-core.sh" > "${case_dir}/output" 2>&1 || status=$?

    if [[ "$expected" == success ]]; then
        [[ "$status" == 0 ]] || { cat "${case_dir}/output" >&2; return 1; }
        grep -F "built ${artifact}" "${case_dir}/output" >/dev/null
        if cmp -s "$artifact" "${case_dir}/previous.wasm"; then
            echo "${name}: validated artifact was not published" >&2
            return 1
        fi
        "$wasm_opt" "$artifact" --quiet -o "${case_dir}/validated.wasm"
    else
        [[ "$status" != 0 ]] || { echo "${name}: build unexpectedly succeeded" >&2; return 1; }
        if grep -F "built ${artifact}" "${case_dir}/output" >/dev/null; then
            echo "${name}: failed build reported success" >&2
            return 1
        fi
        cmp "$artifact" "${case_dir}/previous.wasm"
        for diagnostic in "$@"; do
            grep -F "$diagnostic" "${case_dir}/output" >/dev/null || {
                cat "${case_dir}/output" >&2
                return 1
            }
        done
    fi
    if compgen -G "${artifact}.wasm-opt.*" >/dev/null; then
        echo "${name}: temporary optimized artifact was not removed" >&2
        return 1
    fi
    printf 'PASS %s\n' "$name"
}

run_case no-imports success '(module (func (export "main")))'

# WAT identifiers are literal, not shell variable references.
# shellcheck disable=SC2016
run_case allowed-functions success '(module
    (import "easytier_host" "host_call" (func $host))
    (import "wasi_snapshot_preview1" "proc_exit" (func $exit (param i32)))
    (func (export "main") (call $host) (call $exit (i32.const 0))))'

# shellcheck disable=SC2016
run_case ring-functions failure '(module
    (import "env" "ring_core_0_17_14__CRYPTO_memcmp" (func $memcmp))
    (import "env" "ring_core_0_17_14__aes_nohw_encrypt" (func $encrypt))
    (func (export "main") (call $memcmp) (call $encrypt)))' \
    'unsupported WASI import:' 'ring_core_0_17_14__CRYPTO_memcmp' \
    'ring_core_0_17_14__aes_nohw_encrypt'

run_case other-import-kinds failure '(module
    (import "env" "memory" (memory 1))
    (import "env" "table" (table 1 funcref))
    (import "env" "global" (global i32))
    (export "memory" (memory 0))
    (export "table" (table 0))
    (export "global" (global 0)))' \
    'unsupported WASI import:' '"env" "memory"' '"env" "table"' '"env" "global"'

# shellcheck disable=SC2016
run_case lookalike-module failure '(module
    (import "easytier_host_extra" "host_call" (func $host))
    (func (export "main") (call $host)))' '"easytier_host_extra"'

# shellcheck disable=SC2016
run_case spaced-module failure '(module
    (import "easytier_host unexpected" "host_call" (func $host))
    (func (export "main") (call $host)))' 'unsupported WASI import:'

# Only imports retained in the optimized artifact need a host implementation.
# shellcheck disable=SC2016
run_case removed-import success '(module
    (import "env" "unused" (func $unused))
    (func (export "main")))'

run_case invalid-module failure 'not a WebAssembly module'
