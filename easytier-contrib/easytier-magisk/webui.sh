#!/system/bin/sh

MODDIR=$(CDPATH= cd "${0%/*}" 2>/dev/null && pwd -P) || {
    echo "Failed to resolve module directory" >&2
    exit 1
}
CONFIG_FILE="${MODDIR}/config/config.toml"
COMMAND_ARGS="${MODDIR}/config/command_args"
EASYTIER="${MODDIR}/easytier-core"

fail() {
    echo "$1" >&2
    exit 1
}

running_pids() {
    for process_dir in /proc/[0-9]*; do
        [ "$(readlink "${process_dir}/exe" 2>/dev/null)" = "${EASYTIER}" ] || continue
        printf '%s\n' "${process_dir#/proc/}"
    done
}

is_running() {
    [ -n "$(running_pids)" ]
}

case "$1" in
    status)
        if is_running; then
            echo "running"
        else
            echo "stopped"
        fi
        ;;
    config-mode)
        if [ -f "${COMMAND_ARGS}" ]; then
            echo "command-args"
        else
            echo "toml"
        fi
        ;;
    read-config)
        [ -f "${CONFIG_FILE}" ] || fail "Configuration file not found: ${CONFIG_FILE}"
        cat "${CONFIG_FILE}"
        ;;
    save-and-restart)
        [ -f "${COMMAND_ARGS}" ] && fail "command_args is active; config.toml would be ignored"
        [ -n "$2" ] || fail "Missing base64-encoded configuration"
        [ -x "${EASYTIER}" ] || fail "easytier-core is not executable"

        TEMP_FILE="${CONFIG_FILE}.webui.$$"
        trap 'rm -f "${TEMP_FILE}"' EXIT HUP INT TERM
        umask 077

        printf '%s' "$2" | base64 -d > "${TEMP_FILE}" \
            || fail "Failed to decode configuration"

        VALIDATION_OUTPUT=$("${EASYTIER}" --check-config -c "${TEMP_FILE}" 2>&1)
        if [ $? -ne 0 ]; then
            fail "${VALIDATION_OUTPUT:-Configuration validation failed}"
        fi

        chmod 0644 "${TEMP_FILE}"
        mv -f "${TEMP_FILE}" "${CONFIG_FILE}" \
            || fail "Failed to replace configuration"
        trap - EXIT HUP INT TERM

        RUNNING_PIDS=$(running_pids)
        for pid in ${RUNNING_PIDS}; do
            kill "${pid}" || fail "Failed to restart EasyTier"
        done
        echo "saved"
        ;;
    *)
        fail "Usage: $0 {status|config-mode|read-config|save-and-restart BASE64}"
        ;;
esac
