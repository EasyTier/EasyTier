#!/system/bin/sh
MODDIR=${0%/*}
CONFIG_FILE="${MODDIR}/config/config.toml"
LOG_FILE="${MODDIR}/log.log"
ACTION="$1"  # 参数：add add_once del


# 获取接口/IP
get_et_iface() {
    awk '
        BEGIN { IGNORECASE = 1 }
        /^[[:space:]]*dev_name[[:space:]]*=/ {
            val = $0
            sub(/^[^=]*=[[:space:]]*/, "", val)
            gsub(/[" \t]/, "", val)
            print val
            exit
        }
    ' "$CONFIG_FILE"
}
get_tun_iface() {
    ip link | awk -F': ' '/ tun[[:alnum:]]+/ {print $2; exit}'
}
get_hot_iface() {
    ip link | awk -F': ' '/(^| )(swlan[[:alnum:]_]*|softap[[:alnum:]_]*|p2p-wlan[[:alnum:]_]*|ap[[:alnum:]_]*)\:/ {print $2; exit}' | cut -d'@' -f1 | head -n1
}
get_usb_iface() {
    ip link | awk -F': ' '/(^| )(usb[[:alnum:]_]*|rndis[[:alnum:]_]*|eth[[:alnum:]_]*)\:/ {print $2; exit}' | cut -d'@' -f1 | head -n1
}
get_hot_cidr() {
    ip -4 addr show dev "$1" | awk '/inet /{print $2; exit}'
}


set_nat_rules() {
    ET_IFACE=$(get_et_iface)
    [ -z "$ET_IFACE" ] && ET_IFACE="$(get_tun_iface)"
    HOT_IFACE=$(get_hot_iface)
    USB_IFACE=$(get_usb_iface)
    HOT_CIDR=$(get_hot_cidr "$HOT_IFACE")
    USB_CIDR=$(get_hot_cidr "$USB_IFACE")

    # 如果热点关闭就删除自定义链
   [ -n "$ET_IFACE" ] && { [ -n "$HOT_CIDR" ] || [ -n "$USB_CIDR" ]; } || return 1

    # 创建自定义链（如不存在）
    iptables -t nat -N ET_NAT 2>/dev/null
    iptables -N ET_FWD 2>/dev/null

    # 确保主链首条跳转到自定义链
    iptables -t nat -C POSTROUTING -j ET_NAT 2>/dev/null || \
        iptables -t nat -I POSTROUTING 1 -j ET_NAT
    iptables -C FORWARD -j ET_FWD 2>/dev/null || \
        iptables -I FORWARD 1 -j ET_FWD

    # 添加规则
    if [ -n "$HOT_CIDR" ]; then
        iptables -t nat -A ET_NAT -s "$HOT_CIDR" -o "$ET_IFACE" -j MASQUERADE
        iptables -A ET_FWD -i "$HOT_IFACE" -o "$ET_IFACE" \
            -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        iptables -A ET_FWD -i "$ET_IFACE" -o "$HOT_IFACE" \
            -m state --state ESTABLISHED,RELATED -j ACCEPT
        echo "[ET-NAT] Rules applied: $HOT_IFACE $HOT_CIDR ↔ $ET_IFACE" >> "$LOG_FILE"
    fi
    if [ -n "$USB_CIDR" ]; then
        iptables -t nat -A ET_NAT -s "$USB_CIDR" -o "$ET_IFACE" -j MASQUERADE
        iptables -A ET_FWD -i "$USB_IFACE" -o "$ET_IFACE" \
            -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
        iptables -A ET_FWD -i "$ET_IFACE" -o "$USB_IFACE" \
            -m state --state ESTABLISHED,RELATED -j ACCEPT
        echo "[ET-NAT] Rules applied: $USB_IFACE $USB_CIDR ↔ $ET_IFACE" >> "$LOG_FILE"
    fi
}

flush_rules() {
    iptables -t nat -F ET_NAT 2>/dev/null
    iptables -F ET_FWD 2>/dev/null
    echo "[ET-NAT] Custom chains flushed." >> "$LOG_FILE"
}

case "$ACTION" in
    add)
        set_nat_rules
        echo "[ET-NAT] Guard started." >> "$LOG_FILE"
        ip monitor link addr | while read -r _; do
            if [ -f "${MODDIR}/enable_IP_rule" ]; then
                flush_rules
                set_nat_rules
            fi
        done
        ;;
    add_once)
        flush_rules
        set_nat_rules
        echo "[ET-NAT] One-time rules applied." >> "$LOG_FILE"
        ;;
    del)
        flush_rules
        ;;
    *)
        echo "Usage: $0 [add|del]"
        exit 1
        ;;
esac
