#!/bin/bash
#
# EasyTier 节点刷新脚本
# 
# 这是一个简单的 Bash 脚本，用于定期从 HTTP/TXT/SRV 源获取节点列表
# 并更新 EasyTier 的连接器配置。
#
# 用法:
#   ./refresh-nodes.sh --config-url http://config-server.com/nodes
#   ./refresh-nodes.sh --config-url txt://txt.easytier.cn
#
# 依赖:
#   - curl
#   - dig (用于 DNS 查询)
#

set -e

# 默认配置
CONFIG_URL=""
API_ENDPOINT="http://127.0.0.1:15888"
INTERVAL=300
CURRENT_NODES_FILE="/tmp/easytier_current_nodes.txt"

# 日志函数
log_info() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $*"
}

log_warn() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $*" >&2
}

log_error() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*" >&2
}

# 解析命令行参数
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --config-url)
                CONFIG_URL="$2"
                shift 2
                ;;
            --api-endpoint)
                API_ENDPOINT="$2"
                shift 2
                ;;
            --interval)
                INTERVAL="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    if [[ -z "$CONFIG_URL" ]]; then
        log_error "--config-url is required"
        exit 1
    fi
}

# 从 HTTP 获取节点
fetch_http_nodes() {
    local url="$1"
    curl -s "$url" | grep -E '^(tcp|udp|ws|wss|quic|wg)://' || true
}

# 从 DNS TXT 记录获取节点
fetch_txt_nodes() {
    local domain="$1"
    
    if ! command -v dig &> /dev/null; then
        log_error "dig command not found. Please install dnsutils."
        return 1
    fi
    
    local txt_data
    txt_data=$(dig +short TXT "$domain" 2>/dev/null | tr -d '"' | tr '\n' ' ')
    
    if [[ -z "$txt_data" ]]; then
        log_warn "No TXT record found for $domain"
        return 1
    fi
    
    echo "$txt_data" | tr ' ' '\n' | grep -E '^(tcp|udp|ws|wss|quic|wg)://' || true
}

# 从 DNS SRV 记录获取节点
fetch_srv_nodes() {
    local domain="$1"
    
    if ! command -v dig &> /dev/null; then
        log_error "dig command not found. Please install dnsutils."
        return 1
    fi
    
    local protocols=("tcp" "udp" "ws" "wss" "quic")
    
    for proto in "${protocols[@]}"; do
        local srv_domain="_easytier._${proto}.${domain}"
        
        local srv_records
        srv_records=$(dig +short SRV "$srv_domain" 2>/dev/null || true)
        
        if [[ -n "$srv_records" ]]; then
            echo "$srv_records" | while read -r priority weight port target; do
                if [[ "$port" != "0" && -n "$target" ]]; then
                    target="${target%.}"
                    echo "${proto}://${target}:${port}"
                fi
            done
        fi
    done
}

# 获取节点列表
fetch_nodes() {
    local url="$1"
    local scheme="${url%%://*}"
    
    case "$scheme" in
        http|https)
            fetch_http_nodes "$url"
            ;;
        txt)
            local domain="${url#txt://}"
            fetch_txt_nodes "$domain"
            ;;
        srv)
            local domain="${url#srv://}"
            fetch_srv_nodes "$domain"
            ;;
        *)
            log_error "Unsupported scheme: $scheme"
            return 1
            ;;
    esac
}

# 添加连接器
add_connector() {
    local node_url="$1"
    local api_url="${API_ENDPOINT}/api/v1/instance/connector/add"
    
    if curl -s -X POST "$api_url" \
        -H "Content-Type: application/json" \
        -d "{\"url\": \"${node_url}\"}" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# 移除连接器
remove_connector() {
    local node_url="$1"
    local api_url="${API_ENDPOINT}/api/v1/instance/connector/remove"
    
    if curl -s -X POST "$api_url" \
        -H "Content-Type: application/json" \
        -d "{\"url\": \"${node_url}\"}" > /dev/null 2>&1; then
        return 0
    else
        return 1
    fi
}

# 同步节点
sync_nodes() {
    log_info "Syncing nodes from $CONFIG_URL"
    
    # 获取新的节点列表
    local new_nodes_file
    new_nodes_file=$(mktemp)
    
    if ! fetch_nodes "$CONFIG_URL" > "$new_nodes_file"; then
        log_warn "Failed to fetch nodes, keeping existing connections"
        rm -f "$new_nodes_file"
        return 1
    fi
    
    # 检查是否为空
    if [[ ! -s "$new_nodes_file" ]]; then
        log_warn "No nodes fetched, keeping existing connections"
        rm -f "$new_nodes_file"
        return 0
    fi
    
    # 读取当前节点
    touch "$CURRENT_NODES_FILE"
    
    # 计算需要添加和移除的节点
    local to_add to_remove
    to_add=$(comm -13 <(sort "$CURRENT_NODES_FILE") <(sort "$new_nodes_file"))
    to_remove=$(comm -23 <(sort "$CURRENT_NODES_FILE") <(sort "$new_nodes_file"))
    
    # 添加新节点
    if [[ -n "$to_add" ]]; then
        echo "$to_add" | while read -r node_url; do
            if [[ -n "$node_url" ]]; then
                if add_connector "$node_url"; then
                    log_info "Added connector: $node_url"
                else
                    log_warn "Failed to add connector: $node_url"
                fi
            fi
        done
    fi
    
    # 移除旧节点
    if [[ -n "$to_remove" ]]; then
        echo "$to_remove" | while read -r node_url; do
            if [[ -n "$node_url" ]]; then
                if remove_connector "$node_url"; then
                    log_info "Removed connector: $node_url"
                else
                    log_warn "Failed to remove connector: $node_url"
                fi
            fi
        done
    fi
    
    # 更新当前节点文件
    mv "$new_nodes_file" "$CURRENT_NODES_FILE"
    
    local total added removed
    total=$(wc -l < "$CURRENT_NODES_FILE" | tr -d ' ')
    added=$(echo "$to_add" | grep -c . || echo 0)
    removed=$(echo "$to_remove" | grep -c . || echo 0)
    
    log_info "Sync complete: added $added, removed $removed, total $total"
}

# 主函数
main() {
    parse_args "$@"
    
    log_info "Starting EasyTier Node Refresh Script"
    log_info "Config URL: $CONFIG_URL"
    log_info "API Endpoint: $API_ENDPOINT"
    log_info "Refresh Interval: ${INTERVAL}s"
    
    # 首次立即执行
    sync_nodes || true
    
    # 定期刷新
    while true; do
        sleep "$INTERVAL"
        sync_nodes || true
    done
}

main "$@"
