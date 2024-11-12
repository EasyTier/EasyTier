#!/bin/bash

# 生成配置文件模板
generate_config_template() {
    local mode="$1"
    local output_file="$2"
    
    # 创建基础配置
    cat > "$output_file" << EOF
[common]
network_name = "default"
network_secret = ""
dhcp = true
ipv4 = ""

[log]
level = "info"
file = ""

EOF

    # 根据模式添加特定配置
    case "$mode" in
        "server")
            cat >> "$output_file" << EOF
[[listeners]]
protocol = "tcp"
address = "0.0.0.0:11010"
EOF
            ;;
        "client"|"public_client")
            cat >> "$output_file" << EOF
[[peer]]
uri = ""
EOF
            ;;
    esac
}

# 创建服务文件
create_service_file() {
    local config_name="$1"
    local config_file="$INSTALL_PATH/config/${config_name}.conf"
    local runtime_dir="/run/easytier"
    
    # 创建并设置正确的目录权限
    install -d -m 755 "$runtime_dir"
    install -d -m 755 "$runtime_dir/${config_name}"
    chown root:root "$runtime_dir"
    chown root:root "$runtime_dir/${config_name}"
    
    # 创建服务文件
    cat > "/etc/systemd/system/easytier@${config_name}.service" << EOF
[Unit]
Description=EasyTier VPN Service (${config_name})
Documentation=https://www.easytier.top
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
RuntimeDirectory=easytier/${config_name}
RuntimeDirectoryMode=0755
WorkingDirectory=${INSTALL_PATH}

# 环境变量
Environment=EASYTIER_CONFIG=${config_file}

# 主程序
ExecStart=/usr/sbin/easytier-core -c ${config_file}

# 停止和重启设置
Restart=on-failure
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=10
KillMode=mixed
KillSignal=SIGTERM

# 资源限制
LimitNOFILE=65535
LimitNPROC=65535

# 安全设置
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # 设置服务文件权限
    chmod 644 "/etc/systemd/system/easytier@${config_name}.service"
    chown root:root "/etc/systemd/system/easytier@${config_name}.service"
    
    # 重载 systemd
    systemctl daemon-reload
    
    # 验证服务文件
    if ! systemctl cat "easytier@${config_name}.service" >/dev/null 2>&1; then
        echo -e "${RED_COLOR}服务文件创建失败${RES}"
        return 1
    fi
    
    echo -e "${GREEN_COLOR}服务文件创建成功: easytier@${config_name}.service${RES}"
    return 0
}

# 配置管理入口函数
configure_easytier() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      EasyTier 配置管理${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        echo -e "\n${BLUE_COLOR}配置选项：${RES}"
        echo "1. 创建新配置"
        echo "2. 修改现有配置"
        echo "3. 删除配置"
        echo "4. 查看配置"
        echo "5. 备份配置"
        echo "6. 恢复配置"
        echo "0. 返回主菜单"
        
        echo -n -e "\n请选择 [0-6]: "
        read choice
        
        case "$choice" in
            1) create_configuration ;;
            2) modify_configuration ;;
            3) delete_configuration ;;
            4) view_configuration ;;
            5) backup_configuration ;;
            6) restore_configuration ;;
            0) return 0 ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 创建配置文件的入口函数
create_configuration() {
    clear
    echo -e "${GREEN_COLOR}=================================${RES}"
    echo -e "${GREEN_COLOR}      创建 EasyTier 配置${RES}"
    echo -e "${GREEN_COLOR}=================================${RES}"
    
    echo -e "\n${YELLOW_COLOR}配置模式说明：${RES}"
    echo -e "${YELLOW_COLOR}1. 服务器模式${RES}"
    echo "   用于创建您自己的私有网络节点服务器"
    echo "   适合拥有公网IP的服务器，作为网络的中心节点"
    
    echo -e "\n${YELLOW_COLOR}2. 客户端模式${RES}"
    echo "   用于连接到已有的网络节点"
    echo "   可以连接到您的私有服务器或其他公开的节点"
    
    echo -e "\n${YELLOW_COLOR}3. 公共服务器模式${RES}"
    echo "   加入公共服务器节点集群，服务于社区"
    echo "   建议具有稳定公网IP的服务器选择此模式"
    echo "   您的节点将帮助其他用户获得更好的网络体验"
    
    echo -e "\n${YELLOW_COLOR}4. 公共客户端模式${RES}"
    echo "   连接到公共节点集群网络"
    echo "   特别适合没有公网IP的用户"
    echo "   可以利用公共节点集群获得稳定的网络服务"
    
    echo -e "\n${BLUE_COLOR}请选择${RES}"
    echo "1. 服务器模式 (创建新的网络)"
    echo "2. 客户端模式 (连接到现有网络)"
    echo "3. 公共服务器模式 (加入公共网络)"
    echo "4. 公共客户端模式 (连接公共节点)"
    echo "0. 返回上级菜单"
    
    echo -n -e "\n请选择 [0-4]: "
    read choice
    
    case "$choice" in
        1) create_server_config ;;
        2) create_client_config ;;
        3) create_public_server_config ;;
        4) create_public_client_config ;;
        0) return 0 ;;
        *)
            echo -e "${RED_COLOR}无效选项${RES}"
            sleep 1
            create_configuration
            ;;
    esac
}

# 创建服务器配置
create_server_config() {
    local config_dir="$INSTALL_PATH/config"
    mkdir -p "$config_dir"
    
    # 服务器模式命名规则
    local config_name="easytier_server"
    local num=1
    while [ -f "$config_dir/${config_name}.conf" ]; do
        config_name="easytier_server$num"
        ((num++))
    done
    
    echo -e "\n${BLUE_COLOR}创建服务器配置：${RES}"
    
    # 显示配置文件信息
    echo -e "\n${BLUE_COLOR}配置文件信息：${RES}"
    echo "置文件名: ${config_name}.conf"
    echo "配置文件路径: $config_dir/${config_name}.conf"
    echo -e "${YELLOW_COLOR}注意: 配置文件创建后可在上述路径找到${RES}"
    
    # 获取配置信息
    get_server_config_info "$config_dir/${config_name}.conf"
    
    # 创建服务文件
    create_service_file "$config_name"
    
    echo -e "\n${GREEN_COLOR}配置创建成功！${RES}"
    echo "配置文件: $config_dir/${config_name}.conf"
    
    # 启动服务
    echo -e "\n${BLUE_COLOR}正在启动服务...${RES}"
    systemctl enable "easytier@${config_name}" >/dev/null 2>&1
    if systemctl start "easytier@${config_name}"; then
        echo -e "${GREEN_COLOR}服务启动成功！${RES}"
        sleep 2  # 等待服务完全启动
        
        # 显示服务状态
        echo -e "\n${YELLOW_COLOR}服务状态：${RES}"
        systemctl status "easytier@${config_name}" --no-pager
        
        echo -e "\n${YELLOW_COLOR}文件位置：${RES}"
        echo "配置文件: $config_dir/${config_name}.conf"
        echo "服务文件: /etc/systemd/system/easytier@${config_name}.service"
        echo "运行目录: /run/easytier/${config_name}"
        
        # 获取服务器公网IP和配置信息
        local server_ip=$(curl -s ip.sb || curl -s ifconfig.me)
        local config_file="$config_dir/${config_name}.conf"
        local tcp_port=$(grep -A 5 "listeners = \[" "$config_file" | grep "tcp://" | cut -d':' -f3 | cut -d'"' -f1)
        local wg_port=$(grep "wireguard_listen" "$config_file" | cut -d'"' -f2 | cut -d':' -f2)
        local ws_port=$(grep -A 5 "listeners = \[" "$config_file" | grep "ws://" | cut -d':' -f3 | cut -d'/' -f1)
        local wss_port=$(grep -A 5 "listeners = \[" "$config_file" | grep "wss://" | cut -d':' -f3 | cut -d'/' -f1)
        local rpc_port=$(grep "rpc_portal" "$config_file" | cut -d'"' -f2 | cut -d':' -f2)
        local virtual_ip=$(grep "^ipv4 = " "$config_file" | cut -d'"' -f2)
        local network_name=$(grep "network_name" "$config_file" | cut -d'"' -f2)
        local network_secret=$(grep "network_secret" "$config_file" | cut -d'"' -f2)
        
        echo -e "\n${GREEN_COLOR}================== 客户端连接信息 ==================${RES}"
        echo -e "${YELLOW_COLOR}注意：客户端不要使用服务器虚拟IPv4${RES}"
        echo -e "${YELLOW_COLOR}客户端会自动获取或配置和服务器同网段虚拟IPv4${RES}"
        echo -e "${GREEN_COLOR}------------------------------------------------${RES}"
        if [ "$dhcp" = "true" ]; then
            echo -e "${GREEN_COLOR}虚拟IPv4: 自动分配 (DHCP)${RES}"
        else
            echo -e "${GREEN_COLOR}服务器虚拟IPv4: ${virtual_ip}${RES}"
        fi
        echo -e "${GREEN_COLOR}网络名称: ${network_name}${RES}"
        echo -e "${GREEN_COLOR}网络密钥: ${network_secret}${RES}"
        echo -e "${GREEN_COLOR}连接地址:${RES}"
        echo -e "${GREEN_COLOR}TCP: tcp://${server_ip}:${tcp_port}${RES}"
        echo -e "${GREEN_COLOR}UDP: udp://${server_ip}:${tcp_port}${RES}"
        echo -e "${GREEN_COLOR}WebSocket: ws://${server_ip}:${ws_port}${RES}"
        echo -e "${GREEN_COLOR}WebSocket(SSL): wss://${server_ip}:${wss_port}${RES}"
        echo -e "${GREEN_COLOR}RPC 管理端口: 127.0.0.1:${rpc_port}${RES}"
        echo -e "${GREEN_COLOR}================================================${RES}"

        echo -e "\n${YELLOW_COLOR}服务控制命令：${RES}"
        echo "启动服务: systemctl start easytier@${config_name}"
        echo "停止服务: systemctl stop easytier@${config_name}"
        echo "重启服务: systemctl restart easytier@${config_name}"
        echo "查看状态: systemctl status easytier@${config_name}"
        echo "查看日志: journalctl -u easytier@${config_name} -f"
        
        echo -e "\n${BLUE_COLOR}操作选项：${RES}"
        echo "1. 查看服务状态"
        echo "2. 查看详细日志"
        echo "3. 返回主菜单"
        echo "0. 退出"
        
        # 如果启用了 WireGuard，生成配置和二维码
        if grep -q "vpn_portal_config" "$config_dir/${config_name}.conf"; then
            generate_wireguard_config "$config_name" "$server_ip"
        fi
    else
        echo -e "${RED_COLOR}服务启动失败${RES}"
        echo -e "\n${YELLOW_COLOR}错误信息：${RES}"
        systemctl status "easytier@${config_name}" --no-pager
    fi
    
    while true; do
        echo -n -e "\n请选择 [0-3]: "
        read choice
        
        case "$choice" in
            1)
                systemctl status "easytier@${config_name}"
                echo -e "\n按回车键继续..."
                read
                ;;
            2)
                journalctl -u "easytier@${config_name}" -n 50 --no-pager
                echo -e "\n按回车键继续..."
                read
                ;;
            3)
                return 0
                ;;
            0)
                exit 0
                ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                ;;
        esac
    done
}

# 添加随机字符串生成函数
generate_random_string() {
    local length=$1
    cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $length | head -n 1
}

# 添加随机IP生成函数
generate_random_ip() {
    local network=$1
    local base_ip=$(echo $network | cut -d'/' -f1)
    local ip_parts=(${base_ip//./ })
    local last_octet=$((RANDOM % 254 + 1))  # 1-254之间的机数
    echo "${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.$last_octet"
}

# 添加配置文件验证函数
validate_config() {
    local config_file="$1"
    
    # 检查必要项
    local required_fields=(
        "instance_name"
        "hostname"
        "instance_id"
        "ipv4"
        "network_name"
        "network_secret"
    )
    
    echo -e "\n${BLUE_COLOR}验证配置文件...${RES}"
    
    for field in "${required_fields[@]}"; do
        if ! grep -q "^$field = " "$config_file"; then
            echo -e "${RED_COLOR}错误: 少必要配置项 $field${RES}"
            return 1
        fi
    done
    
    # 检查监听配置
    if ! grep -q "listeners = \[" "$config_file"; then
        echo -e "${RED_COLOR}错误: 缺少监听器置${RES}"
        return 1
    fi
    
    # 检查络身份配置
    if ! grep -q "\[network_identity\]" "$config_file"; then
        echo -e "${RED_COLOR}错误: 缺少网络身份配置${RES}"
        return 1
    fi
    
    return 0
}

# 修改生成服务器配置文件函数
generate_server_config() {
    local config_file="$1"
    local network_name="$2"
    local network_secret="$3"
    local dhcp="$4"
    local ipv4="$5"
    local tcp_port="$6"
    local wg_port="$7"
    local ws_port="$8"
    local wss_port="$9"
    local rpc_port="${10}"
    local enable_vpn_portal="${11}"
    local vpn_portal_config="${12}"
    local enable_proxy="${13}"
    local proxy_networks="${14}"
    
    # 从配置文件路径中提取配置名称
    local instance_name=$(basename "$config_file" .conf)
    
    # 生成配置文件
    cat > "$config_file" << EOF
# 实例名称，用于在同一台机器上标识此 VPN 节点
instance_name = "$instance_name"
# 主机名，用于标识此设备的主机名
hostname = "$(hostname)"
# 实例 ID，一般为 UUID，在同一个 VPN 网络中唯一
instance_id = "$(cat /proc/sys/kernel/random/uuid)"
# 此 VPN 节点的 IPv4 地址，如果为空，则此节点将仅转发数据包，不会创建 TUN 设备
ipv4 = "$ipv4"
# 由 Easytier 自动确定并设置IP地址默认从10.0.0.1开始
dhcp = $dhcp

# 监听器列表，于接受连接
listeners = [
    "tcp://0.0.0.0:${tcp_port}",
    "udp://0.0.0.0:${tcp_port}",
    "wg://0.0.0.0:${wg_port}",
    "ws://0.0.0.0:${ws_port}/",
    "wss://0.0.0.0:${wss_port}/"
]

# 退出节点列
exit_nodes = []

# 用于管理的 RPC 门户地址
rpc_portal = "127.0.0.1:${rpc_port}"

[network_identity]
# 网络名称，用于标识 VPN 网络
network_name = "$network_name"
# 网络密钥，用于验证此节点属于 VPN 网络
network_secret = "$network_secret"

$([ "$enable_vpn_portal" = "true" ] && echo "$vpn_portal_config")

[flags]
# 连接到对等节点使用的默认协议
default_protocol = "tcp"
# TUN 设备名称，如果为空，则使用默认名称
dev_name = ""
# 是否启用加密
enable_encryption = true
# 是否启用 IPv6 支持
enable_ipv6 = true
# TUN 设备 MTU
mtu = 1380
# 延迟优先模式，将尝试使用最低延迟路径转发流量，默认用最短路径
latency_first = false
# 将节点配置为退节点
enable_exit_node = false
# 禁用 TUN 设备
no_tun = false
# 为子网代理启用 smoltcp 堆栈
use_smoltcp = $enable_proxy
# 仅转发白名单网络的流量，支持通配符字符串
foreign_network_whitelist = "*"

[log]
level = "info"
file = ""

$([ "$enable_proxy" = "true" ] && echo "$proxy_networks")
EOF

    # 验证配置文件
    if ! validate_config "$config_file"; then
        echo -e "${RED_COLOR}配置文件验证败${RES}"
        return 1
    fi
    
    # 设置配置文件权限
    chmod 644 "$config_file"
    chown root:root "$config_file"
    
    echo -e "${GREEN_COLOR}配置文件生成成功${RES}"
    return 0
}

# 修改端口和IP冲突检查函数
check_port_and_ip_conflicts() {
    local current_config="$1"
    local tcp_port="$2"
    local wg_port="$3"
    local virtual_ip="$4"
    local rpc_port="$5"
    local ws_port="$6"
    local wss_port="$7"
    local config_dir="$INSTALL_PATH/config"
    local has_conflict=false

    echo -e "\n${BLUE_COLOR}检查端口和IP冲突...${RES}"
    
    # 检查TCP端口
    if ! check_port "$tcp_port"; then
        echo -e "${RED_COLOR}TCP/UDP端口 $tcp_port 已被占用${RES}"
        echo -e "${YELLOW_COLOR}占用详情：${RES}"
        netstat -tunlp | grep ":$tcp_port" || ss -tunlp | grep ":$tcp_port"
        local new_tcp_port=$(generate_random_port 10000)
        echo -e "${GREEN_COLOR}建议使用新端口: $new_tcp_port${RES}"
        echo -n "是否使用新端口？[Y/n]: "
        read confirm
        case "$confirm" in
            [Nn]*)
                echo "配置创建已取消"
                return 1
                ;;
            *)
                tcp_port=$new_tcp_port
                echo -e "${GREEN_COLOR}已更新TCP/UDP端口为: $tcp_port${RES}"
                ;;
        esac
    else
        echo -e "${GREEN_COLOR}TCP/UDP端口 $tcp_port 可用${RES}"
    fi

    # 检查WireGuard端口
    if ! check_port "$wg_port"; then
        echo -e "${RED_COLOR}WireGuard端口 $wg_port 已被占用${RES}"
        echo -e "${YELLOW_COLOR}占用详情：${RES}"
        netstat -tunlp | grep ":$wg_port" || ss -tunlp | grep ":$wg_port"
        local new_wg_port=$(generate_random_port 11000)
        echo -e "${GREEN_COLOR}建议使用新端口: $new_wg_port${RES}"
        echo -n "是否使用新端口？[Y/n]: "
        read confirm
        case "$confirm" in
            [Nn]*)
                echo "配置创建已取消"
                return 1
                ;;
            *)
                wg_port=$new_wg_port
                echo -e "${GREEN_COLOR}已更新WireGuard端口为: $wg_port${RES}"
                ;;
        esac
    else
        echo -e "${GREEN_COLOR}WireGuard端口 $wg_port 可用${RES}"
    fi

    # 检查WebSocket端口
    if ! check_port "$ws_port"; then
        echo -e "${RED_COLOR}WebSocket端口 $ws_port 已被占用${RES}"
        echo -e "${YELLOW_COLOR}占用详情：${RES}"
        netstat -tunlp | grep ":$ws_port" || ss -tunlp | grep ":$ws_port"
        local new_ws_port=$(generate_random_port 12000)
        echo -e "${GREEN_COLOR}建议使用新端口: $new_ws_port${RES}"
        echo -n "是否使用新端口？[Y/n]: "
        read confirm
        case "$confirm" in
            [Nn]*)
                echo "配置创建已取消"
                return 1
                ;;
            *)
                ws_port=$new_ws_port
                echo -e "${GREEN_COLOR}已更新WebSocket端口为: $ws_port${RES}"
                ;;
        esac
    else
        echo -e "${GREEN_COLOR}WebSocket端口 $ws_port 可用${RES}"
    fi

    # 检查WebSocket(SSL)端口
    if ! check_port "$wss_port"; then
        echo -e "${RED_COLOR}WebSocket(SSL)端口 $wss_port 已被占用${RES}"
        echo -e "${YELLOW_COLOR}占用详情：${RES}"
        netstat -tunlp | grep ":$wss_port" || ss -tunlp | grep ":$wss_port"
        local new_wss_port=$(generate_random_port 13000)
        echo -e "${GREEN_COLOR}建议使用新端口: $new_wss_port${RES}"
        echo -n "是使用新端口？[Y/n]: "
        read confirm
        case "$confirm" in
            [Nn]*)
                echo "置创建已取消"
                return 1
                ;;
            *)
                wss_port=$new_wss_port
                echo -e "${GREEN_COLOR}已更新WebSocket(SSL)端口为: $wss_port${RES}"
                ;;
        esac
    else
        echo -e "${GREEN_COLOR}WebSocket(SSL)端口 $wss_port 可用${RES}"
    fi

    # 检查RPC端口
    if ! check_port "$rpc_port"; then
        echo -e "${RED_COLOR}RPC端口 $rpc_port 已被占用${RES}"
        echo -e "${YELLOW_COLOR}用详情：${RES}"
        netstat -tunlp | grep ":$rpc_port" || ss -tunlp | grep ":$rpc_port"
        local new_rpc_port=$(generate_random_port 15000)
        echo -e "${GREEN_COLOR}建议使用新端口: $new_rpc_port${RES}"
        echo -n "是否使用新端口？[Y/n]: "
        read confirm
        case "$confirm" in
            [Nn]*)
                echo "配置创建已取消"
                return 1
                ;;
            *)
                rpc_port=$new_rpc_port
                echo -e "${GREEN_COLOR}已更新RPC端口为: $rpc_port${RES}"
                ;;
        esac
    else
        echo -e "${GREEN_COLOR}RPC端口 $rpc_port 可用${RES}"
    fi

    # 更新全局变量
    tcp_port_global=$tcp_port
    wg_port_global=$wg_port
    ws_port_global=$ws_port
    wss_port_global=$wss_port
    rpc_port_global=$rpc_port

    return 0
}

# 修改获取服务器配置信息函数
get_server_config_info() {
    local config_file="$1"
    
    # 显示分隔线
    echo -e "\n${GREEN_COLOR}--------------------------------${RES}"
    
    # 添加使用说明提示
    echo -e "\n${YELLOW_COLOR}=== 使用说明 ===${RES}"
    echo -e "${YELLOW_COLOR}1. 自动化配置向导，将引导您完成所有必要设置${RES}"
    echo -e "${YELLOW_COLOR}2. 每一步都有默认值，如果不确定可以直接按回车使用推荐配置${RES}"
    echo -e "${YELLOW_COLOR}3. 请仔细阅读每步的提示信息，所有配置后续都可以修改${RES}"
    echo -e "${YELLOW_COLOR}4. 配完成后请务必保存好网络名称和密钥信息${RES}"
    echo -e "${YELLOW_COLOR}5. 如有疑问，可以参考官方文档或联系技术支持${RES}"
    
    # 1. 网络设置
    echo -e "\n${BLUE_COLOR}网络设置：${RES}"
    echo -n "网络名称 [随机生成]: "
    read network_name
    # 如果用户未输入，生成带前缀的10位随机字符
    if [ -z "$network_name" ]; then
        network_name="ET_$(generate_random_string 10)"
    elif [[ ! $network_name =~ ^ET_ ]]; then
        # 如果用户输入的名称没有 ET_ 前缀，自动添加
        network_name="ET_${network_name}"
    fi
    
    echo -n "网络密钥 [随机生成]: "
    read network_secret
    # 如果用户未输入，生成15位随机字符串
    network_secret=${network_secret:-$(generate_random_string 15)}
    
    # 显示生成的值
    echo -e "\n${YELLOW_COLOR}网络名称: ${network_name}${RES}"
    echo -e "${YELLOW_COLOR}网络密钥: ${network_secret}${RES}"
    echo -e "\n请记住这些信息，客户接时需要使用。"
    
    # 2. 虚拟IPv4设置
    echo -e "\n${BLUE_COLOR}虚拟IPv4置：${RES}"
    echo "1. 动分配 (DHCP，从10.0.0.1开始)"
    echo "2. 手动设置 (推荐)"
    echo -n "请选择 [1/2] [默认: 2]: "
    read ip_choice
    
    local dhcp="true"
    local ipv4=""
    case "$ip_choice" in
        1)
            dhcp="true"
            ipv4=""
            ;;
        *) # 默认使用手动设置
            dhcp="false"
            echo -n "请输入虚拟IPv4地址 [回车随机生]: "
            read manual_ip
            if [ -n "$manual_ip" ]; then
                ipv4=$manual_ip
            else
                ipv4=$(generate_virtual_ip)
                echo -e "${GREEN_COLOR}已生成虚拟IPv4地址: $ipv4${RES}"
            fi
            
            # 验IP地址格式
            while [[ ! $ipv4 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; do
                echo -e "${RED_COLOR}效的IP地址格式${RES}"
                echo -n "请重新输入虚拟IPv4地址 [回车随机生成]: "
                read ipv4
                if [ -z "$ipv4" ]; then
                    ipv4=$(generate_virtual_ip)
                    echo -e "${GREEN_COLOR}已生成虚拟IPv4地址: $ipv4${RES}"
                    break
                fi
            done
            ;;
    esac
    
    # 3. 监听端口设置
    echo -e "\n${BLUE_COLOR}端口设置：${RES}"
    echo "默认端口配置："
    echo "TCP/UDP 监听端口: 11010"
    echo "WireGuard/WebSocket 监听端口: 11011"
    echo "WebSocket(SSL) 监听端口: 11012"
    echo "RPC 管理端口: 15888"
    echo -n "是否使用默认端口配置？[y/N]: "
    read use_default_ports
    
    local tcp_port=""
    local wg_port=""
    local ws_port=""
    local wss_port=""
    local rpc_port=""
    
    # 默认进入手动设置模式
    if [[ ! $use_default_ports =~ ^[Yy]$ ]]; then
        echo -n "TCP/UDP 监听口 [回车随机生成]: "
        read input_port
        if [ -n "$input_port" ]; then
            if check_port "$input_port"; then
                tcp_port=$input_port
            else
                echo -e "${RED_COLOR}端口 $input_port 已被占用，将随机生成端口${RES}"
                tcp_port=$(generate_random_port 10000)
            fi
        else
            tcp_port=$(generate_random_port 10000)
        fi
        echo -e "${GREEN_COLOR}TCP/UDP 监听端口: $tcp_port${RES}"
        
        echo -n "WireGuard/WebSocket 监听端口 [回车随机生成]: "
        read input_port
        if [ -n "$input_port" ]; then
            if check_port "$input_port"; then
                wg_port=$input_port
                ws_port=$input_port
            else
                echo -e "${RED_COLOR}端口 $input_port 已被占用，随机生成新端口${RES}"
                wg_port=$(generate_random_port 11000)
                ws_port=$wg_port
            fi
        else
            wg_port=$(generate_random_port 11000)
            ws_port=$wg_port
        fi
        echo -e "${GREEN_COLOR}WireGuard/WebSocket 监听端口: $wg_port${RES}"
        
        echo -n "WebSocket(SSL) 监听端口 [回车随机生成]: "
        read input_port
        if [ -n "$input_port" ]; then
            if check_port "$input_port"; then
                wss_port=$input_port
            else
                echo -e "${RED_COLOR}端口 $input_port 已被占用，将随机生成新端口${RES}"
                wss_port=$(generate_random_port 13000)
            fi
        else
            wss_port=$(generate_random_port 13000)
        fi
        echo -e "${GREEN_COLOR}WebSocket(SSL) 监听端口: $wss_port${RES}"
        
        echo -n "RPC 管理端口 [回车随机生成]: "
        read input_port
        if [ -n "$input_port" ]; then
            if check_port "$input_port"; then
                rpc_port=$input_port
            else
                echo -e "${RED_COLOR}端口 $input_port 已被占用，将随机生成新端口${RES}"
                rpc_port=$(generate_random_port 15000)
            fi
        else
            rpc_port=$(generate_random_port 15000)
        fi
        echo -e "${GREEN_COLOR}RPC 管理端口: $rpc_port${RES}"
    else
        # 使用默认端口，但需要检查是否被占用
        if check_port "11010"; then
            tcp_port="11010"
        else
            echo -e "${RED_COLOR}默认 TCP/UDP 端口被占用，将随机生成新端口${RES}"
            tcp_port=$(generate_random_port 10000)
        fi
        
        if check_port "11011"; then
            wg_port="11011"
            ws_port="11011"
        else
            echo -e "${RED_COLOR}默认 WireGuard/WebSocket 端口被占用，将随机生成新端口${RES}"
            wg_port=$(generate_random_port 11000)
            ws_port=$wg_port
        fi
        
        if check_port "11012"; then
            wss_port="11012"
        else
            echo -e "${RED_COLOR}默认 WebSocket(SSL) 端口被占用，将随机生成新端口${RES}"
            wss_port=$(generate_random_port 13000)
        fi
        
        if check_port "15888"; then
            rpc_port="15888"
        else
            echo -e "${RED_COLOR}默认 RPC 端口被占用，将随生成新端口${RES}"
            rpc_port=$(generate_random_port 15000)
        fi
        
        echo -e "\n${GREEN_COLOR}最终端口配置：${RES}"
        echo "TCP/UDP 监听端口: $tcp_port"
        echo "WireGuard 监听端口: $wg_port"
        echo "WebSocket 监听端口: $ws_port"
        echo "WebSocket(SSL) 监听端口: $wss_port"
        echo "RPC 管理端口: $rpc_port"
    fi
    
    # 4. 询问是否配置 WireGuard
    local enable_wireguard="false"
    local wireguard_config=""
    echo -e "\n${BLUE_COLOR}WireGuard 配置：${RES}"
    echo -n "是否启用 WireGuard？[y/N]: "
    read enable_wg
    
    if [[ $enable_wg =~ ^[Yy]$ ]]; then
        enable_wireguard="true"
        echo -n "请输入客户端网段 [回车机生成]: "
        read manual_cidr
        if [ -n "$manual_cidr" ]; then
            client_cidr="$manual_cidr"
        else
            client_cidr=$(generate_wireguard_cidr)
            echo -e "${GREEN_COLOR}已生成客户端网段: $client_cidr${RES}"
        fi
        
        wireguard_config="# WireGuard 配置 (由 EasyTier 管理)
[vpn_portal_config]
# VPN客端所在的网段
client_cidr = \"$client_cidr\"
# wg所监听的端口
wireguard_listen = \"0.0.0.0:$wg_port\""
    fi
    
    # 5. 询问是否配置子网代理
    local enable_proxy="false"
    local proxy_networks=""
    echo -e "\n${BLUE_COLOR}子网代理配置：${RES}"
    echo -n "是否启用子网代？[y/N]: "
    read enable_proxy_choice
    
    if [[ $enable_proxy_choice =~ ^[Yy]$ ]]; then
        enable_proxy="true"
        echo "请输入要代理的子网 CIDR (每行一个，输入空行成)："
        while true; do
            echo -n "CIDR (留空完成): "
            read proxy_cidr
            if [ -z "$proxy_cidr" ]; then
                break
            fi
            proxy_networks="${proxy_networks}[[proxy_network]]
cidr = \"$proxy_cidr\"

"
        done
    fi
    
    # 生成配置文件前检查冲突
    if ! check_port_and_ip_conflicts "$config_file" "$tcp_port" "$wg_port" "$ipv4" "$rpc_port" "$ws_port" "$wss_port"; then
        echo -e "\n${RED_COLOR}配置冲突，是否重新生成端口IP？[Y/n]: ${RES}"
        read regenerate
        case "$regenerate" in
            [Nn]*)
                echo "配置创建已取消"
                return 1
                ;;
            *)
                # 重新生成端口
                tcp_port=$(generate_random_port 10000)
                wg_port=$(generate_random_port 11000)
                ws_port=$(generate_random_port 12000)
                wss_port=$(generate_random_port 13000)
                rpc_port=$(generate_random_port 15000)
                
                # 重新生成IP
                if [ "$dhcp" = "false" ]; then
                    ipv4=$(generate_virtual_ip)
                fi
                
                echo -e "\n${GREEN_COLOR}新生成的配置：${RES}"
                echo "TCP/UDP 端口: $tcp_port"
                echo "WireGuard 端口: $wg_port"
                echo "WebSocket 端口: $ws_port"
                echo "WebSocket(SSL) 端口: $wss_port"
                echo "RPC 端口: $rpc_port"
                [ "$dhcp" = "false" ] && echo "虚拟IP: $ipv4"
                
                echo -n "是否使用这些新配置？[Y/n]: "
                read confirm
                case "$confirm" in
                    [Nn]*)
                        echo "配置创建已取消"
                        return 1
                        ;;
                esac
        esac
    fi
    
    # 生成配置文件
    generate_server_config "$config_file" "$network_name" "$network_secret" "$dhcp" "$ipv4" \
        "$tcp_port" "$wg_port" "$ws_port" "$wss_port" "$rpc_port" \
        "$enable_wireguard" "$wireguard_config" \
        "$enable_proxy" "$proxy_networks"
    
    echo -e "\n${GREEN_COLOR}配置文件已生成：${RES} $config_file"
    echo -e "请检查配置文件内容是否正确。"

    echo -n "按回车键续..."
    read
}

# 添加虚拟IP网段生成函数
generate_virtual_ip() {
    local virtual_networks=(
        "10.10.0.0/24"
        "10.11.0.0/24"
        "10.12.0.0/24"
        "10.13.0.0/24"
        "10.20.0.0/24"
        "100.100.0.0/24"
        "100.101.0.0/24"
        "100.102.0.0/24"
        "100.103.0.0/24"
        "100.104.0.0/24"
        "192.168.100.0/24"
        "192.168.101.0/24"
        "192.168.102.0/24"
        "192.168.103.0/24"
        "192.168.104.0/24"
    )
    local network=${virtual_networks[$((RANDOM % ${#virtual_networks[@]}))]}
    local base_ip=$(echo $network | cut -d'/' -f1)
    local ip_parts=(${base_ip//./ })
    local last_octet=$((RANDOM % 254 + 1))
    echo "${ip_parts[0]}.${ip_parts[1]}.${ip_parts[2]}.$last_octet"
}

# 添加 WireGuard 网段生成函数
generate_wireguard_cidr() {
    local wireguard_networks=(
        "10.14.14.0/24"
        "10.15.15.0/24"
        "10.16.16.0/24"
        "10.17.17.0/24"
        "10.18.18.0/24"
        "172.16.14.0/24"
        "172.16.15.0/24"
        "172.16.16.0/24"
        "172.16.17.0/24"
        "172.16.17.0/24"
        "172.20.0.0/24"
        "172.21.0.0/24"
        "172.22.0.0/24"
        "172.23.0.0/24"
        "172.24.0.0/24"
    )
    echo "${wireguard_networks[$((RANDOM % ${#wireguard_networks[@]}))]}"
}

# 添加随机端口生成函数
generate_random_port() {
    local base_port=$1
    local range=1000
    while true; do
        # 生成一个基于基础端口的随机端口
        local port=$((base_port + RANDOM % range))
        # 检查端口是否被占用
        if check_port "$port"; then
            echo "$port"
            return 0
        fi
    done
}

# 启动服务
start_service() {
    local config_name="$1"
    local config_file="$INSTALL_PATH/config/${config_name}.conf"
    
    # 检查配置文件
    if ! validate_config "$config_file"; then
        return 1
    fi
    
    # 检查配置文件内容
    echo -e "${BLUE_COLOR}配置文件内容：${RES}"
    cat "$config_file"
    
    # 检查运行目录
    local runtime_dir="/run/easytier/${config_name}"
    if [ ! -d "$runtime_dir" ]; then
        mkdir -p "$runtime_dir"
        chmod 755 "$runtime_dir"
        chown root:root "$runtime_dir"
    fi
    
    # 检查端口占用
    local tcp_port=$(grep -A 5 "listeners = \[" "$config_file" | grep "tcp://" | grep -oE '[0-9]+' | head -1)
    if ! check_port "$tcp_port"; then
        echo -e "${RED_COLOR}错误: TCP端口 $tcp_port 已被占用${RES}"
        return 1
    fi
    
    # 检查虚拟IP冲突
    local virtual_ip=$(grep "^ipv4 = " "$config_file" | cut -d'"' -f2)
    if [ -n "$virtual_ip" ]; then
        for conf in "$INSTALL_PATH/config"/*.conf; do
            if [ "$conf" != "$config_file" ] && grep -q "^ipv4 = \"$virtual_ip\"" "$conf"; then
                echo -e "${RED_COLOR}错误: 虚拟IP $virtual_ip 已被其他配置使用${RES}"
                return 1
            fi
        done
    fi
    
    # 启动服务
    echo -e "${BLUE_COLOR}正在启动服务...${RES}"
    if ! systemctl start "easytier@${config_name}"; then
        echo -e "${RED_COLOR}服务启动失败${RES}"
        echo -e "\n${YELLOW_COLOR}错误日志：${RES}"
        journalctl -u "easytier@${config_name}" -n 50 --no-pager
        return 1
    fi
    
    # 待服务启动
    sleep 2
    if ! systemctl is-active --quiet "easytier@${config_name}"; then
        echo -e "${RED_COLOR}服务启动失败${RES}"
        echo -e "\n${YELLOW_COLOR}错误日志：${RES}"
        journalctl -u "easytier@${config_name}" -n 50 --no-pager
        return 1
    fi
    
    echo -e "${GREEN_COLOR}服务启动成功${RES}"
    return 0
}

# 添加 qrencode 安装函数
install_qrencode() {
    echo -e "${YELLOW_COLOR}未检测到 qrencode，是否安装？[Y/n]: ${RES}"
    read install_choice
    
    case "$install_choice" in
        [Nn]*)
            echo -e "${YELLOW_COLOR}跳过安装 qrencode，将不会生成二维码${RES}"
            return 1
            ;;
        *)
            echo -e "${BLUE_COLOR}正在安装 qrencode...${RES}"
            if command -v apt >/dev/null 2>&1; then
                apt update && apt install -y qrencode
            elif command -v yum >/dev/null 2>&1; then
                yum install -y qrencode
            elif command -v dnf >/dev/null 2>&1; then
                dnf install -y qrencode
            else
                echo -e "${RED_COLOR}无法确定包管理器，请手动安装 qrencode${RES}"
                return 1
            fi
            
            if command -v qrencode >/dev/null 2>&1; then
                echo -e "${GREEN_COLOR}qrencode 安装成功${RES}"
                return 0
            else
                echo -e "${RED_COLOR}qrencode 安装失败${RES}"
                return 1
            fi
            ;;
    esac
}

# 修改 WireGuard 配置生成函数，移除二维码生成部分
generate_wireguard_config() {
    local config_name="$1"
    local server_ip="$2"
    local config_file="$INSTALL_PATH/config/${config_name}.conf"
    
    # 创建 WireGuard 配置目录
    local wg_dir="$INSTALL_PATH/wireguard"
    mkdir -p "$wg_dir"
    
    # 从配置文件中读取端口信息
    local wg_port=$(grep "wireguard_listen" "$config_file" | cut -d'"' -f2 | cut -d':' -f2)
    local rpc_port=$(grep "rpc_portal" "$config_file" | cut -d'"' -f2 | cut -d':' -f2)
    
    # 生成 WireGuard 配置 - 使用正确的 RPC 端口
    local wg_info=$(cd "$INSTALL_PATH" && ./easytier-cli -p "127.0.0.1:$rpc_port" vpn-portal)
    
    if [ $? -eq 0 ] && [ -n "$wg_info" ]; then
        # 修改配置内容，确保格式正确
        local modified_wg_info=$(echo "$wg_info" | \
            sed "s/0.0.0.0:/${server_ip}:/g" | \
            sed 's/# should assign an ip from this cidr manually//g' | \
            sed 's/# should be the public ip(or domain) of the vpn server//g' | \
            sed '/^$/d' | \
            sed 's/\[Interface\]/[Interface]\n/g' | \
            sed 's/\[Peer\]/\n[Peer]\n/g')
        
        # 保存配置文件
        local wg_config_file="$wg_dir/${config_name}.conf"
        echo "$modified_wg_info" > "$wg_config_file"
        
        echo -e "\n${GREEN_COLOR}WireGuard 配置信息：${RES}"
        echo "$modified_wg_info"
        echo -e "\n${GREEN_COLOR}WireGuard 配置文件已保存到：${RES} $wg_config_file"
    else
        echo -e "${RED_COLOR}WireGuard 配置生成失败${RES}"
        echo -e "${YELLOW_COLOR}错误信息：${RES}"
        echo "$wg_info"
    fi
}

# 修改完全卸载函数
perform_full_uninstall() {
    echo -e "\n${YELLOW_COLOR}警告：这将删除所有 EasyTier 相关文件，包括：${RES}"
    echo "- 主程序文件"
    echo "- 所有配置文件"
    echo "- 服务文件"
    echo "- 系统链接"
    echo "- WireGuard 配置文件"
    echo "- 运行时目录"
    echo "- 日志文件"
    echo "- 缓存文件"
    echo -e "\n${GREEN_COLOR}注意：备份文件将会保留${RES}"
    
    echo -n -e "\n${RED_COLOR}确认完全卸载？[Y/n]: ${RES}"
    read confirm
    case "$confirm" in
        [Yy]*)
            # 停止所有服务
            echo -e "\n${BLUE_COLOR}正在停止所有服务...${RES}"
            systemctl stop 'easytier@*'
            systemctl disable 'easytier@*' >/dev/null 2>&1
            
            # 删除主程序文件
            echo -e "${BLUE_COLOR}正在删除主程序文件...${RES}"
            rm -rf "$INSTALL_PATH/bin"
            rm -rf "$INSTALL_PATH/config"
            rm -rf "$INSTALL_PATH/wireguard"
            rm -f /usr/bin/easytier-core
            rm -f /usr/bin/easytier-cli
            rm -f /usr/sbin/easytier-core
            rm -f /usr/sbin/easytier-cli
            
            # 删除服务文件
            echo -e "${BLUE_COLOR}正在删除服务文件...${RES}"
            rm -f /etc/systemd/system/easytier@*.service
            systemctl daemon-reload
            
            # 删除运行时目录
            echo -e "${BLUE_COLOR}正在删除运行时目录...${RES}"
            rm -rf /run/easytier
            
            # 删除日志文件
            echo -e "${BLUE_COLOR}正在删除日志文件...${RES}"
            rm -rf /var/log/easytier
            journalctl --vacuum-time=1s
            
            # 删除临时文件和缓存
            echo -e "${BLUE_COLOR}正在删除临时文件和缓存...${RES}"
            rm -f /tmp/easytier_*
            rm -rf /tmp/easytier-*
            
            # 清理系统配置
            echo -e "${BLUE_COLOR}正在清理系统配置...${RES}"
            rm -f /etc/sysctl.d/99-easytier.conf
            sysctl --system >/dev/null 2>&1
            
            # 检查是否还有遗留文件（排除备份文件）
            echo -e "${BLUE_COLOR}正在检查遗留文件...${RES}"
            local leftover_files=$(find / -name "easytier*" -not -path "*/backup*" -not -name "*.bak*" 2>/dev/null)
            if [ -n "$leftover_files" ]; then
                echo -e "${YELLOW_COLOR}发现以下遗留文件：${RES}"
                echo "$leftover_files"
                echo -n "是否删除这些文件？[Y/n]: "
                read clean_confirm
                if [[ $clean_confirm =~ ^[Yy]$ ]]; then
                    while IFS= read -r file; do
                        if [[ ! "$file" =~ (backup|\.bak) ]]; then
                            rm -rf "$file"
                        fi
                    done <<< "$leftover_files"
                fi
            fi
            
            echo -e "\n${GREEN_COLOR}完全卸载成功！${RES}"
            echo "所有 EasyTier 相关文件已被理（备份文件已保留）"
            echo -e "${YELLOW_COLOR}备份文件位置：${RES}"
            echo "- $HOME/.easytier_backup/"
            echo "- 各配置文件的 .bak 文件"
            ;;
        *)
            echo "卸载已取消"
            ;;
    esac
}

# 添加修改配置函数
modify_configuration() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      修改 EasyTier 配置${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        # 列出现有配置
        echo -e "\n${BLUE_COLOR}现有配置：${RES}"
        local configs=()
        local i=1
        
        # 修正配置件路径为 /opt/easytier/config
        local config_dir="/opt/easytier/config"
        
        # 检查配置目录是否存在 - 修复语法错误
        if [ ! -d "$config_dir" ]; then
            echo -e "${RED_COLOR}错误：配置目录 $config_dir 不存在${RES}"
            echo -e "\n按回车键继续..."
            read
            return
        fi
        
        while IFS= read -r file; do
            if [[ $file == *.conf ]]; then
                configs+=("$config_dir/$file")  # 使用完整路径
                local config_name=$(basename "$file" .conf)
                if systemctl is-active --quiet "easytier@${config_name}"; then
                    echo -e "$i. ${config_name} [${GREEN_COLOR}运行中${RES}]"
                else
                    echo -e "$i. ${config_name} [${RED_COLOR}已停止${RES}]"
                fi
                ((i++))
            fi
        done < <(ls -1 "$config_dir")
        
        if [ ${#configs[@]} -eq 0 ]; then
            echo "暂无配置文件"
            echo -e "\n按回车键继续..."
            read
            return
        fi
        
        echo -e "\n0. 返回上级菜单"
        echo -n "请选择要修改的配置 [0-$((i-1))]: "
        read choice
        
        if [ "$choice" = "0" ]; then
            return
        elif [ "$choice" -ge 1 ] && [ "$choice" -le $((i-1)) ]; then
            local config_file="${configs[$((choice-1))]}"
            local config_name=$(basename "$config_file" .conf)
            
            echo -e "\n${BLUE_COLOR}选择的配置文件：${RES}${config_file}"
            
            # 检查文件是否存在和可读
            if [ ! -f "$config_file" ]; then
                echo -e "${RED_COLOR}错误：配置文件不存在${RES}"
                sleep 2
                continue
            fi
            
            if [ ! -r "$config_file" ]; then
                echo -e "${RED_COLOR}错误：无法读取配置文件，请检查权限${RES}"
                sleep 2
                continue
            fi
            
            # 检查服务状态
            if systemctl is-active --quiet "easytier@${config_name}"; then
                echo -e "\n${YELLOW_COLOR}警告：该配置当前正在运行${RES}"
                echo -e "建议在修改配置前停止服务，以防止配置冲突"
                echo -n "是否停止服务后继续？[y/N]: "
                read stop_confirm
                case "$stop_confirm" in
                    [Yy]*)
                        systemctl stop "easytier@${config_name}"
                        echo -e "${GREEN_COLOR}服务已停止${RES}"
                        ;;
                    *)
                        echo -e "${YELLOW_COLOR}继续修改配置，但可能会造成服务异常${RES}"
                        ;;
                esac
            fi
            
            # 创建配置文件备份
            local backup_file="${config_file}.bak.$(date +%Y%m%d_%H%M%S)"
            if ! cp "$config_file" "$backup_file"; then
                echo -e "${RED_COLOR}错误：无法创建配置备份${RES}"
                sleep 2
                continue
            fi
            echo -e "\n${GREEN_COLOR}已创建配置备份：${RES}${backup_file}"
            
            # 使用 vim 编辑配置文件
            if command -v vim >/dev/null 2>&1; then
                echo -e "\n${BLUE_COLOR}正在使用 vim 打开配置文件...${RES}"
                echo -e "${YELLOW_COLOR}提示：按 i 进入编辑模式，编辑完成后按 ESC 键退出编辑模式${RES}"
                echo -e "${YELLOW_COLOR}      输入 :wq 保存并退出，输入 :q! 不保存退${RES}"
                sleep 2
                vim "$config_file"
                
                # 检查配置文件是否被改
                if ! cmp -s "$config_file" "$backup_file"; then
                    echo -e "\n${GREEN_COLOR}配置文件已修改${RES}"
                    echo -n "是否重启服务以应用新配置？[Y/n]: "
                    read restart_confirm
                    case "$restart_confirm" in
                        [Nn]*)
                            echo -e "${YELLOW_COLOR}配置已保存，但需要手动重启服才能生效${RES}"
                            ;;
                        *)
                            if systemctl restart "easytier@${config_name}"; then
                                echo -e "${GREEN_COLOR}服务已重启${RES}"
                                sleep 1
                                systemctl status "easytier@${config_name}" --no-pager
                            else
                                echo -e "${RED_COLOR}服务重启失败，请检查配置是否正确${RES}"
                                echo -e "${YELLOW_COLOR}可以使用以下命令查看详细错误信息：${RES}"
                                echo "journalctl -u easytier@${config_name} -n 50 --no-pager"
                            fi
                            ;;
                    esac
                else
                    echo -e "\n${YELLOW_COLOR}配置文件未发生变化${RES}"
                    rm -f "$backup_file"  # 删除未使用的备份
                fi
            else
                echo -e "${RED_COLOR}错误：未找到 vim 编辑器${RES}"
                echo -e "请先安装 vim：${YELLOW_COLOR}apt-get install vim${RES} 或 ${YELLOW_COLOR}yum install vim${RES}"
                sleep 2
            fi
            
            echo -e "\n按回车键继续..."
            read
        else
            echo -e "${RED_COLOR}无效选择${RES}"
            sleep 1
        fi
    done
}

# 修改删除配置函数
delete_configuration() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      删除 EasyTier 配置${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        # 列出现有配置
        echo -e "\n${BLUE_COLOR}现有配置：${RES}"
        local configs=()
        local i=1
        local config_dir="/opt/easytier/config"
        
        # 检查配置目录是否存在
        if [ ! -d "$config_dir" ]; then
            echo -e "${RED_COLOR}错误：配置目录 $config_dir 不存在${RES}"
            echo -e "\n按回车键继续..."
            read
            return
        fi
        
        while IFS= read -r file; do
            if [[ $file == *.conf ]]; then
                configs+=("$config_dir/$file")
                local config_name=$(basename "$file" .conf)
                if systemctl is-active --quiet "easytier@${config_name}"; then
                    echo -e "$i. ${config_name} [${GREEN_COLOR}运行中${RES}]"
                else
                    echo -e "$i. ${config_name} [${RED_COLOR}已停止${RES}]"
                fi
                ((i++))
            fi
        done < <(ls -1 "$config_dir")
        
        if [ ${#configs[@]} -eq 0 ]; then
            echo "暂无配置文件"
            echo -e "\n按回车键继续..."
            read
            return
        fi
        
        echo -e "\n0. 返回上级菜单"
        echo -n "请选择要删除的配置 [0-$((i-1))]: "
        read choice
        
        if [ "$choice" = "0" ]; then
            return
        elif [ "$choice" -ge 1 ] && [ "$choice" -le $((i-1)) ]; then
            local config_file="${configs[$((choice-1))]}"
            local config_name=$(basename "$config_file" .conf)
            
            echo -e "\n${RED_COLOR}警告：此操作将删除以下内容：${RES}"
            echo "1. 配置文件: $config_file"
            echo "2. 服务文件: /etc/systemd/system/easytier@${config_name}.service"
            echo "3. 运行时目录: /run/easytier/${config_name}"
            echo "4. WireGuard配置: /opt/easytier/wireguard/${config_name}.conf"
            echo "5. 相关日志文件"
            echo "6. 备份文件"
            
            echo -e "\n${YELLOW_COLOR}此操作不可恢复！${RES}"
            echo -n "确认删除？[y/N]: "
            read del_confirm
            
            case "$del_confirm" in
                [Yy]*)
                    # 1. 停止并禁用服务
                    echo -e "\n${BLUE_COLOR}正在停止服务...${RES}"
                    systemctl stop "easytier@${config_name}" 2>/dev/null
                    systemctl disable "easytier@${config_name}" 2>/dev/null
                    
                    # 2. 删除服务文件
                    echo -e "${BLUE_COLOR}正在删除服务文件...${RES}"
                    rm -f "/etc/systemd/system/easytier@${config_name}.service"
                    systemctl daemon-reload
                    
                    # 3. 删除配置文件
                    echo -e "${BLUE_COLOR}正在删除配置文件...${RES}"
                    rm -f "$config_file"
                    rm -f "${config_file}.bak"*  # 删除所有备份文件
                    
                    # 4. 删除运行时目录
                    echo -e "${BLUE_COLOR}正在删除运行时目录...${RES}"
                    rm -rf "/run/easytier/${config_name}"
                    
                    # 5. 删除WireGuard配置
                    echo -e "${BLUE_COLOR}正在删除WireGuard配置...${RES}"
                    rm -f "/opt/easytier/wireguard/${config_name}.conf"
                    rm -f "/tmp/easytier_wg_${config_name}"*
                    
                    # 6. 清理日志
                    echo -e "${BLUE_COLOR}正在清理日志...${RES}"
                    journalctl --vacuum-time=1s -u "easytier@${config_name}" 2>/dev/null
                    
                    # 7. 检查是否还有相关文件
                    local leftover_files=$(find /opt/easytier -name "*${config_name}*" 2>/dev/null)
                    if [ -n "$leftover_files" ]; then
                        echo -e "\n${YELLOW_COLOR}发现以下相关文件：${RES}"
                        echo "$leftover_files"
                        echo -n "是否删除这些文件？[Y/n]: "
                        read clean_confirm
                        if [[ ! $clean_confirm =~ ^[Nn]$ ]]; then
                            find /opt/easytier -name "*${config_name}*" -exec rm -rf {} + 2>/dev/null
                        fi
                    fi
                    
                    echo -e "\n${GREEN_COLOR}配置删除完成！${RES}"
                    sleep 1
                    ;;
                *)
                    echo -e "\n${YELLOW_COLOR}操作已取消${RES}"
                    sleep 1
                    ;;
            esac
        else
            echo -e "${RED_COLOR}无效选择${RES}"
            sleep 1
        fi
    done
}

# 添加查看配置函数
view_configuration() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      查看 EasyTier 配置${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        # 列出现有配置
        echo -e "\n${BLUE_COLOR}现有配置：${RES}"
        local configs=()
        local i=1
        while IFS= read -r file; do
            if [[ $file == *.conf ]]; then
                configs+=("$file")
                local config_name=$(basename "$file" .conf)
                if systemctl is-active --quiet "easytier@${config_name}"; then
                    echo -e "$i. ${config_name} [${GREEN_COLOR}运行中${RES}]"
                else
                    echo -e "$i. ${config_name} [${RED_COLOR}已停止${RES}]"
                fi
                ((i++))
            fi
        done < <(ls -1 "$INSTALL_PATH/config")
        
        if [ ${#configs[@]} -eq 0 ]; then
            echo "暂无配置文件"
            echo -e "\n按回车键继续..."
            read
            return
        fi
        
        echo -e "\n0. 返回上级菜单"
        echo -n "请选择要查看的配置 [0-$((i-1))]: "
        read choice
        
        if [ "$choice" = "0" ]; then
            return
        elif [ "$choice" -ge 1 ] && [ "$choice" -le $((i-1)) ]; then
            echo -e "\n${BLUE_COLOR}配置文件内容：${RES}"
            echo "----------------------------------------"
            cat "$INSTALL_PATH/config/$(basename "${configs[$((choice-1))]}")"
            echo "----------------------------------------"
            echo -e "\n按回车键继续..."
            read
        else
            echo -e "${RED_COLOR}无效选择${RES}"
            sleep 1
        fi
    done
}

# 添加客户端配置创建函数
create_client_config() {
    local config_dir="$INSTALL_PATH/config"
    mkdir -p "$config_dir"
    
    # 客户端模式命名规则
    local config_name="easytier_client"
    local num=1
    while [ -f "$config_dir/${config_name}.conf" ]; do
        config_name="easytier_client$num"
        ((num++))
    done
    
    echo -e "\n${GREEN_COLOR}================== 创建客户端配置 ==================${RES}"
    
    # 显示配置文件信息
    echo -e "\n${BLUE_COLOR}【配置文件信息】${RES}"
    echo "配置文件名: ${config_name}.conf"
    echo "配置文件路径: $config_dir/${config_name}.conf"
    echo -e "${YELLOW_COLOR}注意: 配置文件创建后可在上述路径找到${RES}"
    
    # 1. 基础信息设置
    echo -e "\n${BLUE_COLOR}【基础信息设置】${RES}"
    # 添加主机名称设置
    echo -n "主机名称 [默认: $(hostname)]: "
    read custom_hostname
    local hostname_value=${custom_hostname:-$(hostname)}
    echo -e "${GREEN_COLOR}已设置主机名称: $hostname_value${RES}"
    
    # 2. 网络信息设置
    echo -e "\n${BLUE_COLOR}【网络信息设置】${RES}"
    
    echo -n "网络名称 [随机生成]: "
    read network_name
    # 如果用户未输入，生成带前缀的10位随机字符串
    if [ -z "$network_name" ]; then
        network_name="ET_$(generate_random_string 10)"
    elif [[ ! $network_name =~ ^ET_ ]]; then
        # 如果用户输入的名称没有 ET_ 前缀，自动添加
        network_name="ET_${network_name}"
    fi
    
    echo -n "网络密钥 [随机生成]: "
    read network_secret
    # 如果用户未输入，生成15位随机字符串
    network_secret=${network_secret:-$(generate_random_string 15)}
    
    # 显示生成的值
    echo -e "\n${YELLOW_COLOR}网络名称: ${network_name}${RES}"
    echo -e "${YELLOW_COLOR}网络密钥: ${network_secret}${RES}"
    
    # 3. 虚拟IPv4设置
    echo -e "\n${BLUE_COLOR}【虚拟IPv4设置】${RES}"
    echo "1. 自动分配 (DHCP)"
    echo "2. 手动设置 (推荐)"
    echo -n "请选择 [1/2] [默认: 2]: "
    read ip_choice
    
    local dhcp="false"
    local ipv4=""
    case "$ip_choice" in
        1)
            dhcp="true"
            ipv4=""
            echo -e "${YELLOW_COLOR}已选择DHCP自动分配IP${RES}"
            ;;
        ""|2)  # 空输入或2都使用手动设置
            dhcp="false"
            echo -n "请输入虚拟IPv4地址 [回车随机生成]: "
            read ipv4
            if [ -z "$ipv4" ]; then
                ipv4=$(generate_virtual_ip)
                echo -e "${GREEN_COLOR}已生成虚拟IPv4: $ipv4${RES}"
            elif [[ ! $ipv4 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "${RED_COLOR}无效的IP地址格式，将随机生成${RES}"
                ipv4=$(generate_virtual_ip)
                echo -e "${GREEN_COLOR}已生成虚拟IPv4: $ipv4${RES}"
            fi
            ;;
        *)
            echo -e "${RED_COLOR}无效选择，使用手动设置${RES}"
            ipv4=$(generate_virtual_ip)
            echo -e "${GREEN_COLOR}已生成虚拟IPv4: $ipv4${RES}"
            ;;
    esac
    
    # 4. Peer节点设置
    echo -e "\n${BLUE_COLOR}【Peer节点设置】${RES}"
    echo -e "${YELLOW_COLOR}提示: 至少需要添加一个服务器节点${RES}"
    echo -e "${YELLOW_COLOR}支持的协议: tcp://, udp://, ws://, wss://${RES}"
    local peers=""
    while true; do
        echo -e "\n${GREEN_COLOR}当前已添加的Peer节点：${RES}"
        if [ -n "$peers" ]; then
            echo -e "${BLUE_COLOR}$peers${RES}"
        else
            echo -e "${YELLOW_COLOR}暂无节点${RES}"
        fi
        
        echo -e "\n1. 添加新节点"
        echo "2. 完成设置"
        echo -n "请选择 [1/2]: "
        read peer_choice
        
        case "$peer_choice" in
            1)
                echo -n "请输入节点URI (例如: tcp://1.2.3.4:11010): "
                read peer_uri
                if [ -n "$peer_uri" ]; then
                    # 验证URI格式
                    if [[ $peer_uri =~ ^(tcp|udp|ws|wss)://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+$ ]]; then
                        peers="${peers}[[peer]]
uri = \"$peer_uri\"

"
                        echo -e "${GREEN_COLOR}节点添加成功${RES}"
                    else
                        echo -e "${RED_COLOR}错误：无效的URI格式${RES}"
                    fi
                fi
                ;;
            2)
                if [ -z "$peers" ]; then
                    echo -e "${RED_COLOR}错误：至少需要添加一个Peer节点${RES}"
                    continue
                fi
                break
                ;;
            *)
                echo -e "${RED_COLOR}无效选择${RES}"
                ;;
        esac
    done
    
    # 5. 子网代理设置（可选）
    echo -e "\n${BLUE_COLOR}子网代理设置：${RES}"
    echo -n "是否启用子网代理？[y/N]: "
    read enable_proxy_choice
    
    local enable_proxy="false"
    local proxy_networks=""
    if [[ $enable_proxy_choice =~ ^[Yy]$ ]]; then
        enable_proxy="true"
        echo "请输入要代理的子网CIDR (每行一个，输入空行完成)："
        while true; do
            echo -n "CIDR (留空完成): "
            read proxy_cidr
            if [ -z "$proxy_cidr" ]; then
                break
            fi
            proxy_networks="${proxy_networks}[[proxy_network]]
cidr = \"$proxy_cidr\"

"
        done
    fi
    
    # 生成配置文件
    cat > "$config_dir/${config_name}.conf" << EOF
# 实例名称
instance_name = "$config_name"
# 主机名
hostname = "$hostname_value"
# 实例ID
instance_id = "$(cat /proc/sys/kernel/random/uuid)"
# 虚拟IPv4地址
ipv4 = "$ipv4"
# DHCP设置
dhcp = $dhcp

# RPC管理端口
rpc_portal = "127.0.0.1:$(generate_random_port 15000)"

[network_identity]
# 网络名称
network_name = "$network_name"
# 网络密钥
network_secret = "$network_secret"

# Peer节点列表
$peers

[flags]
# 默认协议
default_protocol = "tcp"
# TUN设备名称
dev_name = ""
# 启用加密
enable_encryption = true
# 启用IPv6
enable_ipv6 = true
# MTU设置
mtu = 1380
# ��迟优先
latency_first = false
# 退出节点
enable_exit_node = false
# 禁用TUN
no_tun = false
# 启用smoltcp
use_smoltcp = $enable_proxy
# 外部网络白名单
foreign_network_whitelist = "*"

[log]
level = "info"
file = ""

$([ "$enable_proxy" = "true" ] && echo "$proxy_networks")
EOF

    # 创建服务文件
    if create_service_file "$config_name"; then
        echo -e "\n${GREEN_COLOR}配置创建成功！${RES}"
        echo "配置文件: $config_dir/${config_name}.conf"
        
        # 启动服务
        echo -e "\n${BLUE_COLOR}正在启动服务...${RES}"
        systemctl enable "easytier@${config_name}" >/dev/null 2>&1
        if systemctl start "easytier@${config_name}"; then
            echo -e "${GREEN_COLOR}服务启动成功！${RES}"
            
            # 显示服务状态
            echo -e "\n${YELLOW_COLOR}服务状态：${RES}"
            systemctl status "easytier@${config_name}" --no-pager
            
            echo -e "\n${YELLOW_COLOR}服务控制命令：${RES}"
            echo "启动服务: systemctl start easytier@${config_name}"
            echo "停止服务: systemctl stop easytier@${config_name}"
            echo "重启服务: systemctl restart easytier@${config_name}"
            echo "查看状态: systemctl status easytier@${config_name}"
            echo "查看日志: journalctl -u easytier@${config_name} -f"
        else
            echo -e "${RED_COLOR}服务启动失败${RES}"
            echo -e "\n${YELLOW_COLOR}错误信息：${RES}"
            systemctl status "easytier@${config_name}" --no-pager
        fi
    else
        echo -e "${RED_COLOR}配置创建失败${RES}"
    fi
    
    echo -e "\n${BLUE_COLOR}操作选项：${RES}"
    echo "1. 查看服务状态"
    echo "2. 查看详细日志"
    echo "3. 返回主菜单"
    echo "0. 退出"
    
    while true; do
        echo -n -e "\n请选择 [0-3]: "
        read choice
        
        case "$choice" in
            1)
                systemctl status "easytier@${config_name}"
                echo -e "\n按回车键继续..."
                read
                ;;
            2)
                journalctl -u "easytier@${config_name}" -n 50 --no-pager
                echo -e "\n按回车键继续..."
                read
                ;;
            3)
                return 0
                ;;
            0)
                exit 0
                ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                ;;
        esac
    done
}

# 添加公共服务器配置函数
create_public_server_config() {
    local config_dir="$INSTALL_PATH/config"
    mkdir -p "$config_dir"
    
    # 公共服务器模式命名规则
    local config_name="easytier_public_server"
    local num=1
    while [ -f "$config_dir/${config_name}.conf" ]; do
        config_name="easytier_public_server$num"
        ((num++))
    done
    
    echo -e "\n${GREEN_COLOR}================== 加入公共服务器节点集群 ==================${RES}"
    
    echo -e "\n${BLUE_COLOR}【公共网络信息】${RES}"
    echo -e "${YELLOW_COLOR}网络名称: ${RES}easytier"
    echo -e "${YELLOW_COLOR}网络密钥: ${RES}easytier"
    echo -e "${YELLOW_COLOR}公共节点: ${RES}tcp://public.easytier.top:11010"
    
    echo -e "\n${YELLOW_COLOR}注意事项：${RES}"
    echo "1. 加入公共网络意味着您的节点将成为公共服务器集群的一部分"
    echo "2. 其他用户可能会通过您的节点进行连接"
    echo "3. 建议具有公网IP的服务器使用此模式"
    echo "4. 您可以随时退出公共网络"
    
    echo -n -e "\n${GREEN_COLOR}是否确认加入公共服务器节点集群？[y/N]: ${RES}"
    read confirm
    
    case "$confirm" in
        [Yy]*)
            # 生成配置文件
            cat > "$config_dir/${config_name}.conf" << EOF
# 实例名称
instance_name = "$config_name"
# 主机名
hostname = "$(hostname)"
# 实例ID
instance_id = "$(cat /proc/sys/kernel/random/uuid)"
# 虚拟IPv4地址
ipv4 = "$(generate_virtual_ip)"
# DHCP设置
dhcp = false

# 监听器列表
listeners = [
    "tcp://0.0.0.0:11010",
    "udp://0.0.0.0:11010",
    "ws://0.0.0.0:11011/",
    "wss://0.0.0.0:11012/"
]

# Peer节点列表
[[peer]]
uri = "tcp://public.easytier.top:11010"

# RPC管理端口
rpc_portal = "127.0.0.1:15888"

[network_identity]
# 网络名称
network_name = "easytier"
# 网络密钥
network_secret = "easytier"

[flags]
# 默认协议
default_protocol = "tcp"
# TUN设备名称
dev_name = ""
# 启用加密
enable_encryption = true
# 启用IPv6
enable_ipv6 = true
# MTU设置
mtu = 1380
# 延迟优先
latency_first = false
# 退出节点
enable_exit_node = false
# 禁用TUN
no_tun = false
# 启用smoltcp
use_smoltcp = false
# 外部网络白名单
foreign_network_whitelist = "*"

[log]
level = "info"
file = ""
EOF

            # 创建服务文件
            if create_service_file "$config_name"; then
                echo -e "\n${GREEN_COLOR}配置创建成功！${RES}"
                echo "配置文件: $config_dir/${config_name}.conf"
                
                # 启动服务
                echo -e "\n${BLUE_COLOR}正在启动服务...${RES}"
                systemctl enable "easytier@${config_name}" >/dev/null 2>&1
                if systemctl start "easytier@${config_name}"; then
                    echo -e "${GREEN_COLOR}服务启动成功！${RES}"
                    
                    # 显示服务状态
                    echo -e "\n${YELLOW_COLOR}服务状态：${RES}"
                    systemctl status "easytier@${config_name}" --no-pager
                    
                    echo -e "\n${GREEN_COLOR}================== 公共节点信息 ==================${RES}"
                    echo -e "${YELLOW_COLOR}您的节点已成功加入公共服务器集群${RES}"
                    echo -e "${GREEN_COLOR}网络名称: easytier${RES}"
                    echo -e "${GREEN_COLOR}网络密钥: easytier${RES}"
                    echo -e "${GREEN_COLOR}公共节点: tcp://public.easytier.top:11010${RES}"
                    echo -e "${GREEN_COLOR}================================================${RES}"
                    
                    echo -e "\n${YELLOW_COLOR}服务控制命令：${RES}"
                    echo "启动服务: systemctl start easytier@${config_name}"
                    echo "停止服务: systemctl stop easytier@${config_name}"
                    echo "重启服务: systemctl restart easytier@${config_name}"
                    echo "查看状态: systemctl status easytier@${config_name}"
                    echo "查看日志: journalctl -u easytier@${config_name} -f"
                else
                    echo -e "${RED_COLOR}服务启动失败${RES}"
                    echo -e "\n${YELLOW_COLOR}错误信息：${RES}"
                    systemctl status "easytier@${config_name}" --no-pager
                fi
            else
                echo -e "${RED_COLOR}配置创建失败${RES}"
            fi
            ;;
        *)
            echo -e "${YELLOW_COLOR}已取消加入公共服务器节点集群${RES}"
            return 1
            ;;
    esac
    
    echo -e "\n${BLUE_COLOR}操作选项：${RES}"
    echo "1. 查看服务状态"
    echo "2. 查看详细日志"
    echo "3. 返回主菜单"
    echo "0. 退出"
    
    while true; do
        echo -n -e "\n请选择 [0-3]: "
        read choice
        
        case "$choice" in
            1)
                systemctl status "easytier@${config_name}"
                echo -e "\n按回车键继续..."
                read
                ;;
            2)
                journalctl -u "easytier@${config_name}" -n 50 --no-pager
                echo -e "\n按回车键继续..."
                read
                ;;
            3)
                return 0
                ;;
            0)
                exit 0
                ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                ;;
        esac
    done
}

# 添加公共客户端配置函数
create_public_client_config() {
    local config_dir="$INSTALL_PATH/config"
    mkdir -p "$config_dir"
    
    # 公共客户端模式命名规则
    local config_name="easytier_public_client"
    local num=1
    while [ -f "$config_dir/${config_name}.conf" ]; do
        config_name="easytier_public_client$num"
        ((num++))
    done
    
    echo -e "\n${GREEN_COLOR}================== 连接公共节点网络 ==================${RES}"
    
    # 显示配置文件信息
    echo -e "\n${BLUE_COLOR}【配置文件信息】${RES}"
    echo "配置文件名: ${config_name}.conf"
    echo "配置文件路径: $config_dir/${config_name}.conf"
    echo -e "${YELLOW_COLOR}注意: 配置文件创建后可在上述路径找到${RES}"
    
    # 1. 基础信息设置
    echo -e "\n${BLUE_COLOR}【基础信息设置】${RES}"
    echo -n "主机名称 [默认: $(hostname)]: "
    read custom_hostname
    local hostname_value=${custom_hostname:-$(hostname)}
    echo -e "${GREEN_COLOR}已设置主机名称: $hostname_value${RES}"
    
    # 2. 网络信息设置
    echo -e "\n${BLUE_COLOR}【网络信息设置】${RES}"
    
    echo -n "网络名称 [随机生成]: "
    read network_name
    # 如果用户未输入，生成带前缀的10位随机字符串
    if [ -z "$network_name" ]; then
        network_name="ET_$(generate_random_string 10)"
    elif [[ ! $network_name =~ ^ET_ ]]; then
        # 如果用户输入的名称没有 ET_ 前缀，自动添加
        network_name="ET_${network_name}"
    fi
    
    echo -n "网络密钥 [随机生成]: "
    read network_secret
    # 如果用户未输入，生成15位随机字符串
    network_secret=${network_secret:-$(generate_random_string 15)}
    
    # 显示生成的值
    echo -e "\n${YELLOW_COLOR}网络名称: ${network_name}${RES}"
    echo -e "${YELLOW_COLOR}网络密钥: ${network_secret}${RES}"
    
    # 3. 虚拟IPv4设置
    echo -e "\n${BLUE_COLOR}【虚拟IPv4设置】${RES}"
    echo "1. 自动分配 (DHCP)"
    echo "2. 手动设置 (推荐)"
    echo -n "请选择 [1/2] [默认: 2]: "
    read ip_choice
    
    local dhcp="false"
    local ipv4=""
    case "$ip_choice" in
        1)
            dhcp="true"
            ipv4=""
            echo -e "${YELLOW_COLOR}已选择DHCP自动分配IP${RES}"
            ;;
        ""|2)  # 空输入或2都使用手动设置
            dhcp="false"
            echo -n "请输入虚拟IPv4地址 [回车随机生成]: "
            read ipv4
            if [ -z "$ipv4" ]; then
                ipv4=$(generate_virtual_ip)
                echo -e "${GREEN_COLOR}已生成虚拟IPv4: $ipv4${RES}"
            elif [[ ! $ipv4 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "${RED_COLOR}无效的IP地址格式，将随机生成${RES}"
                ipv4=$(generate_virtual_ip)
                echo -e "${GREEN_COLOR}已生成虚拟IPv4: $ipv4${RES}"
            fi
            ;;
        *)
            echo -e "${RED_COLOR}无效选择，使用手动设置${RES}"
            ipv4=$(generate_virtual_ip)
            echo -e "${GREEN_COLOR}已生成虚拟IPv4: $ipv4${RES}"
            ;;
    esac
    
    # 4. 公共节点选择
    echo -e "\n${BLUE_COLOR}【公共节点选择】${RES}"
    echo -e "${YELLOW_COLOR}提示: 如果访问GitHub较慢，建议使用国内DNS解析${RES}"
    echo -e "${YELLOW_COLOR}可以尝试修改hosts: 140.82.114.4 raw.githubusercontent.com${RES}"
    
    # 定义公共节点列表
    local public_nodes=(
        "tcp://public.easytiertop:11010"
        "tcp://c.oee.icu:60006"
        "tcp://ah.nkbpal.cn:11010"
        "tcp://s1.ct8.pl:11010"
        "tcp://et.ie12vps.xyz:11010"
    )
    
    echo -e "\n可用的公共节点："
    local i=1
    for node in "${public_nodes[@]}"; do
        echo "$i. $node"
        ((i++))
    done
    echo "$i. 全部使用"
    
    local peers=""
    echo -n "请选择节点 [1-$i]: "
    read node_choice
    
    if [ "$node_choice" -eq "$i" ]; then
        # 选择全部节点
        for node in "${public_nodes[@]}"; do
            peers="${peers}[[peer]]
uri = \"$node\"

"
        done
        echo -e "${GREEN_COLOR}已添加所有公共节点${RES}"
    elif [ "$node_choice" -ge 1 ] && [ "$node_choice" -lt "$i" ]; then
        # 选择单个节点
        peers="[[peer]]
uri = \"${public_nodes[$((node_choice-1))}\"
"
        echo -e "${GREEN_COLOR}已添加节点: ${public_nodes[$((node_choice-1))]}${RES}"
    else
        echo -e "${RED_COLOR}无效选择，将使用第一个节点${RES}"
        peers="[[peer]]
uri = \"${public_nodes[0]}\"
"
    fi
    
    # 5. 子网代理设置（可选）
    echo -e "\n${BLUE_COLOR}【子网代理设置】${RES}"
    echo -n "是否启用子网代理？[y/N]: "
    read enable_proxy_choice
    
    local enable_proxy="false"
    local proxy_networks=""
    if [[ $enable_proxy_choice =~ ^[Yy]$ ]]; then
        enable_proxy="true"
        echo "请输入要代理的子网CIDR (每行一个，输入空行完成)："
        while true; do
            echo -n "CIDR (留空完成): "
            read proxy_cidr
            if [ -z "$proxy_cidr" ]; then
                break
            fi
            proxy_networks="${proxy_networks}[[proxy_network]]
cidr = \"$proxy_cidr\"

"
        done
    fi
    
    # 生成配置文件
    cat > "$config_dir/${config_name}.conf" << EOF
# 实例名称
instance_name = "$config_name"
# 主机名
hostname = "$hostname_value"
# 实例ID
instance_id = "$(cat /proc/sys/kernel/random/uuid)"
# 虚拟IPv4地址
ipv4 = "$ipv4"
# DHCP设置
dhcp = $dhcp

# RPC管理端口
rpc_portal = "127.0.0.1:$(generate_random_port 15000)"

[network_identity]
# 网络名称
network_name = "$network_name"
# 网络密钥
network_secret = "$network_secret"

# Peer节点列表
$peers

[flags]
# 默认协议
default_protocol = "tcp"
# TUN设备名称
dev_name = ""
# 启用加密
enable_encryption = true
# 启用IPv6
enable_ipv6 = true
# MTU设置
mtu = 1380
# 延迟优先模式（默认启用）
latency_first = true
# 退出节点
enable_exit_node = false
# 禁用TUN
no_tun = false
# 启用smoltcp
use_smoltcp = $enable_proxy
# 外部网络白名单
foreign_network_whitelist = "*"

[log]
level = "info"
file = ""

$([ "$enable_proxy" = "true" ] && echo "$proxy_networks")
EOF

    # 创建服务文件
    if create_service_file "$config_name"; then
        echo -e "\n${GREEN_COLOR}配置创建成功！${RES}"
        echo "配置文件: $config_dir/${config_name}.conf"
        
        # 启动服务
        echo -e "\n${BLUE_COLOR}正在启动服务...${RES}"
        systemctl enable "easytier@${config_name}" >/dev/null 2>&1
        if systemctl start "easytier@${config_name}"; then
            echo -e "${GREEN_COLOR}服务启动成功！${RES}"
            
            # 显示服务状态
            echo -e "\n${YELLOW_COLOR}服务状态：${RES}"
            systemctl status "easytier@${config_name}" --no-pager
            
            echo -e "\n${GREEN_COLOR}================== 连接信息 ==================${RES}"
            echo -e "${GREEN_COLOR}网络名称: ${network_name}${RES}"
            echo -e "${GREEN_COLOR}网络密钥: ${network_secret}${RES}"
            if [ "$dhcp" = "true" ]; then
                echo -e "${GREEN_COLOR}虚拟IP: 自动分配 (DHCP)${RES}"
            else
                echo -e "${GREEN_COLOR}虚拟IP: $ipv4${RES}"
            fi
            echo -e "${GREEN_COLOR}延迟优先: 已启用${RES}"
            echo -e "${GREEN_COLOR}已连接节点:${RES}"
            
            # 显示已添加的节点
            if [ "$node_choice" -eq "$i" ]; then
                # 显示所有节点
                for node in "${public_nodes[@]}"; do
                    echo -e "${GREEN_COLOR}- $node${RES}"
                done
            else
                # 显示单个选择的节点
                echo -e "${GREEN_COLOR}- ${public_nodes[$((node_choice-1))]}${RES}"
            fi
            
            echo -e "${GREEN_COLOR}================================================${RES}"
            
            echo -e "\n${YELLOW_COLOR}服务控制命令：${RES}"
            echo "启动服务: systemctl start easytier@${config_name}"
            echo "停止服务: systemctl stop easytier@${config_name}"
            echo "重启服务: systemctl restart easytier@${config_name}"
            echo "查看状态: systemctl status easytier@${config_name}"
            echo "查看日志: journalctl -u easytier@${config_name} -f"
        else
            echo -e "${RED_COLOR}服务启动失败${RES}"
            echo -e "\n${YELLOW_COLOR}错误信息：${RES}"
            systemctl status "easytier@${config_name}" --no-pager
        fi
    else
        echo -e "${RED_COLOR}配置创建失败${RES}"
    fi
    
    echo -e "\n${BLUE_COLOR}操作选项：${RES}"
    echo "1. 查看服务状态"
    echo "2. 查看详细日志"
    echo "3. 返回主菜单"
    echo "0. 退出"
    
    while true; do
        echo -n -e "\n请选择 [0-3]: "
        read choice
        
        case "$choice" in
            1)
                systemctl status "easytier@${config_name}"
                echo -e "\n按回车键继续..."
                read
                ;;
            2)
                journalctl -u "easytier@${config_name}" -n 50 --no-pager
                echo -e "\n按回车键继续..."
                read
                ;;
            3)
                return 0
                ;;
            0)
                exit 0
                ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                ;;
        esac
    done
}
