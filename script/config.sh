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
Environment=RUST_BACKTRACE=1

# 主程序
ExecStart=/usr/sbin/easytier-core -c ${config_file}

# PID 文件
PIDFile=/run/easytier/${config_name}/easytier.pid

# 停止和重启设置
Restart=on-failure
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=10
KillMode=mixed
KillSignal=SIGTERM

# 资源限制
CPUQuota=50%
MemoryLimit=256M
TasksMax=4096
LimitNOFILE=65535
LimitNPROC=65535

# 安全设置
ProtectSystem=full
ProtectHome=true
PrivateTmp=true
NoNewPrivileges=true

# 网络设置
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW

[Install]
WantedBy=multi-user.target
EOF

    # 设置服务文件权限
    chmod 644 "/etc/systemd/system/easytier@${config_name}.service"
    chown root:root "/etc/systemd/system/easytier@${config_name}.service"
    
    # 重载 systemd
    systemctl daemon-reload
    
    # 验证
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
    echo "   可以连接到您的私有服务器或社区公共节点"
    echo "   支持连接 EasyTier 社区提供的公共节点集群"
    
    echo -e "\n${YELLOW_COLOR}3. 公共服务器模式${RES}"
    echo "   加入公共服务器节点集群，服务于社区"
    echo "   建议具有稳定公网IP的服务器选择此模式"
    
    echo -e "\n${BLUE_COLOR}请选择${RES}"
    echo "1. 服务器模式 (创建新的网络节点)"
    echo "2. 客户端模式 (连接到现有网络节点)"
    echo "3. 公共服务器模式 (加入公共网络集群)"
    echo "0. 返上菜单"
    
    while true; do
        echo -n -e "\n请选择 [0-3]: "
        read mode_choice
        
        case "$mode_choice" in
            1) 
                create_server_config
                break
                ;;
            2) 
                if type create_client_config >/dev/null 2>&1; then
                    create_client_config
                else
                    echo -e "${RED_COLOR}错误：客户端配置函数未定义${RES}"
                    sleep 2
                fi
                break
                ;;
            3) 
                create_public_server_config
                break
                ;;
            0) 
                return 0 
                ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
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
    
    # 显示配置文件息
    echo -e "\n${BLUE_COLOR}配置文件信息：${RES}"
    echo "配置文件名: ${config_name}.conf"
    echo "配置文件路径: $config_dir/${config_name}.conf"
    echo -e "${YELLOW_COLOR}注意: 配置文件创建后可在上述路径找到${RES}"
    
    # 获取配置信息
    get_server_config_info "$config_dir/${config_name}.conf"
    
    # 创建服务文件
    create_service_file "$config_name"
    
    echo -e "\n${GREEN_COLOR}配置创建成功！${RES}"
    echo "配置文件: $config_dir/${config_name}.conf"
    
    # 启动服务
    echo -e "\n${BLUE_COLOR}正在动服务...${RES}"
    systemctl enable "easytier@${config_name}" >/dev/null 2>&1
    if systemctl start "easytier@${config_name}"; then
        echo -e "${GREEN_COLOR}服务启动成功！${RES}"
        sleep 2  # 等务全启动
        
        # 显示服务状态
        echo -e "\n${YELLOW_COLOR}服务状态：${RES}"
        systemctl status "easytier@${config_name}" --no-pager
        
        echo -e "\n${YELLOW_COLOR}文件位置：${RES}"
        echo "配置文件: $config_dir/${config_name}.conf"
        echo "服务文件: /etc/systemd/system/easytier@${config_name}.service"
        echo "运行目录: /run/easytier/${config_name}"
        
        # 获取服务公IP和配置息
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
        echo -e "${YELLOW_COLOR}客户端会自动获取或者自行配置和服务器同网段虚拟IPv4${RES}"
        echo -e "${GREEN_COLOR}------------------------------------------------${RES}"
        if [ "$dhcp" = "true" ]; then
            echo -e "${GREEN_COLOR}虚拟IPv4: 自动分配 (DHCP)${RES}"
        else
            echo -e "${GREEN_COLOR}虚拟IPv4: ${virtual_ip}${RES}"
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
        echo -e "${RED_COLOR}错误: 缺少监听器配置${RES}"
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
    
    # 从配置文件路径中提取配置名称和编号
    local config_name=$(basename "$config_file" .conf)
    local num=$(echo "$config_name" | grep -o '[0-9]*$')
    [ -z "$num" ] && num=1
    
    # 生成 TUN 设备名称
    local tun_name=$(get_tun_device_name "server" "$num")
    # 检查 TUN 设备名称是否已存在
    while grep -r "dev_name = \"$tun_name\"" "$config_dir"/* >/dev/null 2>&1; do
        ((num++))
        tun_name=$(get_tun_device_name "server" "$num")
    done
    
    # 生成配置文件
    cat > "$config_file" << EOF
# 实例名称
instance_name = "$config_name"
# 主机名
hostname = "$(hostname)"
# 实例ID
instance_id = "$(cat /proc/sys/kernel/random/uuid)"
# 虚拟IPv4地址
ipv4 = "$ipv4"
# DHCP设置
dhcp = $dhcp

# 监听器列表
listeners = [
    "tcp://0.0.0.0:${tcp_port}",
    "udp://0.0.0.0:${tcp_port}",
    "ws://0.0.0.0:${ws_port}/",
    "wss://0.0.0.0:${wss_port}/"
]

# 退出节点列表
exit_nodes = []

# RPC管理端口
rpc_portal = "127.0.0.1:${rpc_port}"

[network_identity]
# 网络名称
network_name = "$network_name"
# 网络密钥
network_secret = "$network_secret"

$([ "$enable_vpn_portal" = "true" ] && echo "$vpn_portal_config")

[flags]
# 默认协议
default_protocol = "tcp"
# TUN设备名称
dev_name = "$tun_name"
# 启用加密
enable_encryption = true
# 启用IPv6
enable_ipv6 = true
# MTU设置
mtu = 1380
# 延迟优先模式
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

    # 验证配置文件
    if ! validate_config "$config_file"; then
        echo -e "${RED_COLOR}配置文件验证失败${RES}"
        return 1
    fi
    
    # 设置配置文限
    chmod 644 "$config_file"
    chown root:root "$config_file"
    
    echo -e "${GREEN_COLOR}配置文件生成成功${RES}"
    return 0
}

# 修改端口和IP冲突检查函
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
        echo -e "${RED_COLOR}WebSocket口 $ws_port 已被占用${RES}"
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
                echo "配置创建已取消"
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
        echo -e "${YELLOW_COLOR}占用详情：${RES}"
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
        # 如果用户输入的名称没有 ET_ 前，自动添加
        network_name="ET_${network_name}"
    fi
    
    echo -n "网络密钥 [随机生成]: "
    read network_secret
    # 如果用户未输入，生成15位随机字符串
    network_secret=${network_secret:-$(generate_random_string 15)}
    
    # 显示生成值
    echo -e "\n${YELLOW_COLOR}网络名称: ${network_name}${RES}"
    echo -e "${YELLOW_COLOR}网络密钥: ${network_secret}${RES}"
    echo -e "\n请记住这些信息，客户连接此节点时需要使用。"
    
    # 2. 虚拟IPv4设置
    echo -e "\n${BLUE_COLOR}虚拟IPv4设置：${RES}"
    echo "1. 自动分配 (DHCP，从10.0.0.1开始)"
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
            echo -n "请输入虚拟IPv4地址 [随机生成]: "
            read manual_ip
            if [ -n "$manual_ip" ]; then
                ipv4=$manual_ip
            else
                ipv4=$(generate_virtual_ip)
                echo -e "${GREEN_COLOR}已生成虚拟IPv4地址: $ipv4${RES}"
            fi
            
            # 验IP地址格式
            while [[ ! $ipv4 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; do
                echo -e "${RED_COLOR}有效的IP地址格式${RES}"
                echo -n "请重新输入虚拟IPv4地址 [随机生成]: "
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
    
    # 默认进入手动设置式
    if [[ ! $use_default_ports =~ ^[Yy]$ ]]; then
        echo -n "TCP/UDP 监听端口 [随机生成]: "
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
        
        echo -n "WireGuard/WebSocket 监听端口 [随机生成]: "
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
        
        echo -n "WebSocket(SSL) 监听端口 [随机生成]: "
        read input_port
        if [ -n "$input_port" ]; then
            if check_port "$input_port"; then
                wss_port=$input_port
            else
                echo -e "${RED_COLOR}端口 $input_port 已被占，将随机生成新端口${RES}"
                wss_port=$(generate_random_port 13000)
            fi
        else
            wss_port=$(generate_random_port 13000)
        fi
        echo -e "${GREEN_COLOR}WebSocket(SSL) 监听端口: $wss_port${RES}"
        
        echo -n "RPC 管理端口 [随机生成]: "
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
            echo -e "${RED_COLOR}默认 TCP/UDP 口被占用，随机生成新端口${RES}"
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
        echo -n "请输入客户端网段 [随机生成]: "
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
    echo -n "是否启用子网代理？[y/N]: "
    read enable_proxy_choice
    
    if [[ $enable_proxy_choice =~ ^[Yy]$ ]]; then
        enable_proxy="true"
        # 创建一个数组来存储所有输入的CIDR
        declare -a proxy_cidrs
        echo "请输入要代理的子网CIDR (请注意子网格式10.10.10.0/24,请勿输入错误)："
        while true; do
            echo -n "CIDR (留空完成): "
            read proxy_cidr
            if [ -z "$proxy_cidr" ]; then
                break
            fi
            # 将CIDR添加到数组和配置字符串中
            proxy_cidrs+=("$proxy_cidr")
            proxy_networks="${proxy_networks}[[proxy_network]]
cidr = \"$proxy_cidr\"

"
        done

        # 如果有输入的CIDR，则配置防火墙
        if [ ${#proxy_cidrs[@]} -gt 0 ]; then
            # 添加防火墙配置
            echo -e "\n${BLUE_COLOR}正在配置防火墙规则...${RES}"
            echo -e "${YELLOW_COLOR}支持的防火墙类型：${RES}"
            echo "- iptables (适用于大多数Linux发行版)"
            echo "- firewalld (适用于RHEL/CentOS/Fedora等)"
            echo "- ufw (适用于Ubuntu/Debian等)"
            
            # 启用IP转发
            echo -e "\n${BLUE_COLOR}启用IP转发...${RES}"
            sysctl -w net.ipv4.ip_forward=1
            echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-easytier.conf
            sysctl -p /etc/sysctl.d/99-easytier.conf
            
            # 配置防火墙规则
            echo -e "\n${BLUE_COLOR}配置防火墙规则...${RES}"
            if command -v firewall-cmd >/dev/null 2>&1; then
                echo -e "${GREEN_COLOR}检测到 firewalld，添加规则：${RES}"
                for cidr in "${proxy_cidrs[@]}"; do
                    echo "firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -s $cidr -j ACCEPT"
                    echo "firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -d $cidr -j ACCEPT"
                    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -s "$cidr" -j ACCEPT
                    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -d "$cidr" -j ACCEPT
                done
                firewall-cmd --reload
            elif command -v ufw >/dev/null 2>&1; then
                echo -e "${GREEN_COLOR}检测到 ufw，添加规则：${RES}"
                for cidr in "${proxy_cidrs[@]}"; do
                    echo "ufw route allow from $cidr"
                    echo "ufw route allow to $cidr"
                    ufw route allow from "$cidr"
                    ufw route allow to "$cidr"
                done
            else
                echo -e "${GREEN_COLOR}使用 iptables 添加规则：${RES}"
                for cidr in "${proxy_cidrs[@]}"; do
                    echo "iptables -A FORWARD -s $cidr -j ACCEPT"
                    echo "iptables -A FORWARD -d $cidr -j ACCEPT"
                    iptables -A FORWARD -s "$cidr" -j ACCEPT
                    iptables -A FORWARD -d "$cidr" -j ACCEPT
                done
            fi
            
            echo -e "${GREEN_COLOR}防火墙规则已添加${RES}"
        else
            echo -e "${YELLOW_COLOR}未输入任何CIDR，跳过防火墙配置${RES}"
        fi
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
    
    # 生配置文件
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
        # 检端口是否被占用
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
    
    # 启动服
    echo -e "${BLUE_COLOR}正在启动服务...${RES}"
    if ! systemctl start "easytier@${config_name}"; then
        echo -e "${RED_COLOR}服启动失败${RES}"
        echo -e "\n${YELLOW_COLOR}错误日志：${RES}"
        journalctl -u "easytier@${config_name}" -n 50 --no-pager
        return 1
    fi
    
    # 待服务启动
    sleep 2
    if ! systemctl is-active --quiet "easytier@${config_name}"; then
        echo -e "${RED_COLOR}服务启动失败${RES}"
        echo -e "\n${YELLOW_COLOR}错误日志${RES}"
        journalctl -u "easytier@${config_name}" -n 50 --no-pager
        return 1
    fi
    
    echo -e "${GREEN_COLOR}服务启动成功${RES}"
    return 0
}

# 添加 qrencode 安装函数
install_qrencode() {
    echo -e "${YELLOW_COLOR}未检测到 qrencode，是否安装？（WireGuard的配置二维码需要次软件才能生成）[Y/n]: ${RES}"
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

# WireGuard 配置生成函数
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
    
    echo -e "\n${BLUE_COLOR}正在生成 WireGuard 配置信息...${RES}"
    
    # 生成 WireGuard 配置
    local wg_info=$(cd "$INSTALL_PATH" && ./easytier-cli -p "127.0.0.1:$rpc_port" vpn-portal)
    
    if [ $? -eq 0 ] && [ -n "$wg_info" ]; then
        # 提取配置部分并去除注释
        local config_content=$(echo "$wg_info" | sed -n '/############### client_config_start ###############/,/############### client_config_end ###############/p' | \
            grep -v '###############' | \
            sed 's/ #.*$//' | \
            sed '/^$/d' | \
            sed 's/^[[:space:]]*//g' | \
            sed 's/[[:space:]]*$//')

        # 替换 Endpoint 中的 IP
        config_content=$(echo "$config_content" | sed "s/0.0.0.0:/${server_ip}:/")
        
        # 保存配置文件
        local wg_config_file="$wg_dir/${config_name}_wg.conf"
        echo "$config_content" > "$wg_config_file"
        
        # 生成二维码
        if command -v qrencode >/dev/null 2>&1; then
            local qr_file="$wg_dir/${config_name}_wg.png"
            echo "$config_content" | qrencode -o "$qr_file" -t PNG
            echo -e "${GREEN_COLOR}已生成WireGuard 配置二维码：${RES} $qr_file"
            
            # 在终端打印二维码
            echo -e "\n${YELLOW_COLOR}WireGuard 配置二维码：${RES}"
            echo "$config_content" | qrencode -s 3 -m 3 -t ANSIUTF8
        else
            echo -e "${YELLOW_COLOR}未安装 qrencode，跳过WireGuard 二维码生成${RES}"
        fi
        
        echo -e "\n${GREEN_COLOR}WireGuard 配置信息：${RES}"
        echo -e "${GREEN_COLOR}配置文件已保存到：${RES} $wg_config_file"
        echo -e "\n${YELLOW_COLOR}重要说明：${RES}"
        echo -e "${YELLOW_COLOR}如果您在内网环境中通过 WireGuard 配置信息连接本服务器，请将配置文件中的${RES}"
        echo -e "${YELLOW_COLOR}Endpoint IP 地址修改为服务器实际的内网 IP 地址！${RES}"
        echo -e "\n${YELLOW_COLOR}配置内容：${RES}"
        echo "$config_content"
        
        return 0
    else
        echo -e "${RED_COLOR}WireGuard 配置生成失败${RES}"
        echo -e "${YELLOW_COLOR}错误信息：${RES}"
        echo "$wg_info"
        return 1
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
    echo -e "\n${GREEN_COLOR}注意：备份文件将会留${RES}"
    
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
            echo -e "${BLUE_COLOR}正在删除运行时录...${RES}"
            rm -rf /run/easytier
            
            # 删除日志文件
            echo -e "${BLUE_COLOR}正在删除日志文件...${RES}"
            rm -rf /var/log/easytier
            journalctl --vacuum-time=1s
            
            # 除临时文件和缓存
            echo -e "${BLUE_COLOR}正在删除临时文件和缓存...${RES}"
            rm -f /tmp/easytier_*
            rm -rf /tmp/easytier-*
            
            # 清理系统配置
            echo -e "${BLUE_COLOR}正在清理系统配置...${RES}"
            rm -f /etc/sysctl.d/99-easytier.conf
            sysctl --system >/dev/null 2>&1
            
            # 检查是否还有遗留文件（排除备份文件）
            echo -e "${BLUE_COLOR}正在检查遗文件...${RES}"
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
        echo -e "\n${BLUE_COLOR}现有配置${RES}"
        local configs=()
        local i=1
        
        # 修正配置件路径为 /opt/easytier/config
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
        
        echo -e "\n0. 返回级菜单"
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
                echo -e "${RED_COLOR}错误：配置件不存在${RES}"
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
                echo -n "是否停止服务继续？[y/N]: "
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
            echo -e "${RED_COLOR}无选择${RES}"
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
            echo "4. WireGuard配置: /opt/easytier/wireguard/${config_name}_wg.conf"
            echo "5. WireGuard二维码: /opt/easytier/wireguard/${config_name}_wg.png"
            echo "6. 相关日志文件"
            
            echo -e "\n${YELLOW_COLOR}注意：删除前将自动备份所有相关文件${RES}"
            echo -e "${YELLOW_COLOR}备份文件将保存在 $HOME/.easytier_backup/ 目录下${RES}"
            
            echo -n -e "\n${RED_COLOR}确认删除？[y/N]: ${RES}"
            read del_confirm
            
            case "$del_confirm" in
                [Yy]*)
                    # 1. 创建备份目
                    local backup_dir="$HOME/.easytier_backup"
                    local backup_time=$(date +%Y%m%d_%H%M%S)
                    local backup_path="$backup_dir/${config_name}_${backup_time}"
                    mkdir -p "$backup_path"
                    
                    echo -e "\n${BLUE_COLOR}正在备份文件...${RES}"
                    
                    # 2. 备份配置文件
                    if [ -f "$config_file" ]; then
                        cp -p "$config_file" "$backup_path/"
                        echo -e "${GREEN_COLOR}已备份配置文件${RES}"
                    fi
                    
                    # 3. 备份服务文件
                    if [ -f "/etc/systemd/system/easytier@${config_name}.service" ]; then
                        cp -p "/etc/systemd/system/easytier@${config_name}.service" "$backup_path/"
                        echo -e "${GREEN_COLOR}已备份服务文件${RES}"
                    fi
                    
                    # 4. 备份 WireGuard 配置
                    if [ -f "/opt/easytier/wireguard/${config_name}_wg.conf" ]; then
                        cp -p "/opt/easytier/wireguard/${config_name}_wg.conf" "$backup_path/"
                        echo -e "${GREEN_COLOR}已备份 WireGuard 配置${RES}"
                    fi
                    
                    # 5. 备份运行时数据（如果存在）
                    if [ -d "/run/easytier/${config_name}" ]; then
                        cp -rp "/run/easytier/${config_name}" "$backup_path/runtime_data"
                        echo -e "${GREEN_COLOR}已备份运行时数据${RES}"
                    fi
                    
                    echo -e "\n${BLUE_COLOR}正在停止服务...${RES}"
                    systemctl stop "easytier@${config_name}" 2>/dev/null
                    systemctl disable "easytier@${config_name}" 2>/dev/null
                    
                    echo -e "${BLUE_COLOR}正在删除文件...${RES}"
                    # 删除服务文件
                    rm -f "/etc/systemd/system/easytier@${config_name}.service"
                    systemctl daemon-reload
                    
                    # 删除配置文件
                    rm -f "$config_file"
                    
                    # 删除运行时目录
                    rm -rf "/run/easytier/${config_name}"
                    
                    # 删除 WireGuard 配置
                    rm -f "/opt/easytier/wireguard/${config_name}_wg.conf"
                    rm -f "/opt/easytier/wireguard/${config_name}_wg.png"
                    rm -f "/tmp/easytier_wg_${config_name}"*
                    
                    # 清理日志
                    journalctl --vacuum-time=1s -u "easytier@${config_name}" 2>/dev/null
                    
                    echo -e "\n${GREEN_COLOR}配置删除完成！${RES}"
                    echo -e "${YELLOW_COLOR}备份文件已保存在：${RES} $backup_path"
                    echo -e "${YELLOW_COLOR}如需恢复配置，请使用备份恢复功能。${RES}"
                    sleep 2
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
        
        # 列现有配置
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
    echo -e "\n${GREEN_COLOR}================== 创建客户端配置文件 ==================${RES}"
    
    local config_dir="$INSTALL_PATH/config"
    mkdir -p "$config_dir"
    
    # 客户端模式命名规则
    local config_name="easytier_client"
    local num=1
    while [ -f "$config_dir/${config_name}.conf" ]; do
        config_name="easytier_client$num"
        ((num++))
    done
    
    # 生成 TUN 设备名称
    local tun_name="c${num}"  # 使用简短名称，如 c1, c2, c3 等
    
    # 显示配置文件信息
    echo -e "\n${BLUE_COLOR}【配置文件信息】${RES}"
    echo "配置文件名: ${config_name}.conf"
    echo "配置文件路径: $config_dir/${config_name}.conf"
    echo -e "${YELLOW_COLOR}注意: 配置文件创建后可上述路径找${RES}"
    
    # 1. 础信息设置
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
            echo -e "${YELLOW_COLOR}已选择DHCP自分配IP${RES}"
            ;;
        ""|2)  # 空输入或2都使用手动设置
            dhcp="false"
            echo -n "请输入虚拟IPv4地址 [回车随机生成]: "
            read ipv4
            if [ -z "$ipv4" ]; then
                ipv4=$(generate_virtual_ip)
                echo -e "${GREEN_COLOR}已生成虚拟IPv4: $ipv4${RES}"
            elif [[ ! $ipv4 =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "${RED_COLOR}无效IP地址格式，将随机生成${RES}"
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
    echo -e "\n${GREEN_COLOR}社区公共节点列表：${RES}"
    echo
    echo "=== 官方/公共服务器 ==="
    echo "EasyTier 官方 tcp://public.easytier.top:11010"
    echo
    echo "=== 中国境内服务器 ==="
    echo "安徽合肥 电信 tcp://ah.nkbpal.cn:11010"
    echo "安徽合肥 电信 wss://ah.nkbpal.cn:11012"
    echo "广东广州 腾讯云 tcp://43.136.45.249:11010"
    echo "广东广州 腾讯云 wss://43.136.45.249:11012"
    echo "广东深圳 阿里云 tcp://public.server.soe.icu:11010"
    echo "广东深圳 阿里云 wss://public.server.soe.icu:11012"
    echo "海南海口 联通 tcp://et.of130328.xyz:11010"
    echo "江苏南京 电信 tcp://et.ie12vps.xyz:11010"
    echo "上海上海 阿里云 tcp://47.103.35.100:11010"
    echo "浙江宁波 电信 tcp://et.gbc.moe:11011"
    echo "浙江宁波 电信 wss://et.gbc.moe:11012"
    echo
    echo "=== 中国香港服务器 ==="
    echo "中国香港 tcp://141.11.219.120:11010"
    echo "中国香港 wss://141.11.219.120:11012"
    echo "中国香港 tcp://116.206.178.250:11010"
    echo
    echo "=== 国外服务器 ==="
    echo "美国科罗拉多 tcp://et.pub.moe.gift:11111"
    echo "美国科罗拉多 wss://et.pub.moe.gift:11111"
    echo "美国亚利桑那 tcp://x.cfgw.rr.nu:11010"
    echo
    echo -e "${YELLOW_COLOR}您可以选择上述任意节点进行连接${RES}"
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
                echo -n "请输入节点信息 (例如: tcp://1.2.3.4:11010 或 tcp://example.com:11010): "
                read peer_uri
                if [ -n "$peer_uri" ]; then
                    # 修改验证正则表达式以支持域名和IP
                    if [[ $peer_uri =~ ^(tcp|udp|ws|wss)://(([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)|([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}):[0-9]+$ ]]; then
                        peers="${peers}[[peer]]
uri = \"$peer_uri\"

"
                        echo -e "${GREEN_COLOR}节点添加成功${RES}"
                    else
                        echo -e "${RED_COLOR}错误：无效的URI格式${RES}"
                        echo -e "${YELLOW_COLOR}正确格式示例：${RES}"
                        echo "- IP格式：tcp://1.2.3.4:11010"
                        echo "- 域名格式：tcp://example.com:11010"
                        echo -e "${YELLOW_COLOR}支持的协议：tcp://, udp://, ws://, wss://${RES}"
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
        # 创建一个数组来存储所有输入的CIDR
        declare -a proxy_cidrs
        echo "请输入要代理的子网CIDR (请注意子网格式10.10.10.0/24,请勿输入错误)"
        while true; do
            echo -n "CIDR (留空完成): "
            read proxy_cidr
            if [ -z "$proxy_cidr" ]; then
                break
            fi
            # 将CIDR添加到数组和配置字符串中
            proxy_cidrs+=("$proxy_cidr")
            proxy_networks="${proxy_networks}[[proxy_network]]
cidr = \"$proxy_cidr\"

"
        done

        # 如果有输入的CIDR，则配置防火墙
        if [ ${#proxy_cidrs[@]} -gt 0 ]; then
            # 添加防火墙配置
            echo -e "\n${BLUE_COLOR}正在配置防火墙规则...${RES}"
            echo -e "${YELLOW_COLOR}支持的防火墙类型：${RES}"
            echo "- iptables (适用于大多数Linux发行版)"
            echo "- firewalld (适用于RHEL/CentOS/Fedora等)"
            echo "- ufw (适用于Ubuntu/Debian等)"
            
            # 启用IP转发
            echo -e "\n${BLUE_COLOR}启用IP转发...${RES}"
            sysctl -w net.ipv4.ip_forward=1
            echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-easytier.conf
            sysctl -p /etc/sysctl.d/99-easytier.conf
            
            # 配置防火墙规则
            echo -e "\n${BLUE_COLOR}配置防火墙规则...${RES}"
            if command -v firewall-cmd >/dev/null 2>&1; then
                echo -e "${GREEN_COLOR}检测到 firewalld，添加规则：${RES}"
                for cidr in "${proxy_cidrs[@]}"; do
                    echo "firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -s $cidr -j ACCEPT"
                    echo "firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -d $cidr -j ACCEPT"
                    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -s "$cidr" -j ACCEPT
                    firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -d "$cidr" -j ACCEPT
                done
                firewall-cmd --reload
            elif command -v ufw >/dev/null 2>&1; then
                echo -e "${GREEN_COLOR}检测到 ufw，添加规则：${RES}"
                for cidr in "${proxy_cidrs[@]}"; do
                    echo "ufw route allow from $cidr"
                    echo "ufw route allow to $cidr"
                    ufw route allow from "$cidr"
                    ufw route allow to "$cidr"
                done
            else
                echo -e "${GREEN_COLOR}使用 iptables 添加规则：${RES}"
                for cidr in "${proxy_cidrs[@]}"; do
                    echo "iptables -A FORWARD -s $cidr -j ACCEPT"
                    echo "iptables -A FORWARD -d $cidr -j ACCEPT"
                    iptables -A FORWARD -s "$cidr" -j ACCEPT
                    iptables -A FORWARD -d "$cidr" -j ACCEPT
                done
            fi
            
            echo -e "${GREEN_COLOR}防火墙规则已添加${RES}"
        else
            echo -e "${YELLOW_COLOR}未输入任何CIDR，跳过防火墙配置${RES}"
        fi
    fi
    
    # 4.5 WireGuard 配置（可选）
    echo -e "\n${BLUE_COLOR}【WireGuard 配置】${RES}"
    echo -n "否启用 WireGuard？[y/N]: "
    read enable_wg

    local enable_wireguard="false"
    local wireguard_config=""
    local wg_port=""
    local ws_port=""
    local rpc_port=""

    if [[ $enable_wg =~ ^[Yy]$ ]]; then
        enable_wireguard="true"
        
        # 端口设置
        echo -e "\n${BLUE_COLOR}端口设置：${RES}"
        echo "默认端口配置："
        echo "WireGuard/WebSocket 监听端口: 11011"
        echo "RPC 管理端口: 15888"
        echo -n "是否使用默认端口配置？[y/N]: "
        read use_default_ports
        
        if [[ $use_default_ports =~ ^[Yy]$ ]]; then
            # 检查默认端口是否用
            if check_port "11011"; then
                wg_port="11011"
                ws_port="11011"
            else
                echo -e "${RED_COLOR}默认 WireGuard/WebSocket 端口被占用，将随机生成新端口${RES}"
                wg_port=$(generate_random_port 11000)
                ws_port=$wg_port
            fi
            
            if check_port "15888"; then
                rpc_port="15888"
            else
                echo -e "${RED_COLOR}默认 RPC 端口被占用，将随机生成新端口${RES}"
                rpc_port=$(generate_random_port 15000)
            fi
        else
            # 手动设置端口
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
            
            echo -n "RPC 管理端口 [回车随机生成]: "
            read input_port
            if [ -n "$input_port" ]; then
                if check_port "$input_port"; then
                    rpc_port=$input_port
                else
                    echo -e "${RED_COLOR}端口 $input_port 已被占用，机生成新端口${RES}"
                    rpc_port=$(generate_random_port 15000)
                fi
            else
                rpc_port=$(generate_random_port 15000)
            fi
            echo -e "${GREEN_COLOR}RPC 管理端口: $rpc_port${RES}"
        fi
        
        # 生成 WireGuard 配置
        wireguard_config="# WireGuard 配置
[vpn_portal_config]
# VPN客户端所在的网段
client_cidr = \"$(generate_wireguard_cidr)\"
# wg所监听的端口
wireguard_listen = \"0.0.0.0:$wg_port\""

        # 添加监听器配置
        listeners_config="# 监听器列表
listeners = [
    \"ws://0.0.0.0:${ws_port}/\"
]"
    else
        # 如果不启用 WireGuard，使用随机 RPC 端口
        rpc_port=$(generate_random_port 15000)
        # 不添加监听器配置
        listeners_config=""
    fi

    # 修改配置文件生成部分，根据是否启用 WireGuard 添加相应配置
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
rpc_portal = "127.0.0.1:$rpc_port"

# 监听器列表
listeners = [
    $([ "$enable_wireguard" = "true" ] && echo "\"ws://0.0.0.0:${ws_port}/\",")
    $([ "$enable_wireguard" = "true" ] && echo "\"wg://0.0.0.0:${wg_port}/\"")
]

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
# TUN设备名称（使用配置名作设备名）
dev_name = "$tun_name"
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

$([ "$enable_wireguard" = "true" ] && echo "$wireguard_config")
EOF

    # 在显示连接信息时添加 WireGuard 相关信息
    if [ "$enable_wireguard" = "true" ]; then
        echo -e "\n${YELLOW_COLOR}WireGuard 配置：${RES}"
        echo -e "${GREEN_COLOR}WireGuard/WebSocket 端口: $wg_port${RES}"
        echo -e "${GREEN_COLOR}RPC 管理端口: $rpc_port${RES}"
    fi

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
            
            # 如果启用了 WireGuard，生成配置
            if [ "$enable_wireguard" = "true" ]; then
                echo -e "\n${BLUE_COLOR}正在生成 WireGuard 配置...${RES}"
                sleep 2  # 等待服务完全启动
                
                # 创建 WireGuard 配置目录
                local wg_dir="$INSTALL_PATH/wireguard"
                mkdir -p "$wg_dir"
                
                # 获取 WireGuard 配置
                local wg_info=$(cd "$INSTALL_PATH" && ./easytier-cli -p "127.0.0.1:$rpc_port" vpn-portal)
                
                if [ $? -eq 0 ] && [ -n "$wg_info" ]; then
                    # 获取当前设备的公网 IP
                    local server_ip=$(curl -s ip.sb || curl -s ifconfig.me)
                    
                    # 修改配置文件中的 Endpoint
                    if [ -n "$server_ip" ]; then
                        wg_info=$(echo "$wg_info" | sed "s/0.0.0.0:/${server_ip}:/g")
                    fi
                    
                    # 保存配置文件
                    local wg_config_file="$wg_dir/${config_name}_wg.conf"
                    echo "$wg_info" > "$wg_config_file"
                    
                    echo -e "\n${GREEN_COLOR}WireGuard 配置信息：${RES}"
                    echo -e "${GREEN_COLOR}配置文件已保存到：${RES} $wg_config_file"
                    echo -e "\n${YELLOW_COLOR}重要说明：${RES}"
                    echo -e "${YELLOW_COLOR}如果您在内网环境中通过 WireGuard 配置连接本服务器，请将配置文件中的${RES}"
                    echo -e "${YELLOW_COLOR}Endpoint IP 地址修改为服务器实际的内网 IP 地址！${RES}"
                    echo -e "\n${YELLOW_COLOR}配置内容：${RES}"
                    echo "$wg_info"
                else
                    echo -e "${RED_COLOR}WireGuard 配置生成失败${RES}"
                    echo -e "${YELLOW_COLOR}错误信息：${RES}"
                    echo "$wg_info"
                fi
            fi
            
            echo -e "\n${GREEN_COLOR}================== 连接信息 ==================${RES}"
            echo -e "${GREEN_COLOR}网络名称: ${network_name}${RES}"
            echo -e "${GREEN_COLOR}网络密钥: ${network_secret}${RES}"
            if [ "$dhcp" = "true" ]; then
                echo -e "${GREEN_COLOR}虚拟IP: 自动分配 (DHCP)${RES}"
            else
                echo -e "${GREEN_COLOR}虚拟IP: $ipv4${RES}"
            fi
            echo -e "${GREEN_COLOR}延迟优先: 已启用${RES}"
            
            # 显示连接节点信息
            echo -e "\n${YELLOW_COLOR}已连接节点：${RES}"
            if [ -n "$peers" ]; then
                echo "$peers" | grep "uri = " | while read -r line; do
                    echo -e "${GREEN_COLOR}- ${line#*= }${RES}" | tr -d '"'
                done
            fi
            
            # 如果启用了子网代理，显示子网信息
            if [ "$enable_proxy" = "true" ] && [ ${#proxy_cidrs[@]} -gt 0 ]; then
                echo -e "\n${YELLOW_COLOR}子网代理配置：${RES}"
                echo -e "${GREEN_COLOR}已启用以下子网的转发：${RES}"
                for cidr in "${proxy_cidrs[@]}"; do
                    echo -e "${GREEN_COLOR}- $cidr${RES}"
                done
                
                # 显示防火墙配置信息
                echo -e "\n${YELLOW_COLOR}防火墙配置：${RES}"
                if command -v firewall-cmd >/dev/null 2>&1; then
                    echo -e "${GREEN_COLOR}已配置 firewalld 转发规则${RES}"
                elif command -v ufw >/dev/null 2>&1; then
                    echo -e "${GREEN_COLOR}已配置 ufw 转发规则${RES}"
                else
                    echo -e "${GREEN_COLOR}已配置 iptables 转发规则${RES}"
                fi
                echo -e "${GREEN_COLOR}系统 IP 转发已启用${RES}"
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

# 添加公共服务器配置函数
create_public_server_config() {
    echo -e "\n${GREEN_COLOR}================== 加入服务器节点集群 ==================${RES}"
    
    local config_dir="$INSTALL_PATH/config"
    mkdir -p "$config_dir"
    
    # 公共服务器模式命名规则
    local config_name="easytier_public_server"
    local num=1
    while [ -f "$config_dir/${config_name}.conf" ]; do
        config_name="easytier_public_server$num"
        ((num++))
    done

    # 生成简短的 TUN 设备名称
    local tun_name=$(get_tun_device_name "public_server" "$num")
    
    echo -e "\n${BLUE_COLOR}【公共网络信息】${RES}"
    echo -e "${YELLOW_COLOR}网络名称: ${RES}easytier"
    echo -e "${YELLOW_COLOR}网络密钥: ${RES}easytier"
    echo -e "${YELLOW_COLOR}公共节: ${RES}tcp://public.easytier.top:11010"
    
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
# 例ID
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
    "wg://0.0.0.0:11011/",
    "wss://0.0.0.0:11012/"
]

# Peer节点列表
[[peer]]
uri = "tcp://public.easytier.top:11010"

[[peer]]
uri = "udp://public.easytier.top:11010"

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
# TUN设备名称（使用简短名称）
dev_name = "$tun_name"
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

# 在创建配置前添加 DNS 检查函数
check_dns_resolution() {
    local domain="$1"
    if ! host "$domain" >/dev/null 2>&1; then
        if ! nslookup "$domain" >/dev/null 2>&1; then
            if ! dig "$domain" >/dev/null 2>&1; then
                return 1
            fi
        fi
    fi
    return 0
}

# 修改 TUN 设备名称生成函数
get_tun_device_name() {
    local mode="$1"
    local num="$2"
    
    case "$mode" in
        "server")
            echo "s${num}"  # s1, s2, s3...
            ;;
        "client")
            echo "c${num}"  # c1, c2, c3...
            ;;
        "public_server")
            echo "ps${num}"  # ps1, ps2, ps3...
            ;;
        "public_client")
            echo "pc${num}"  # pc1, pc2, pc3...
            ;;
        *)
            echo "t${num}"  # 默认情况，t1, t2, t3...
            ;;
    esac
}

# 添加备份配置函数
backup_configuration() {
    clear
    echo -e "${GREEN_COLOR}=================================${RES}"
    echo -e "${GREEN_COLOR}      备份 EasyTier 配置${RES}"
    echo -e "${GREEN_COLOR}=================================${RES}"
    
    # 列出现有配置
    echo -e "\n${BLUE_COLOR}现有配置：${RES}"
    local configs=()
    local i=1
    local config_dir="/opt/easytier/config"
    
    # 检查配置目录是否存在
    if [ ! -d "$config_dir" ]; then
        echo -e "${RED_COLOR}错：配置目录 $config_dir 不存在${RES}"
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
    echo -n "请选择要备份的配置 [0-$((i-1))]: "
    read choice
    
    if [ "$choice" = "0" ]; then
        return
    elif [ "$choice" -ge 1 ] && [ "$choice" -le $((i-1)) ]; then
        local config_file="${configs[$((choice-1))]}"
        local config_name=$(basename "$config_file" .conf)
        
        # 创建备份目录
        local backup_dir="$HOME/.easytier_backup"
        local backup_time=$(date +%Y%m%d_%H%M%S)
        local backup_path="$backup_dir/${config_name}_${backup_time}"
        mkdir -p "$backup_path"
        
        echo -e "\n${BLUE_COLOR}正在备份文件...${RES}"
        
        # 1. 备份配置文件
        if [ -f "$config_file" ]; then
            cp -p "$config_file" "$backup_path/"
            echo -e "${GREEN_COLOR}已备份配置文件${RES}"
        fi
        
        # 2. 备份服务文件
        if [ -f "/etc/systemd/system/easytier@${config_name}.service" ]; then
            cp -p "/etc/systemd/system/easytier@${config_name}.service" "$backup_path/"
            echo -e "${GREEN_COLOR}已备份服务文件${RES}"
        fi
        
        # 3. 备份 WireGuard 配置
        if [ -f "/opt/easytier/wireguard/${config_name}.conf" ]; then
            cp -p "/opt/easytier/wireguard/${config_name}.conf" "$backup_path/"
            echo -e "${GREEN_COLOR}已备份 WireGuard 配置${RES}"
        fi
        
        # 4. 备份运行时数据（如果存在）
        if [ -d "/run/easytier/${config_name}" ]; then
            cp -rp "/run/easytier/${config_name}" "$backup_path/runtime_data"
            echo -e "${GREEN_COLOR}已备份运行时数据${RES}"
        fi
        
        echo -e "\n${GREEN_COLOR}备份完成！${RES}"
        echo -e "${YELLOW_COLOR}备份文件已保存在：${RES} $backup_path"
        echo -e "\n按回车键继续..."
        read
    else
        echo -e "${RED_COLOR}无效选择${RES}"
        sleep 1
    fi
}

# 添加恢复配置函数
restore_configuration() {
    clear
    echo -e "${GREEN_COLOR}=================================${RES}"
    echo -e "${GREEN_COLOR}      恢复 EasyTier 配置${RES}"
    echo -e "${GREEN_COLOR}=================================${RES}"
    
    local backup_dir="$HOME/.easytier_backup"
    
    # 检查备份目录是否存在
    if [ ! -d "$backup_dir" ]; then
        echo -e "${RED_COLOR}错误：备份目录不存在${RES}"
        echo -e "\n按回车键继续..."
        read
        return
    fi
    
    # 列出所有备份
    echo -e "\n${BLUE_COLOR}可用的备份：${RES}"
    local backups=()
    local i=1
    
    while IFS= read -r backup; do
        if [ -d "$backup" ]; then
            backups+=("$backup")
            local backup_name=$(basename "$backup")
            local backup_time=${backup_name##*_}
            local config_name=${backup_name%_*}
            echo "$i. $config_name (备份时间: ${backup_time})"
            ((i++))
        fi
    done < <(ls -d "$backup_dir"/*/ 2>/dev/null)
    
    if [ ${#backups[@]} -eq 0 ]; then
        echo "暂无可用的备份"
        echo -e "\n按回车键继续..."
        read
        return
    fi
    
    echo -e "\n0. 返回上级菜单"
    echo -n "请选择要恢复的备份 [0-$((i-1))]: "
    read choice
    
    if [ "$choice" = "0" ]; then
        return
    elif [ "$choice" -ge 1 ] && [ "$choice" -le $((i-1)) ]; then
        local backup_path="${backups[$((choice-1))]}"
        local backup_name=$(basename "$backup_path")
        local config_name=${backup_name%_*}
        
        echo -e "\n${YELLOW_COLOR}警告：恢复操作将覆盖现有配置（如果存在）${RES}"
        echo -n "是否继续？[y/N]: "
        read confirm
        
        case "$confirm" in
            [Yy]*)
                # 1. 停止现有服务（如果存在）
                if systemctl is-active --quiet "easytier@${config_name}"; then
                    echo -e "\n${BLUE_COLOR}正在停止现有服务...${RES}"
                    systemctl stop "easytier@${config_name}"
                    systemctl disable "easytier@${config_name}" >/dev/null 2>&1
                fi
                
                echo -e "\n${BLUE_COLOR}正在恢复文件...${RES}"
                
                # 2. 恢复配置文件
                if [ -f "$backup_path/${config_name}.conf" ]; then
                    mkdir -p "/opt/easytier/config"
                    cp -p "$backup_path/${config_name}.conf" "/opt/easytier/config/"
                    echo -e "${GREEN_COLOR}已恢复配置文件${RES}"
                fi
                
                # 3. 恢复服务文件
                if [ -f "$backup_path/easytier@${config_name}.service" ]; then
                    cp -p "$backup_path/easytier@${config_name}.service" "/etc/systemd/system/"
                    systemctl daemon-reload
                    echo -e "${GREEN_COLOR}已恢复服务文件${RES}"
                fi
                
                # 4. 恢复 WireGuard 配置
                if [ -f "$backup_path/${config_name}.conf" ]; then
                    mkdir -p "/opt/easytier/wireguard"
                    cp -p "$backup_path/${config_name}.conf" "/opt/easytier/wireguard/"
                    echo -e "${GREEN_COLOR}已恢复 WireGuard 配置${RES}"
                fi
                
                # 5. 恢复运行时数据
                if [ -d "$backup_path/runtime_data" ]; then
                    mkdir -p "/run/easytier/${config_name}"
                    cp -rp "$backup_path/runtime_data/"* "/run/easytier/${config_name}/"
                    echo -e "${GREEN_COLOR}已恢复运行时数据${RES}"
                fi
                
                # 6. 设置正确的权限
                chmod 644 "/opt/easytier/config/${config_name}.conf"
                chmod 644 "/etc/systemd/system/easytier@${config_name}.service"
                chmod -R 755 "/run/easytier/${config_name}"
                
                echo -e "\n${GREEN_COLOR}恢复完成！${RES}"
                
                # 询问是否启动服务
                echo -n "是否立即启动服务？[Y/n]: "
                read start_service
                
                case "$start_service" in
                    [Nn]*)
                        echo -e "${YELLOW_COLOR}服务未启动，您可以稍后手动启动${RES}"
                        ;;
                    *)
                        echo -e "\n${BLUE_COLOR}正在启动服务...${RES}"
                        systemctl enable "easytier@${config_name}" >/dev/null 2>&1
                        if systemctl start "easytier@${config_name}"; then
                            echo -e "${GREEN_COLOR}服务启动成功！${RES}"
                            systemctl status "easytier@${config_name}" --no-pager
                        else
                            echo -e "${RED_COLOR}服务启动失败${RES}"
                            echo -e "${YELLOW_COLOR}请检查配置文件或查看日志：${RES}"
                            echo "journalctl -u easytier@${config_name} -n 50 --no-pager"
                        fi
                        ;;
                esac
                ;;
            *)
                echo -e "\n${YELLOW_COLOR}恢复操作已取消${RES}"
                ;;
        esac
        
        echo -e "\n按回车键继续..."
        read
    else
        echo -e "${RED_COLOR}无效选择${RES}"
        sleep 1
    fi
}