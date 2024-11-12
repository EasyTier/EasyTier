#!/bin/bash

# 添加日志函数
log_message() {
    local level="$1"
    local message="$2"
    local log_file="/var/log/easytier/install.log"
    
    mkdir -p "$(dirname "$log_file")"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" >> "$log_file"
}

# 权限检查函数
check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED_COLOR}请使用root权限运行此脚本${RES}"
        log_message "ERROR" "Script must be run as root"
        return 1
    fi
    return 0
}

# 检查依赖函数
check_dependencies() {
    local missing_deps=()
    
    # 检查必要的命令
    local required_commands=(
        "curl"
        "unzip"
        "systemctl"
        "tar"
        "grep"
        "sed"
        "awk"
    )
    
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    # 如果有缺失的依赖，尝试安装
    if [ ${#missing_deps[@]} -ne 0 ]; then
        echo -e "${YELLOW_COLOR}检测到缺少以下依赖：${RES}"
        printf '%s\n' "${missing_deps[@]}"
        
        echo -e "\n${BLUE_COLOR}正在尝试安装缺失的依赖...${RES}"
        
        # 检测包管理器
        if command -v apt >/dev/null 2>&1; then
            apt update
            apt install -y "${missing_deps[@]}"
        elif command -v yum >/dev/null 2>&1; then
            yum install -y "${missing_deps[@]}"
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y "${missing_deps[@]}"
        else
            echo -e "${RED_COLOR}错误：无法确定系统的包管理器${RES}"
            return 1
        fi
        
        # 再次检查依赖是否安装成功
        local still_missing=()
        for cmd in "${missing_deps[@]}"; do
            if ! command -v "$cmd" >/dev/null 2>&1; then
                still_missing+=("$cmd")
            fi
        done
        
        if [ ${#still_missing[@]} -ne 0 ]; then
            echo -e "${RED_COLOR}错误：以下依赖安装失败：${RES}"
            printf '%s\n' "${still_missing[@]}"
            return 1
        fi
    fi
    
    return 0
}

# 系统检测函数
check_system() {
    # 获取系统架构
    if command -v arch >/dev/null 2>&1; then
        platform=$(arch)
    else
        platform=$(uname -m)
    fi

    # 确定目���架构
    case "$platform" in
        amd64 | x86_64)
            ARCH="x86_64"
            ;;
        arm64 | aarch64 | *armv8*)
            ARCH="aarch64"
            ;;
        *armv7*)
            ARCH="armv7"
            ;;
        *arm*)
            ARCH="arm"
            ;;
        mips)
            ARCH="mips"
            ;;
        mipsel)
            ARCH="mipsel"
            ;;
        *)
            ARCH="UNKNOWN"
            ;;
    esac

    # 获取操作系统信息
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_NAME="$NAME"
        OS_VERSION="$VERSION_ID"
    elif [ -f /etc/redhat-release ]; then
        OS_NAME=$(cat /etc/redhat-release | cut -d' ' -f1)
        OS_VERSION=$(cat /etc/redhat-release | grep -oE '[0-9]+\.[0-9]+')
    else
        OS_NAME=$(uname -s)
        OS_VERSION=$(uname -r)
    fi

    # 导出变量供其他函数使用
    export OS_NAME
    export OS_VERSION
    export PLATFORM="$platform"
    export ARCH

    # 检查架构是否支持
    if [ "$ARCH" == "UNKNOWN" ]; then
        echo -e "\n${RED_COLOR}错误: 不支持的系统架构${RES}"
        log_message "ERROR" "Unsupported architecture: $platform"
        return 1
    fi

    # 检查是否支持 systemd
    if ! command -v systemctl >/dev/null 2>&1; then
        echo -e "\n${RED_COLOR}错误: 您的系统不支持 systemctl${RES}"
        log_message "ERROR" "System does not support systemctl"
        return 1
    fi

    log_message "INFO" "System check completed. OS: $OS_NAME $OS_VERSION, Arch: $ARCH"
    return 0
}

# 端口检查函数
check_port() {
    local port="$1"
    if ! command -v netstat >/dev/null 2>&1; then
        if ! command -v ss >/dev/null 2>&1; then
            return 1
        fi
        if ss -ln | grep -q ":$port "; then
            return 1
        fi
    else
        if netstat -tuln | grep -q ":$port "; then
            return 1
        fi
    fi
    return 0
}

# 下载函数
download_file() {
    local version="$1"
    local package_name="$2"
    local output_file="$3"
    local retry_count=0
    local max_retries=3
    
    # 显示下载信息
    echo -e "\n${BLUE_COLOR}正在下载 ${version} ...${RES}"
    echo -e "${BLUE_COLOR}目标安装包: ${package_name}${RES}"
    
    # 构建下载链接数组，CDN 源放在前面
    local download_urls=(
        "https://ghproxy.com/https://github.com/EasyTier/EasyTier/releases/download/${version}/${package_name}"
        "https://mirror.ghproxy.com/https://github.com/EasyTier/EasyTier/releases/download/${version}/${package_name}"
        "https://hub.gitmirror.com/https://github.com/EasyTier/EasyTier/releases/download/${version}/${package_name}"
        "https://gh.ddlc.top/https://github.com/EasyTier/EasyTier/releases/download/${version}/${package_name}"
        "https://gh.api.99988866.xyz/https://github.com/EasyTier/EasyTier/releases/download/${version}/${package_name}"
        "https://github.com/EasyTier/EasyTier/releases/download/${version}/${package_name}"
    )
    
    while [ $retry_count -lt $max_retries ]; do
        for url in "${download_urls[@]}"; do
            echo -e "\n${BLUE_COLOR}尝试下载: ${url}${RES}"
            log_message "INFO" "Attempting download from: ${url}"
            
            if curl -L --connect-timeout 10 "${url}" -o "$output_file" $CURL_BAR; then
                if [ -s "$output_file" ] && unzip -t "$output_file" >/dev/null 2>&1; then
                    echo -e "${GREEN_COLOR}下载成功！${RES}"
                    log_message "INFO" "Download successful"
                    return 0
                fi
                rm -f "$output_file"
            fi
            
            log_message "WARNING" "Download failed from: ${url}"
        done
        
        ((retry_count++))
        if [ $retry_count -lt $max_retries ]; then
            echo -e "\n${YELLOW_COLOR}重试下载 ($retry_count/$max_retries)${RES}"
            sleep 3
        fi
    done
    
    echo -e "\n${RED_COLOR}错误: 下载失败${RES}"
    log_message "ERROR" "All download attempts failed"
    return 1
}

# 获取最新版本和下载链接
get_download_info() {
    # 设置固定版本号
    LATEST_VERSION="2.0.3"
    
    # 构建包名
    PACKAGE_NAME="easytier-linux-${ARCH}-v${LATEST_VERSION}.zip"
    
    # 返回版本号和包名
    echo "v${LATEST_VERSION}:${PACKAGE_NAME}"
}

# 获取本地版本
get_local_version() {
    if [ -f "$INSTALL_PATH/easytier-core" ]; then
        # 获取完整版本信息
        local full_version=$("$INSTALL_PATH/easytier-core" -V 2>/dev/null)
        # 提取版本号部分
        local version=$(echo "$full_version" | cut -d' ' -f2 | cut -d'-' -f1)
        # 添加 v 前缀
        if $IS_CN; then
            echo "v$version"
        else
            if [ -n "$version" ]; then
                echo "v$version"
            else
                echo "Not installed"
            fi
        fi
    else
        if $IS_CN; then
            echo "未安装"
        else
            echo "Not installed"
        fi
    fi
}

# 版本比较函数
compare_versions() {
    local ver1=$(echo "$1" | sed 's/^v//')  # 移除 v 前缀
    local ver2=$(echo "$2" | sed 's/^v//')  # 移除 v 前缀
    
    if [[ "$ver1" == "$ver2" ]]; then
        echo "equal"
    elif [[ "$(printf '%s\n' "$ver1" "$ver2" | sort -V | head -n1)" == "$ver1" ]]; then
        echo "older"
    else
        echo "newer"
    fi
}

# 检查更新函数
check_update() {
    local latest_version=$(get_download_info | cut -d':' -f1)
    local local_version=$(get_local_version)
    
    if [ "$local_version" = "未安装" ]; then
        return 2  # 未安装
    fi
    
    local compare_result=$(compare_versions "$local_version" "$latest_version")
    case "$compare_result" in
        "equal")
            return 0  # 已是最新版本
            ;;
        "older")
            return 1  # 有新版本
            ;;
        "newer")
            return 3  # 本地版本较新
            ;;
    esac
}

# 显示版本信息函数
show_version_info() {
    local latest_version=$(get_download_info | cut -d':' -f1)
    local local_version=$(get_local_version)
    
    if $IS_CN; then
        echo -e "\n${BLUE_COLOR}版本信息：${RES}"
        echo "官方最新版本: $latest_version"
        echo "本地安装版本: $local_version"
    else
        echo -e "\n${BLUE_COLOR}Version Information:${RES}"
        echo "Latest Version: $latest_version"
        echo "Local Version: $local_version"
    fi
    
    if [ "$local_version" != "未安装" ] && [ "$local_version" != "Not installed" ]; then
        local compare_result=$(compare_versions "$local_version" "$latest_version")
        if $IS_CN; then
            case "$compare_result" in
                "equal")
                    echo -e "${GREEN_COLOR}状态: 已是最新版本${RES}"
                    ;;
                "older")
                    echo -e "${YELLOW_COLOR}状态: 有新版本可用${RES}"
                    ;;
                "newer")
                    echo -e "${BLUE_COLOR}状态: 本地版本较新${RES}"
                    ;;
            esac
        else
            case "$compare_result" in
                "equal")
                    echo -e "${GREEN_COLOR}Status: Up to date${RES}"
                    ;;
                "older")
                    echo -e "${YELLOW_COLOR}Status: Update available${RES}"
                    ;;
                "newer")
                    echo -e "${BLUE_COLOR}Status: Local version is newer${RES}"
                    ;;
            esac
        fi
    fi
}

# 配置文件检查函数
check_config() {
    local config_file="$1"
    if [ ! -f "$config_file" ]; then
        echo -e "${RED_COLOR}配置文件不存在${RES}"
        log_message "ERROR" "Config file not found: $config_file"
        return 1
    fi
    return 0
}

# 添加系统优化函数
optimize_system() {
    # 调整系统参数
    sysctl -w net.ipv4.ip_forward=1
    sysctl -w net.ipv4.tcp_fastopen=3
    sysctl -w net.core.rmem_max=26214400
    sysctl -w net.core.wmem_max=26214400
    
    # 持久化设
    cat > /etc/sysctl.d/99-easytier.conf << EOF
net.ipv4.ip_forward = 1
net.ipv4.tcp_fastopen = 3
net.core.rmem_max = 26214400
net.core.wmem_max = 26214400
EOF
    
    sysctl -p /etc/sysctl.d/99-easytier.conf
}

# 添加诊断函数
diagnose_easytier() {
    echo -e "${BLUE_COLOR}开始诊断 EasyTier...${RES}"
    
    # 检查系统状态
    echo -e "\n${BLUE_COLOR}系统状态：${RES}"
    echo "内存使用: $(free -h)"
    echo "CPU负载: $(uptime)"
    
    # 检查网络状态
    echo -e "\n${BLUE_COLOR}网络状态：${RES}"
    echo "网络接口:"
    ip addr
    
    # 检查服务状态
    echo -e "\n${BLUE_COLOR}服务状态：${RES}"
    systemctl status 'easytier@*'
    
    # 检查日志
    echo -e "\n${BLUE_COLOR}最近日志：${RES}"
    journalctl -u 'easytier@*' -n 50 --no-pager
}

# 添加错误处理函数
handle_error() {
    local error_code=$1
    local error_message=$2
    
    echo -e "${RED_COLOR}错误: $error_message${RES}"
    log_message "ERROR" "$error_message (代码: $error_code)"
    
    case $error_code in
        1) echo "建议: 请检查您的权限" ;;
        2) echo "建议: 请检查网络连接" ;;
        3) echo "建议: 请检查磁盘间" ;;
        *) echo "建议: 请查看日志获取详细信息" ;;
    esac
}

# 添加健康检查函数
health_check() {
    echo -e "${BLUE_COLOR}执行健康检查...${RES}"
    
    # 检查服务状态
    local services=$(systemctl list-units --type=service --state=running | grep easytier@ | wc -l)
    echo "运行中的服务: $services"
    
    # 检查资源使用
    local cpu_usage=$(ps aux | grep easytier-core | grep -v grep | awk '{print $3}')
    local mem_usage=$(ps aux | grep easytier-core | grep -v grep | awk '{print $4}')
    echo "CPU使用率: $cpu_usage%"
    echo "内存使用率: $mem_usage%"
    
    # 检查网络连接
    local connections=$(netstat -an | grep :11010 | wc -l)
    echo "活动连接数: $connections"
}

# 添加进度条函数
show_progress() {
    local current=$1
    local total=$2
    local width=50
    local percentage=$((current * 100 / total))
    local completed=$((width * current / total))
    local remaining=$((width - completed))
    
    printf "\r["
    printf "%${completed}s" | tr ' ' '#'
    printf "%${remaining}s" | tr ' ' '-'
    printf "] %d%%" $percentage
}

# 添加旋转加载动画
show_spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf "\r[%c] " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
    done
    printf "\r"
}

# 修改网络诊断函数
network_diagnosis() {
    while true; do
        clear
        echo -e "${BLUE_COLOR}开始网络诊断...${RES}"
        
        # 检查网络接口
        echo -e "\n${BLUE_COLOR}网络接口状态：${RES}"
        ip link show
        
        # 检查路由表
        echo -e "\n${BLUE_COLOR}路由表：${RES}"
        ip route
        
        # 检查DNS
        echo -e "\n${BLUE_COLOR}DNS配置：${RES}"
        cat /etc/resolv.conf
        
        # 检查防火墙
        echo -e "\n${BLUE_COLOR}防火墙状态：${RES}"
        if command -v ufw >/dev/null 2>&1; then
            ufw status
        elif command -v firewall-cmd >/dev/null 2>&1; then
            firewall-cmd --list-all
        fi
        
        # 检查端口占用
        echo -e "\n${BLUE_COLOR}端口占用情况：${RES}"
        netstat -tuln | grep LISTEN

        echo -e "\n${BLUE_COLOR}诊断选项：${RES}"
        echo "1. 刷新诊断信息"
        echo "2. 测试网络连接"
        echo "3. 检查特定端口"
        echo "4. 查看详细信息"
        echo "0. 返回上级菜单"
        
        echo -n -e "\n请选择 [0-4]: "
        read choice
        
        case "$choice" in
            1) continue ;;
            2) 
                echo -n "请输入要测试的地址: "
                read test_addr
                ping -c 4 "$test_addr"
                echo -e "\n按回车键继续..."
                read
                ;;
            3)
                echo -n "请输入要检查的端口: "
                read port
                netstat -tuln | grep ":$port"
                echo -e "\n按回车键继续..."
                read
                ;;
            4)
                echo -e "\n${BLUE_COLOR}详细网络信息：${RES}"
                ip -s link
                echo -e "\n${BLUE_COLOR}网络统计：${RES}"
                netstat -s
                echo -e "\n按回车键继续..."
                read
                ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 修改性能监控函数
monitor_performance() {
    while true; do
        clear
        echo -e "${BLUE_COLOR}EasyTier 性能监控${RES}"
        echo "按 q 退出监控"
        echo -e "\n${YELLOW_COLOR}系统资源使用情况：${RES}"
        
        # CPU使用率
        echo -e "\n${BLUE_COLOR}CPU使用率：${RES}"
        top -bn1 | head -n 5
        
        # 内存使用
        echo -e "\n${BLUE_COLOR}内存使用：${RES}"
        free -h
        
        # EasyTier进程状态
        echo -e "\n${BLUE_COLOR}EasyTier进程：${RES}"
        ps aux | grep easytier-core | grep -v grep
        
        # 网络连接
        echo -e "\n${BLUE_COLOR}网络连接：${RES}"
        netstat -tnp | grep easytier-core
        
        echo -e "\n${BLUE_COLOR}监控选项：${RES}"
        echo "1. 刷新监控信息"
        echo "2. 查看详细CPU信息"
        echo "3. 查看详细内存信息"
        echo "4. 查看详细网络信息"
        echo "0. 返回上级菜单"
        
        echo -n -e "\n请选择 [0-4]: "
        read choice
        
        case "$choice" in
            1) continue ;;
            2)
                clear
                echo -e "${BLUE_COLOR}CPU详细信息：${RES}"
                mpstat -P ALL 1 5
                echo -e "\n按回车键继续..."
                read
                ;;
            3)
                clear
                echo -e "${BLUE_COLOR}内存详细信息：${RES}"
                vmstat -S M 1 5
                echo -e "\n按回车键继续..."
                read
                ;;
            4)
                clear
                echo -e "${BLUE_COLOR}网络详细信息：${RES}"
                iftop -t -s 5 2>/dev/null
                echo -e "\n按回车键继续..."
                read
                ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 修改日志分析函数
analyze_logs() {
    while true; do
        clear
        echo -e "${BLUE_COLOR}日志析工具${RES}"
        
        echo -e "\n${BLUE_COLOR}分析选项：${RES}"
        echo "1. 查看错误日志"
        echo "2. 查看警告日志"
        echo "3. 查看连接日志"
        echo "4. 查看最近日志"
        echo "5. 导出日志"
        echo "0. 返回上级菜单"
        
        echo -n -e "\n请选择 [0-5]: "
        read choice
        
        case "$choice" in
            1)
                clear
                echo -e "${BLUE_COLOR}错误日志：${RES}"
                journalctl -u 'easytier@*' --since "24 hours ago" | grep -i "error"
                echo -e "\n按回车键继续..."
                read
                ;;
            2)
                clear
                echo -e "${BLUE_COLOR}警告日志：${RES}"
                journalctl -u 'easytier@*' --since "24 hours ago" | grep -i "warning"
                echo -e "\n按回车键继续..."
                read
                ;;
            3)
                clear
                echo -e "${BLUE_COLOR}连接日志：${RES}"
                journalctl -u 'easytier@*' --since "24 hours ago" | grep -i "connect\|disconnect"
                echo -e "\n按回车键继续..."
                read
                ;;
            4)
                clear
                echo -e "${BLUE_COLOR}最近日志：${RES}"
                journalctl -u 'easytier@*' -n 50 --no-pager
                echo -e "\n按回车键继续..."
                read
                ;;
            5)
                local log_file="/tmp/easytier_logs_$(date +%Y%m%d_%H%M%S).txt"
                journalctl -u 'easytier@*' --since "24 hours ago" > "$log_file"
                echo -e "${GREEN_COLOR}日志已导出到：${RES} $log_file"
                echo -e "\n按回车键继续..."
                read
                ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 修改安全检查函数
security_check() {
    while true; do
        clear
        echo -e "${BLUE_COLOR}安全检查工具${RES}"
        
        echo -e "\n${BLUE_COLOR}检查选项：${RES}"
        echo "1. 检查文件权限"
        echo "2. 检查网络安全"
        echo "3. 检查系统安全"
        echo "4. 生成安全报告"
        echo "0. 返回上级菜单"
        
        echo -n -e "\n请选择 [0-4]: "
        read choice
        
        case "$choice" in
            1)
                clear
                echo -e "${BLUE_COLOR}文件权限检查：${RES}"
                check_file_permissions
                echo -e "\n按回车键继续..."
                read
                ;;
            2)
                clear
                echo -e "${BLUE_COLOR}网络安全检查：${RES}"
                check_network_security
                echo -e "\n按回车键继续..."
                read
                ;;
            3)
                clear
                echo -e "${BLUE_COLOR}系统安全检查：${RES}"
                check_system_security
                echo -e "\n按回车键继续..."
                read
                ;;
            4)
                generate_security_report
                echo -e "\n按回车键继续..."
                read
                ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 添加文件权限检查函数
check_file_permissions() {
    echo -e "\n${BLUE_COLOR}配置文件权限：${RES}"
    find "$INSTALL_PATH/config" -type f -name "*.conf" -exec ls -l {} \;
    
    echo -e "\n${BLUE_COLOR}程序文件权限：${RES}"
    ls -l "$INSTALL_PATH/easytier-core" "$INSTALL_PATH/easytier-cli"
    
    echo -e "\n${BLUE_COLOR}服务文件权限：${RES}"
    ls -l /etc/systemd/system/easytier@*.service
}

# 添加网络安全检查函数
check_network_security() {
    echo -e "\n${BLUE_COLOR}开放端口：${RES}"
    netstat -tuln | grep LISTEN
    
    echo -e "\n${BLUE_COLOR}活动连接：${RES}"
    netstat -tn | grep ESTABLISHED
    
    echo -e "\n${BLUE_COLOR}防火墙规则：${RES}"
    if command -v ufw >/dev/null 2>&1; then
        ufw status verbose
    elif command -v firewall-cmd >/dev/null 2>&1; then
        firewall-cmd --list-all
    fi
}

# 添加系统安全检查函数
check_system_security() {
    echo -e "\n${BLUE_COLOR}系统更新状态：${RES}"
    if command -v apt >/dev/null 2>&1; then
        apt list --upgradable
    elif command -v yum >/dev/null 2>&1; then
        yum check-update
    fi
    
    echo -e "\n${BLUE_COLOR}系统服务状态：${RES}"
    systemctl list-units --type=service --state=running
    
    echo -e "\n${BLUE_COLOR}系统日志：${RES}"
    tail -n 20 /var/log/syslog 2>/dev/null || tail -n 20 /var/log/messages
}

# 添加安全报告生成函数
generate_security_report() {
    local report_file="/tmp/easytier_security_report_$(date +%Y%m%d_%H%M%S).txt"
    
    {
        echo "EasyTier 安全报告"
        echo "生成时间: $(date)"
        echo "----------------------------------------"
        
        echo -e "\n文件权限检查:"
        check_file_permissions
        
        echo -e "\n网络安全检查:"
        check_network_security
        
        echo -e "\n系统安全检查:"
        check_system_security
        
    } > "$report_file"
    
    echo -e "${GREEN_COLOR}安全报告已生成：${RES} $report_file"
}

# 添加一键修复函数
quick_fix() {
    echo -e "${BLUE_COLOR}开始修复常见问题...${RES}"
    
    # 修复权限
    echo -e "\n${BLUE_COLOR}修复权限...${RES}"
    chmod -R 644 "$INSTALL_PATH/config"/*.conf
    chmod 755 "$INSTALL_PATH/easytier-core"
    chmod 755 "$INSTALL_PATH/easytier-cli"
    
    # 修复服务
    echo -e "\n${BLUE_COLOR}修复服务...${RES}"
    systemctl daemon-reload
    systemctl reset-failed
    
    # 修复网络
    echo -e "\n${BLUE_COLOR}修复网络...${RES}"
    ip link set dev easytier0 down 2>/dev/null
    ip link set dev easytier0 up 2>/dev/null
    
    # 清理日志
    echo -e "\n${BLUE_COLOR}清理日志...${RES}"
    journalctl --vacuum-time=2d
    
    echo -e "${GREEN_COLOR}修复完成${RES}"
}

# 修改版本检查函数
check_version_update() {
    local latest_version=$(get_download_info | cut -d':' -f1)
    local local_version=$(get_local_version)
    
    if [ "$local_version" != "未安装" ] && [ "$local_version" != "Not installed" ] && [ "$latest_version" != "$local_version" ]; then
        if $IS_CN; then
            echo -e "${YELLOW_COLOR}发现新版本: ${latest_version}${RES}"
            echo -e "${YELLOW_COLOR}建议更新您的 EasyTier${RES}"
        else
            echo -e "${YELLOW_COLOR}New version available: ${latest_version}${RES}"
            echo -e "${YELLOW_COLOR}It is recommended to update your EasyTier${RES}"
        fi
        sleep 2
    fi
}
