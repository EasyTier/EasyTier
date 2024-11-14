#!/bin/bash

# 定义镜像源列表
MIRROR_URLS=(
     "https://gcore.jsdelivr.net/gh/CGG888/EasyTier/script"
     "https://fastly.jsdelivr.net/gh/CGG888/EasyTier/script"
     "https://testingcf.jsdelivr.net/gh/CGG888/EasyTier/script"
     "https://quantil.jsdelivr.net/gh/CGG888/EasyTier/script"
    "https://ghp.ci/https://raw.githubusercontent.com/CGG888/EasyTier/main/script"
    "https://mirror.ghproxy.com/https://raw.githubusercontent.com/CGG888/EasyTier/main/script"
    "https://hub.gitmirror.com/https://raw.githubusercontent.com/CGG888/EasyTier/main/script"
    "https://gh.ddlc.top/https://raw.githubusercontent.com/CGG888/EasyTier/main/script"
    "https://gh.api.99988866.xyz/https://raw.githubusercontent.com/CGG888/EasyTier/main/script"
    "https://raw.githubusercontent.com/CGG888/EasyTier/main/script"
)

# 测试镜像源速度并排序
test_mirror_speed() {
    local mirror_url="$1"
    local domain=$(echo "$mirror_url" | sed -e 's|^[^/]*//||' -e 's|/.*$||')
    local start_time=$(date +%s%N)
    ping -c 1 -W 1 "$domain" >/dev/null 2>&1
    local status=$?
    local end_time=$(date +%s%N)
    local time_diff=$((($end_time - $start_time)/1000000)) # 转换为毫秒

    if [ $status -eq 0 ]; then
        echo "$time_diff $mirror_url"
    else
        echo "999999 $mirror_url" # 如果ping失败，给一个很大的延迟值
    fi
}

# 对镜像源进行速度测试和排序
echo -e "${BLUE_COLOR}正在测试镜像源速度...${RES}"
SORTED_MIRRORS=()
while read -r line; do
    SORTED_MIRRORS+=("$(echo "$line" | cut -d' ' -f2-)")
done < <(
    for url in "${MIRROR_URLS[@]}"; do
        test_mirror_speed "$url"
    done | sort -n
)

# 显示测试结果
echo -e "\n${GREEN_COLOR}镜像源速度测试结果：${RES}"
for i in "${!SORTED_MIRRORS[@]}"; do
    echo "[$((i+1))] ${SORTED_MIRRORS[$i]}"
done

# 导入其他脚本
for script in utils.sh install.sh config.sh backup.sh; do
    echo -e "\n${BLUE_COLOR}正在加载 $script ...${RES}"
    loaded=false
    
    for url in "${SORTED_MIRRORS[@]}"; do
        echo -e "尝试从 ${url} 加载..."
        if source <(curl -sL "${url}/${script}"); then
            echo -e "${GREEN_COLOR}成功从最快的镜像加载 $script${RES}"
            loaded=true
            break
        fi
    done
    
    if ! $loaded; then
        echo -e "${RED_COLOR}错误：无法加载 $script，所有镜像源都无法访问${RES}"
        exit 1
    fi
done

# 导入其他脚本
#SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
#source "${SCRIPT_DIR}/utils.sh"
#source "${SCRIPT_DIR}/install.sh"
#source "${SCRIPT_DIR}/config.sh"
#source "${SCRIPT_DIR}/backup.sh"

# 定义颜色变量
RED_COLOR='\e[1;31m'
GREEN_COLOR='\e[1;32m'
YELLOW_COLOR='\e[1;33m'
BLUE_COLOR='\e[1;34m'
PINK_COLOR='\e[1;35m'
SHAN='\e[1;33;5m'
RES='\e[0m'

# 初始化变量
SKIP_FOLDER_VERIFY=false
SKIP_FOLDER_FIX=false
FORCE_LANG=""
INSTALL_PATH=""
IS_CN=false
COMMEND=""

# 修改版本信息定义
SCRIPT_VERSION="v1.0.0"
EASYTIER_VERSION="v2.0.3"

# 在主菜单前添加版本检查函数
check_version_update() {
    local latest_version=$(get_download_info | cut -d':' -f1)
    local local_version=$(get_local_version)
    
    if [ "$local_version" != "未安装" ] && [ "$latest_version" != "$local_version" ]; then
        echo -e "${YELLOW_COLOR}发现新版本: ${latest_version}${RES}"
        echo -e "${YELLOW_COLOR}建议更新您的 EasyTier${RES}"
        sleep 2
    fi
}

# 主菜单显示函数
show_main_menu() {
    check_version_update
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      ${MSG_WELCOME}${RES}"
        if $IS_CN; then
            echo -e "${GREEN_COLOR}      版本: ${SCRIPT_VERSION}${RES}"
        else
            echo -e "${GREEN_COLOR}      Version: ${SCRIPT_VERSION}${RES}"
        fi
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        # 获取版本信息
        local latest_version=$(get_download_info | cut -d':' -f1)
        local local_version=$(get_local_version)
        
        echo -e "\n${BLUE_COLOR}${MSG_VERSION_INFO}:${RES}"
        if $IS_CN; then
            echo "官方最新版本: ${latest_version:-获取失败}"
            echo "本地安装版本: ${local_version:-未安装}"
        else
            echo "Latest Version: ${latest_version:-Failed to get}"
            echo "Local Version: ${local_version:-Not installed}"
        fi
        
        echo -e "\n${BLUE_COLOR}${MSG_SYSTEM_INFO}:${RES}"
        echo "操作系统: $OS_NAME $OS_VERSION"
        echo "系统架构: $PLATFORM ($ARCH)"
        echo "内核版本: $(uname -r)"
        echo "CPU架构: $(uname -m)"
        
        echo -e "\n${BLUE_COLOR}软件信息：${RES}"
        echo "EasyTier 是一个网状 P2P VPN，一条命令即可将所有设备连接到同一网络。"
        echo "支持的系统架构: x86_64, aarch64, armv7, arm, mips, mipsel"
        echo "支持的操作系统: Linux (需要 systemd 支持)"
        
        echo -e "\n${YELLOW_COLOR}注意事项：${RES}"
        echo "1. EasyTier 需要一个专用的空文件夹来安装"
        echo "2. EasyTier 是一个开发中的产品，可能存在一些问题"
        echo "3. 使用 EasyTier 需要基本的网络知识"
        echo "4. 使用 EasyTier 带来的风险需要您自行承担"
        
        echo -e "\n${BLUE_COLOR}${MSG_MAIN_MENU}:${RES}"
        echo "1. ${MSG_INSTALL}"
        echo "2. ${MSG_UPDATE}"
        echo "3. ${MSG_UNINSTALL}"
        echo "4. ${MSG_CONFIG}"
        echo "5. ${MSG_CONTROL}"
        echo "6. ${MSG_TOOLS}"
        echo "0. ${MSG_EXIT}"
        
        # 显示当前状态
        echo -e "\n${BLUE_COLOR}当前状态：${RES}"
        if [ -f "$INSTALL_PATH/easytier-core" ]; then
            echo -e "${GREEN_COLOR}EasyTier 已安装${RES}"
            local version=$("$INSTALL_PATH/easytier-core" -V 2>/dev/null)
            echo "版本: ${version:-未知}"
            
            # 获取所有配置文件数量
            local config_count=$(ls -1 "$INSTALL_PATH/config"/*.conf 2>/dev/null | wc -l)
            echo "配置数量: $config_count"
            
            # 检查服务状态并显示实例
            local running_instances=0
            local stopped_instances=0
            echo -e "\n运行实例:"
            for conf in "$INSTALL_PATH/config"/*.conf; do
                if [ -f "$conf" ]; then
                    local instance_name=$(basename "$conf" .conf)
                    if systemctl is-active --quiet "easytier@${instance_name}"; then
                        echo -e "${GREEN_COLOR}- easytier@${instance_name}.service${RES}"
                        ((running_instances++))
                    fi
                fi
            done
            
            echo -e "\n停止实例:"
            for conf in "$INSTALL_PATH/config"/*.conf; do
                if [ -f "$conf" ]; then
                    local instance_name=$(basename "$conf" .conf)
                    if ! systemctl is-active --quiet "easytier@${instance_name}"; then
                        echo -e "${RED_COLOR}- easytier@${instance_name}.service${RES}"
                        ((stopped_instances++))
                    fi
                fi
            done
            
            # 显示服务状态统计
            if [ $running_instances -gt 0 ]; then
                echo -e "\n服务状态: ${GREEN_COLOR}运行中 ($running_instances 个运行, $stopped_instances 个停止)${RES}"
            else
                echo -e "\n服务状态: ${RED_COLOR}未运行 ($running_instances 个运行, $stopped_instances 个停止)${RES}"
            fi
        else
            echo -e "${RED_COLOR}EasyTier 未安装${RES}"
        fi
        
        if $IS_CN; then
            echo -n -e "\n请输入选项 [0-6]: "
        else
            echo -n -e "\nPlease select an option [0-6]: "
        fi
        read choice
        
        case "$choice" in
            1) install_easytier ;;
            2) update_easytier ;;
            3) uninstall_easytier ;;
            4) configure_easytier ;;
            5) show_control_menu ;;
            6) show_tools_menu ;;
            0) 
                if $IS_CN; then
                    echo -e "\n${GREEN_COLOR}感谢使用 EasyTier！${RES}"
                else
                    echo -e "\n${GREEN_COLOR}Thanks for using EasyTier!${RES}"
                fi
                exit 0
                ;;
            *)
                if $IS_CN; then
                    echo -e "\n${RED_COLOR}无效选项，请重新选择${RES}"
                else
                    echo -e "\n${RED_COLOR}Invalid option, please try again${RES}"
                fi
                sleep 2
                ;;
        esac
    done
}

# 添加工具箱菜单
show_tools_menu() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      ${MSG_TOOLS_TITLE}${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        echo -e "\n${BLUE_COLOR}${MSG_TOOLS_OPTIONS}：${RES}"
        echo "1. ${MSG_SYSTEM_OPTIMIZE}"
        echo "2. ${MSG_DIAGNOSTIC}"
        echo "3. ${MSG_PERFORMANCE}"
        echo "4. ${MSG_SECURITY}"
        echo "5. ${MSG_LOGS}"
        echo "6. ${MSG_QUICK_FIX}"
        echo "7. ${MSG_NETWORK_DIAG}"
        echo "0. ${MSG_BACK_MAIN}"
        
        echo -n -e "\n请选择 [0-7]: "
        read choice
        
        case "$choice" in
            1) show_optimization_menu ;;
            2) show_diagnostic_menu ;;
            3) show_monitor_menu ;;
            4) show_security_menu ;;
            5) analyze_logs ;;
            6) quick_fix ;;
            7) network_diagnosis ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 修改优化菜单
show_optimization_menu() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      系统优化工具${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        echo -e "\n${BLUE_COLOR}优化选项：${RES}"
        echo "1. 自动优化系统"
        echo "2. 优化网络参数"
        echo "3. 优化服务配置"
        echo "4. 清理系统缓存"
        echo "0. 返回上级菜单"
        
        echo -n -e "\n请选择 [0-4]: "
        read choice
        
        case "$choice" in
            1) auto_optimize ;;
            2) optimize_system ;;
            3) optimize_service_config ;;
            4) clear_system_cache ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 修改诊断菜单
show_diagnostic_menu() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      系统诊断工具${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        echo -e "\n${BLUE_COLOR}诊断选项：${RES}"
        echo "1. 系统诊断"
        echo "2. 服务诊断"
        echo "3. 配置诊断"
        echo "4. 依赖检查"
        echo "0. 返回上级菜单"
        
        echo -n -e "\n请选择 [0-4]: "
        read choice
        
        case "$choice" in
            1) diagnose_system ;;
            2) diagnose_service ;;
            3) diagnose_config ;;
            4) check_dependencies ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 修改监控菜单
show_monitor_menu() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      性能监控工具${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        echo -e "\n${BLUE_COLOR}监控选项：${RES}"
        echo "1. 实时性能监控"
        echo "2. 资源使用统计"
        echo "3. 网络流量监控"
        echo "4. 连接状态监控"
        echo "0. 返回上级菜单"
        
        echo -n -e "\n请选择 [0-4]: "
        read choice
        
        case "$choice" in
            1) monitor_performance ;;
            2) show_resource_usage ;;
            3) monitor_network_traffic ;;
            4) monitor_connections ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 修改安全菜单
show_security_menu() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      安全检查工具${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        echo -e "\n${BLUE_COLOR}安全选项：${RES}"
        echo "1. 文件权限检查"
        echo "2. 网络安全检查"
        echo "3. 系统安全检查"
        echo "4. 生成安全报告"
        echo "0. 返回上级菜单"
        
        echo -n -e "\n请选择 [0-4]: "
        read choice
        
        case "$choice" in
            1) check_file_permissions ;;
            2) check_network_security ;;
            3) check_system_security ;;
            4) generate_security_report ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 添加控制菜单函数
show_control_menu() {
    while true; do
        clear
        echo -e "${GREEN_COLOR}=================================${RES}"
        echo -e "${GREEN_COLOR}      ${MSG_CONTROL_TITLE}${RES}"
        echo -e "${GREEN_COLOR}=================================${RES}"
        
        # 显示当前服务状态
        echo -e "\n${BLUE_COLOR}当前状态：${RES}"
        local running_services=0
        local services_list=""
        while IFS= read -r line; do
            if [[ $line =~ easytier@ ]]; then
                ((running_services++))
                services_list+="- $line\n"
            fi
        done < <(systemctl list-units --type=service --state=running | grep easytier@)
        
        if [ $running_services -gt 0 ]; then
            echo -e "${GREEN_COLOR}运行中的实例 ($running_services):${RES}"
            echo -e "$services_list"
        else
            echo -e "${RED_COLOR}没有运行中的实例${RES}"
        fi
        
        echo -e "\n${BLUE_COLOR}${MSG_CONTROL_OPTIONS}：${RES}"
        echo "1. ${MSG_START_SERVICE}"
        echo "2. ${MSG_STOP_SERVICE}"
        echo "3. ${MSG_RESTART_SERVICE}"
        echo "4. ${MSG_START_ALL}"
        echo "5. ${MSG_STOP_ALL}"
        echo "6. ${MSG_RESTART_ALL}"
        echo "0. ${MSG_BACK_MAIN}"
        
        echo -n -e "\n请选择 [0-6]: "
        read choice
        
        case "$choice" in
            1) control_service "start" ;;
            2) control_service "stop" ;;
            3) control_service "restart" ;;
            4) control_all_services "start" ;;
            5) control_all_services "stop" ;;
            6) control_all_services "restart" ;;
            0) return ;;
            *)
                echo -e "${RED_COLOR}无效选项${RES}"
                sleep 1
                ;;
        esac
    done
}

# 添加控制单个服务函数
control_service() {
    local action=$1
    local config_dir="$INSTALL_PATH/config"
    local configs=()
    local i=1
    
    echo -e "\n${BLUE_COLOR}可用配置：${RES}"
    while IFS= read -r file; do
        if [[ $file == *.conf ]]; then
            configs+=("$file")
            local config_name="${file%.conf}"
            if systemctl is-active --quiet "easytier@${config_name}"; then
                echo -e "$i. ${config_name} [${GREEN_COLOR}运行中${RES}]"
            else
                echo -e "$i. ${config_name} [${RED_COLOR}已停止${RES}]"
            fi
            ((i++))
        fi
    done < <(ls -1 "$config_dir")
    
    if [ ${#configs[@]} -eq 0 ]; then
        echo -e "${RED_COLOR}没有找到配置文件${RES}"
        echo -e "\n按回车键继续..."
        read
        return
    fi
    
    echo -n "请选择配置 [1-$((i-1))]: "
    read selection
    
    if [ "$selection" -ge 1 ] && [ "$selection" -le $((i-1)) ]; then
        local config_name=$(basename "${configs[$((selection-1))]}" .conf)
        systemctl "$action" "easytier@${config_name}"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN_COLOR}操作成功${RES}"
        else
            echo -e "${RED_COLOR}操作失败${RES}"
        fi
    else
        echo -e "${RED_COLOR}无效选择${RES}"
    fi
    
    echo -e "\n按回车键继续..."
    read
}

# 添加控制所有服务函数
control_all_services() {
    local action=$1
    
    echo -e "\n${BLUE_COLOR}正在${action}所有服务...${RES}"
    systemctl "$action" 'easytier@*'
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN_COLOR}操作成功${RES}"
    else
        echo -e "${RED_COLOR}操作失败${RES}"
    fi
    
    echo -e "\n按回车键继续..."
    read
}

# 定义消息函数
define_messages() {
    if $IS_CN; then
        # 主菜单
        MSG_WELCOME="欢迎使用 EasyTier 安装控制脚本"
        MSG_VERSION_INFO="版本信息"
        MSG_LATEST_VERSION="官方最新版本"
        MSG_LOCAL_VERSION="本地安装版本"
        MSG_SYSTEM_INFO="系统信息"
        MSG_MAIN_MENU="主菜单选项"
        MSG_INSTALL="安装 EasyTier"
        MSG_UPDATE="更新 EasyTier"
        MSG_UNINSTALL="卸载 EasyTier"
        MSG_CONFIG="配置 EasyTier"
        MSG_TOOLS="工具"
        MSG_EXIT="退出"
        
        # 工具菜单
        MSG_TOOLS_TITLE="EasyTier 工具"
        MSG_TOOLS_OPTIONS="工具选项"
        MSG_SYSTEM_OPTIMIZE="系统优化"
        MSG_DIAGNOSTIC="诊断工具"
        MSG_PERFORMANCE="性能监控"
        MSG_SECURITY="安全检查"
        MSG_LOGS="日志分析"
        MSG_QUICK_FIX="一键修复"
        MSG_NETWORK_DIAG="网络诊断"
        MSG_BACK_MAIN="返回主菜单"
        
        # 优化菜单
        MSG_OPTIMIZE_TITLE="系统优化工具"
        MSG_OPTIMIZE_OPTIONS="优化选项"
        MSG_AUTO_OPTIMIZE="自动优化系统"
        MSG_NETWORK_OPTIMIZE="优化网络参数"
        MSG_SERVICE_OPTIMIZE="优化服务配置"
        MSG_CACHE_CLEAN="清理系统缓存"
        MSG_BACK_UPPER="返回上级菜单"
        
        # 诊断菜单
        MSG_DIAG_TITLE="系统诊断工具"
        MSG_DIAG_OPTIONS="诊断选项"
        MSG_SYSTEM_DIAG="系统诊断"
        MSG_SERVICE_DIAG="服务诊断"
        MSG_CONFIG_DIAG="配置诊断"
        MSG_DEPS_CHECK="依赖检查"
        
        # 监控菜单
        MSG_MONITOR_TITLE="性能监控工具"
        MSG_MONITOR_OPTIONS="监控选项"
        MSG_REAL_TIME="实时性能监控"
        MSG_RESOURCE_USAGE="资源使用统计"
        MSG_NETWORK_MONITOR="网络流量监控"
        MSG_CONN_STATUS="连接状态监控"
        
        # 安全菜单
        MSG_SECURITY_TITLE="安全检查工具"
        MSG_SECURITY_OPTIONS="安全选项"
        MSG_FILE_PERM="文件权限检查"
        MSG_NETWORK_SECURITY="网络安全检查"
        MSG_SYSTEM_SECURITY="系统安全检查"
        MSG_SECURITY_REPORT="生成安全报告"
        
        # 控制菜单
        MSG_CONTROL="控制 EasyTier"
        MSG_CONTROL_TITLE="EasyTier 控制面板"
        MSG_CONTROL_OPTIONS="控制选项"
        MSG_START_SERVICE="启动服务"
        MSG_STOP_SERVICE="停止服务"
        MSG_RESTART_SERVICE="重启服务"
        MSG_START_ALL="启动所有服务"
        MSG_STOP_ALL="停止所有服务"
        MSG_RESTART_ALL="重启所有服务"
    else
        # Main Menu
        MSG_WELCOME="Welcome to EasyTier Installation Script"
        MSG_VERSION="Version"
        MSG_VERSION_INFO="Version Information"
        MSG_LATEST_VERSION="Latest Version"
        MSG_LOCAL_VERSION="Local Version"
        MSG_SYSTEM_INFO="System Information"
        MSG_MAIN_MENU="Main Menu Options"
        MSG_INSTALL="Install EasyTier"
        MSG_UPDATE="Update EasyTier"
        MSG_UNINSTALL="Uninstall EasyTier"
        MSG_CONFIG="Configure EasyTier"
        MSG_TOOLS="Tools"
        MSG_EXIT="Exit"
        
        # Tools Menu
        MSG_TOOLS_TITLE="EasyTier Tools"
        MSG_TOOLS_OPTIONS="Tool Options"
        MSG_SYSTEM_OPTIMIZE="System Optimization"
        MSG_DIAGNOSTIC="Diagnostic Tools"
        MSG_PERFORMANCE="Performance Monitor"
        MSG_SECURITY="Security Check"
        MSG_LOGS="Log Analysis"
        MSG_QUICK_FIX="Quick Fix"
        MSG_NETWORK_DIAG="Network Diagnostics"
        MSG_BACK_MAIN="Back to Main Menu"
        
        # Optimization Menu
        MSG_OPTIMIZE_TITLE="System Optimization Tools"
        MSG_OPTIMIZE_OPTIONS="Optimization Options"
        MSG_AUTO_OPTIMIZE="Auto Optimize System"
        MSG_NETWORK_OPTIMIZE="Optimize Network Parameters"
        MSG_SERVICE_OPTIMIZE="Optimize Service Configuration"
        MSG_CACHE_CLEAN="Clean System Cache"
        MSG_BACK_UPPER="Back to Upper Menu"
        
        # Diagnostic Menu
        MSG_DIAG_TITLE="System Diagnostic Tools"
        MSG_DIAG_OPTIONS="Diagnostic Options"
        MSG_SYSTEM_DIAG="System Diagnostics"
        MSG_SERVICE_DIAG="Service Diagnostics"
        MSG_CONFIG_DIAG="Configuration Diagnostics"
        MSG_DEPS_CHECK="Dependency Check"
        
        # Monitor Menu
        MSG_MONITOR_TITLE="Performance Monitoring Tools"
        MSG_MONITOR_OPTIONS="Monitoring Options"
        MSG_REAL_TIME="Real-time Performance Monitor"
        MSG_RESOURCE_USAGE="Resource Usage Statistics"
        MSG_NETWORK_MONITOR="Network Traffic Monitor"
        MSG_CONN_STATUS="Connection Status Monitor"
        
        # Security Menu
        MSG_SECURITY_TITLE="Security Check Tools"
        MSG_SECURITY_OPTIONS="Security Options"
        MSG_FILE_PERM="File Permission Check"
        MSG_NETWORK_SECURITY="Network Security Check"
        MSG_SYSTEM_SECURITY="System Security Check"
        MSG_SECURITY_REPORT="Generate Security Report"
        
        # Control Menu
        MSG_CONTROL="Control EasyTier"
        MSG_CONTROL_TITLE="EasyTier Control Panel"
        MSG_CONTROL_OPTIONS="Control Options"
        MSG_START_SERVICE="Start Service"
        MSG_STOP_SERVICE="Stop Service"
        MSG_RESTART_SERVICE="Restart Service"
        MSG_START_ALL="Start All Services"
        MSG_STOP_ALL="Stop All Services"
        MSG_RESTART_ALL="Restart All Services"
        
        # Common Messages
        MSG_INVALID_OPTION="Invalid option"
        MSG_PRESS_ENTER="Press Enter to continue..."
        MSG_OPERATION_CANCELLED="Operation cancelled"
        MSG_OPERATION_COMPLETED="Operation completed"
        MSG_CONFIRM_ACTION="Are you sure? [y/N]"
    fi
}

# 主执行流程
main() {
    # 查权限
    check_permissions
    if [ $? -ne 0 ]; then
        exit 1
    fi
    
    # 系统检测
    echo -e "\n${BLUE_COLOR}正在检测系统环境...${RES}"
    check_system
    if [ $? -ne 0 ]; then
        exit 1
    fi
    
    echo -e "\n${GREEN_COLOR}系统检测结果：${RES}"
    echo "操作系统: $OS_NAME $OS_VERSION"
    echo "系统架构: $PLATFORM ($ARCH)"
    echo "内核版本: $(uname -r)"
    echo "CPU架构: $(uname -m)"
    sleep 2
    
    # 检查语言
    if [ -z "$FORCE_LANG" ]; then
        clear
        echo -e "${GREEN_COLOR}=====================================${RES}"
        if $IS_CN; then
            echo -e "${GREEN_COLOR}      EasyTier 安装控制脚本${RES}"
            echo -e "${GREEN_COLOR}      版本: ${SCRIPT_VERSION}${RES}"
        else
            echo -e "${GREEN_COLOR}      EasyTier Installation Script${RES}"
            echo -e "${GREEN_COLOR}      Version: ${SCRIPT_VERSION}${RES}"
        fi
        echo -e "${GREEN_COLOR}=====================================${RES}"
        echo -e "\n${BLUE_COLOR}请选择语言 / Please select language:${RES}"
        echo "1. 中文 / Chinese"
        echo "2. English"
        echo -n "Enter your choice [1/2] [default=2]: "
        read lang_choice

        case "$lang_choice" in
            1|"中文") 
                IS_CN=true 
                define_messages
                show_main_menu
                ;;
            2|"English"|"") 
                IS_CN=false 
                define_messages
                show_main_menu
                ;;
            *) 
                echo "Invalid choice / 无效选项"
                sleep 2
                exec "$0"
                ;;
        esac
    fi
}

# 设置初始变量
if [[ "$#" -ge 1 && ! "$1" == --* ]]; then
    INSTALL_PATH=$1
    shift
fi

# 检查其他参数
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --skip-folder-verify) SKIP_FOLDER_VERIFY=true ;;
        --skip-folder-fix) SKIP_FOLDER_FIX=true ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
    shift
done

if [ -z "$INSTALL_PATH" ]; then
    INSTALL_PATH='/opt/easytier'
fi

if [[ "$INSTALL_PATH" == */ ]]; then
    INSTALL_PATH=${INSTALL_PATH%?}
fi

if ! $SKIP_FOLDER_FIX && ! [[ "$INSTALL_PATH" == */easytier ]]; then
    INSTALL_PATH="$INSTALL_PATH/easytier"
fi

# 导出变量供其他脚本使用
export RED_COLOR GREEN_COLOR YELLOW_COLOR BLUE_COLOR PINK_COLOR SHAN RES
export SKIP_FOLDER_VERIFY SKIP_FOLDER_FIX FORCE_LANG INSTALL_PATH IS_CN

# 启动主程序
main
