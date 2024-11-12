#!/bin/bash

# 安装流程函数
install_easytier() {
    clear
    echo -e "${GREEN_COLOR}=================================${RES}"
    echo -e "${GREEN_COLOR}      EasyTier 安装向导${RES}"
    echo -e "${GREEN_COLOR}=================================${RES}"
    
    # 获取版本信息
    local latest_version=$(get_download_info | cut -d':' -f1)
    local local_version=$(get_local_version)
    
    echo -e "\n${BLUE_COLOR}版本信息：${RES}"
    echo "官方最新版本: ${latest_version:-获取失败}"
    echo "本地安装版本: $local_version"
    
    # 1. 检查权限
    check_permissions
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # 2. 系统检测
    echo -e "\n${BLUE_COLOR}正在检查系统环境...${RES}"
    check_system
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # 3. 检查依赖
    echo -e "\n${BLUE_COLOR}正在检查依赖...${RES}"
    check_dependencies
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # 4. 安装确认
    echo -e "\n${YELLOW_COLOR}安装信息：${RES}"
    echo "安装路径: $INSTALL_PATH"
    echo "系统架构: $ARCH"
    echo -n "确认安装？[Y/n]: "
    read confirm
    case "$confirm" in
        [Nn]*)
            echo "安装已取消"
            return 1
            ;;
    esac
    
    # 5. 执行安装
    INSTALL
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # 6. 初始化
    echo -e "\n${BLUE_COLOR}正在初始化...${RES}"
    INIT
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    # 7. 安装成功
    SUCCESS
    return 0
}

# INSTALL 函数
INSTALL() {
    # 获取版本信息和包名
    local download_info=$(get_download_info)
    local version=$(echo "$download_info" | cut -d':' -f1)
    local package_name=$(echo "$download_info" | cut -d':' -f2)
    
    echo -e "\n${BLUE_COLOR}开始安装...${RES}"
    
    # 下载文件
    if ! download_file "$version" "$package_name" "/tmp/easytier_tmp_install.zip"; then
        echo -e "${RED_COLOR}下载失败${RES}"
        log_message "ERROR" "Download failed"
        return 1
    fi
    
    echo -e "\r\n${GREEN_COLOR}正在解压资源...${RES}"
    
    # 创建临时目录
    local temp_dir=$(mktemp -d)
    
    # 解压文件到临时目录
    if ! unzip -o /tmp/easytier_tmp_install.zip -d "$temp_dir/"; then
        echo -e "${RED_COLOR}解压文件失败${RES}"
        log_message "ERROR" "Failed to extract files"
        rm -rf "$temp_dir"
        return 1
    fi

    # 创建安装目录
    mkdir -p "$INSTALL_PATH"
    mkdir -p "$INSTALL_PATH/config"

    # 复制文件到安装目录
    cp -f "$temp_dir"/*/easytier-* "$INSTALL_PATH/"
    
    # 设置执行权限
    chmod +x "$INSTALL_PATH/easytier-core" "$INSTALL_PATH/easytier-cli"
    
    # 清理临时文件
    rm -rf "$temp_dir"
    rm -f /tmp/easytier_tmp_install.zip

    # 验证安装
    if [ -f "$INSTALL_PATH/easytier-core" ] && [ -f "$INSTALL_PATH/easytier-cli" ]; then
        echo -e "${GREEN_COLOR}安装成功${RES}"
        log_message "INFO" "Installation completed successfully"
        return 0
    else
        echo -e "${RED_COLOR}安装失败${RES}"
        log_message "ERROR" "Installation failed"
        return 1
    fi
}

# INIT 函数
INIT() {
    log_message "INFO" "Starting initialization"
    
    if [ ! -f "$INSTALL_PATH/easytier-core" ]; then
        echo -e "\r\n${RED_COLOR}错误: 找不到 EasyTier${RES}"
        log_message "ERROR" "EasyTier core not found"
        return 1
    fi

    # 清理旧文件
    rm -f /etc/systemd/system/easytier.service
    rm -f /usr/bin/easytier-core
    rm -f /usr/bin/easytier-cli

    # 创建软链接
    ln -sf "$INSTALL_PATH/easytier-core" /usr/sbin/easytier-core
    ln -sf "$INSTALL_PATH/easytier-cli" /usr/sbin/easytier-cli

    # 创建配置目录
    mkdir -p "$INSTALL_PATH/config"

    # 重载 systemd
    systemctl daemon-reload
    
    log_message "INFO" "Initialization completed"
    return 0
}

# SUCCESS 函数
SUCCESS() {
    log_message "INFO" "Installation successful"
    
    clear
    echo -e "${GREEN_COLOR}=================================${RES}"
    echo -e "${GREEN_COLOR}      EasyTier 安装成功！${RES}"
    echo -e "${GREEN_COLOR}=================================${RES}"

    echo -e "\n${BLUE_COLOR}后续步骤：${RES}"
    echo "1. 创建配置文件"
    echo "2. 返回主菜单"
    echo "0. 退出安装程序"

    echo -n -e "\n请选择 [0-2]: "
    read choice

    case "$choice" in
        1)
            create_configuration
            ;;
        2)
            return 0
            ;;
        0|"")
            echo -e "\n${GREEN_COLOR}感谢使用 EasyTier！${RES}"
            exit 0
            ;;
        *)
            echo -e "${RED_COLOR}无效选项${RES}"
            sleep 1
            SUCCESS
            ;;
    esac
}

# 更新函数
update_easytier() {
    clear
    echo -e "${GREEN_COLOR}=================================${RES}"
    echo -e "${GREEN_COLOR}      EasyTier 更新向导${RES}"
    echo -e "${GREEN_COLOR}=================================${RES}"
    
    # 获取版本信息
    local latest_version=$(get_download_info | cut -d':' -f1)
    local local_version=$(get_local_version)
    
    echo -e "\n${BLUE_COLOR}版本信息：${RES}"
    echo "当前版本: $local_version"
    echo "最新版本: $latest_version"
    
    if [ "$local_version" = "$latest_version" ]; then
        echo -e "\n${GREEN_COLOR}已经是最新版本${RES}"
        echo -e "\n按回车键继续..."
        read
        return 0
    fi
    
    echo -n -e "\n是否更新？[Y/n]: "
    read confirm
    case "$confirm" in
        [Nn]*)
            echo "更新已取消"
            return 1
            ;;
    esac
    
    # 执行更新
    INSTALL
    if [ $? -eq 0 ]; then
        INIT
        echo -e "\n${GREEN_COLOR}更新成功！${RES}"
    else
        echo -e "\n${RED_COLOR}更新失败${RES}"
    fi
    
    echo -e "\n按回车键继续..."
    read
}

# 卸载函数
uninstall_easytier() {
    clear
    echo -e "${GREEN_COLOR}=================================${RES}"
    echo -e "${GREEN_COLOR}      EasyTier 卸载向导${RES}"
    echo -e "${GREEN_COLOR}=================================${RES}"
    
    # 检查是否已安装
    if [ ! -f "$INSTALL_PATH/easytier-core" ] && [ ! -f "/usr/sbin/easytier-core" ]; then
        echo -e "\n${RED_COLOR}错误: EasyTier 未安装！${RES}"
        echo -e "\n按回车键继续..."
        read
        return 1
    fi

    # 显示卸载选项
    echo -e "\n${BLUE_COLOR}请选择卸载方式：${RES}"
    echo "1. 完全卸载（删除所有文件，包括配置）"
    echo "2. 仅卸载主程序（保留配置文件）"
    echo "0. 返回主菜单"
    
    echo -n "请选择 [0-2]: "
    read choice

    case "$choice" in
        1)
            perform_full_uninstall
            ;;
        2)
            perform_partial_uninstall
            ;;
        0)
            return 0
            ;;
        *)
            echo -e "${RED_COLOR}无效选项${RES}"
            sleep 1
            uninstall_easytier
            ;;
    esac
}

# 完全卸载
perform_full_uninstall() {
    echo -e "\n${YELLOW_COLOR}警告：这将删除所有 EasyTier 相关文件，包括：${RES}"
    echo "- 主程序文件"
    echo "- 所有配置文件"
    echo "- 服务文件"
    echo "- 系统链接"
    echo -n -e "\n${RED_COLOR}确认完全卸载？[y/N]: ${RES}"
    read confirm
    case "$confirm" in
        [Yy]*)
            # 停止所有服务
            echo -e "\n${BLUE_COLOR}正在停止所有服务...${RES}"
            systemctl stop 'easytier@*'
            systemctl disable 'easytier@*' >/dev/null 2>&1
            
            # 删除所有文件
            echo -e "${BLUE_COLOR}正在删除文件...${RES}"
            rm -rf "$INSTALL_PATH"
            rm -f /etc/systemd/system/easytier@*.service
            rm -f /usr/bin/easytier-core
            rm -f /usr/bin/easytier-cli
            rm -f /usr/sbin/easytier-core
            rm -f /usr/sbin/easytier-cli
            
            # 重载 systemd
            systemctl daemon-reload
            
            echo -e "\n${GREEN_COLOR}完全卸载成功！${RES}"
            ;;
        *)
            echo "卸载已取消"
            ;;
    esac
}

# 部分卸载
perform_partial_uninstall() {
    echo -e "\n${YELLOW_COLOR}将保留配置文件，仅卸载主程序${RES}"
    echo -n "确认卸载？[y/N]: "
    read confirm
    case "$confirm" in
        [Yy]*)
            # 停止所有服务
            echo -e "\n${BLUE_COLOR}正在停止所有服务...${RES}"
            systemctl stop 'easytier@*'
            
            # 备份配置
            if [ -d "$INSTALL_PATH/config" ]; then
                echo -e "${BLUE_COLOR}正在备份配置文件...${RES}"
                local backup_dir="/tmp/easytier_config_backup_$(date +%Y%m%d_%H%M%S)"
                cp -r "$INSTALL_PATH/config" "$backup_dir"
            fi
            
            # 删除主程序文件
            echo -e "${BLUE_COLOR}正在删除主程序...${RES}"
            rm -f "$INSTALL_PATH/easytier-core"
            rm -f "$INSTALL_PATH/easytier-cli"
            rm -f /usr/bin/easytier-core
            rm -f /usr/bin/easytier-cli
            rm -f /usr/sbin/easytier-core
            rm -f /usr/sbin/easytier-cli
            
            # 恢复配置
            if [ -d "$backup_dir" ]; then
                echo -e "${BLUE_COLOR}正在恢复配置文件...${RES}"
                mkdir -p "$INSTALL_PATH/config"
                cp -r "$backup_dir/"* "$INSTALL_PATH/config/"
                rm -rf "$backup_dir"
            fi
            
            echo -e "\n${GREEN_COLOR}主程序卸载成功！配置文件已保留在 $INSTALL_PATH/config${RES}"
            ;;
        *)
            echo "卸载已取消"
            ;;
    esac
}

# 改进安装检查函数
check_installation() {
    local required_files=(
        "$INSTALL_PATH/easytier-core"
        "$INSTALL_PATH/easytier-cli"
        "/usr/sbin/easytier-core"
        "/usr/sbin/easytier-cli"
    )
    
    local missing_files=()
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -ne 0 ]; then
        echo -e "${RED_COLOR}安装不完整，缺少以下文件：${RES}"
        printf '%s\n' "${missing_files[@]}"
        return 1
    fi
    
    return 0
}
