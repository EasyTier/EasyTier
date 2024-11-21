#!/bin/bash

# 备份配置
backup_configuration() {
    local config_dir="$INSTALL_PATH/config"
    local backup_dir="$HOME/.easytier_backup"
    
    # 检查是否有配置文件
    if [ ! -d "$config_dir" ] || [ -z "$(ls -A $config_dir)" ]; then
        echo -e "${RED_COLOR}错误：没有找到配置文件${RES}"
        echo -e "\n按回车键继续..."
        read
        return 1
    fi
    
    # 显示备份选项
    echo -e "\n${BLUE_COLOR}请选择备份方式：${RES}"
    echo "1. 备份所有配置"
    echo "2. 备份单个配置"
    echo "0. 返回上级菜单"
    
    echo -n "请选择 [0-2]: "
    read choice
    
    case "$choice" in
        1) backup_all_configs ;;
        2) backup_single_config ;;
        0) return 0 ;;
        *)
            echo -e "${RED_COLOR}无效选项${RES}"
            sleep 1
            return 1
            ;;
    esac
}

# 备份所有配置
backup_all_configs() {
    local config_dir="$INSTALL_PATH/config"
    local backup_dir="$HOME/.easytier_backup"
    local backup_name="easytier_backup_all_$(date +%Y%m%d_%H%M%S)"
    
    # 创建备份目录
    mkdir -p "$backup_dir/$backup_name"
    
    # 复制所有配置文件
    cp -r "$config_dir/"* "$backup_dir/$backup_name/"
    
    # 创建服务文件备份
    mkdir -p "$backup_dir/$backup_name/services"
    for conf in "$config_dir"/*.conf; do
        if [ -f "$conf" ]; then
            local service_name=$(basename "$conf" .conf)
            if [ -f "/etc/systemd/system/easytier@${service_name}.service" ]; then
                cp "/etc/systemd/system/easytier@${service_name}.service" "$backup_dir/$backup_name/services/"
            fi
        fi
    done
    
    # 创建备份压缩包
    cd "$backup_dir"
    tar czf "${backup_name}.tar.gz" "$backup_name"
    rm -rf "$backup_name"
    
    echo -e "${GREEN_COLOR}所有配置已备份到：${RES}"
    echo "$backup_dir/${backup_name}.tar.gz"
    
    echo -e "\n按回车键继续..."
    read
}

# 备份单个配置
backup_single_config() {
    local config_dir="$INSTALL_PATH/config"
    local backup_dir="$HOME/.easytier_backup"
    
    # 显示现有配置列表
    echo -e "\n${BLUE_COLOR}现有配置：${RES}"
    local configs=()
    local i=1
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
        echo "暂无配置文件"
        echo -e "\n按回车键继续..."
        read
        return 1
    fi
    
    echo -n "请选择要备份的配置 [1-$((i-1))]: "
    read selection
    
    if [ "$selection" -ge 1 ] && [ "$selection" -le $((i-1)) ]; then
        local config_name=$(basename "${configs[$((selection-1))]}" .conf)
        local backup_name="easytier_backup_${config_name}_$(date +%Y%m%d_%H%M%S)"
        
        # 创建备份目录
        mkdir -p "$backup_dir/$backup_name"
        
        # 复制选择的配置文件
        cp "$config_dir/${config_name}.conf" "$backup_dir/$backup_name/"
        
        # 备份对应的服务文件
        mkdir -p "$backup_dir/$backup_name/services"
        if [ -f "/etc/systemd/system/easytier@${config_name}.service" ]; then
            cp "/etc/systemd/system/easytier@${config_name}.service" "$backup_dir/$backup_name/services/"
        fi
        
        # 创建备份压缩包
        cd "$backup_dir"
        tar czf "${backup_name}.tar.gz" "$backup_name"
        rm -rf "$backup_name"
        
        echo -e "${GREEN_COLOR}配置已备份到：${RES}"
        echo "$backup_dir/${backup_name}.tar.gz"
    else
        echo -e "${RED_COLOR}无效选择${RES}"
    fi
    
    echo -e "\n按回车键继续..."
    read
}

# 恢复配置
restore_configuration() {
    local backup_dir="$HOME/.easytier_backup"
    local config_dir="$INSTALL_PATH/config"
    
    # 检查备份目录
    if [ ! -d "$backup_dir" ]; then
        echo -e "${RED_COLOR}错误：未找到备份目录${RES}"
        echo -e "\n按回车键继续..."
        read
        return 1
    fi
    
    # 列出可用备份
    echo -e "\n${BLUE_COLOR}可用备份：${RES}"
    local all_backups=()
    local single_backups=()
    local i=1
    local j=1
    
    echo "全部配置备份："
    while IFS= read -r file; do
        if [[ $file == *backup_all_*.tar.gz ]]; then
            all_backups+=("$file")
            echo "$i. $(basename "$file" .tar.gz)"
            ((i++))
        fi
    done < <(ls -1 "$backup_dir"/*.tar.gz 2>/dev/null)
    
    echo -e "\n单个配置备份："
    while IFS= read -r file; do
        if [[ $file == *backup_easytier_*.tar.gz ]]; then
            single_backups+=("$file")
            echo "$j. $(basename "$file" .tar.gz)"
            ((j++))
        fi
    done < <(ls -1 "$backup_dir"/*.tar.gz 2>/dev/null)
    
    if [ ${#all_backups[@]} -eq 0 ] && [ ${#single_backups[@]} -eq 0 ]; then
        echo "没有找到备份文件"
        echo -e "\n按回车键继续..."
        read
        return 1
    fi
    
    echo -e "\n${BLUE_COLOR}选择恢复方式：${RES}"
    echo "1. 恢复全部配置"
    echo "2. 恢复单个配置"
    echo "0. 返回上级菜单"
    
    echo -n "请选择 [0-2]: "
    read choice
    
    case "$choice" in
        1) restore_all_configs "${all_backups[@]}" ;;
        2) restore_single_config "${single_backups[@]}" ;;
        0) return 0 ;;
        *)
            echo -e "${RED_COLOR}无效选项${RES}"
            sleep 1
            return 1
            ;;
    esac
}

# 恢复所有配置
restore_all_configs() {
    local -a backups=("$@")
    local backup_dir="$HOME/.easytier_backup"
    local config_dir="$INSTALL_PATH/config"
    
    if [ ${#backups[@]} -eq 0 ]; then
        echo -e "${RED_COLOR}没有找到全部配置的备份${RES}"
        return 1
    fi
    
    echo -e "\n${BLUE_COLOR}可用的全部配置备份：${RES}"
    local i=1
    for backup in "${backups[@]}"; do
        echo "$i. $(basename "$backup" .tar.gz)"
        ((i++))
    done
    
    echo -n "请选择要恢复的备份 [1-$((i-1))]: "
    read selection
    
    if [ "$selection" -ge 1 ] && [ "$selection" -le $((i-1)) ]; then
        perform_restore_all "${backups[$((selection-1))]}"
    else
        echo -e "${RED_COLOR}无效选择${RES}"
    fi
}

# 执行全部配置恢复
perform_restore_all() {
    local backup_file="$1"
    local backup_dir="$HOME/.easytier_backup"
    local config_dir="$INSTALL_PATH/config"
    
    echo -e "\n${YELLOW_COLOR}警告：恢复操作将覆盖所有现有配置${RES}"
    echo -n "确认恢复？[y/N]: "
    read confirm
    
    case "$confirm" in
        [Yy]*)
            # 停止所有服务
            echo -e "\n${BLUE_COLOR}正在停止所有服务...${RES}"
            systemctl stop 'easytier@*'
            
            # 创建临时目录
            local temp_dir=$(mktemp -d)
            
            # 解压备份文件
            tar xzf "$backup_dir/$backup_file" -C "$temp_dir"
            
            # 恢复配置文件
            rm -rf "$config_dir"
            mkdir -p "$config_dir"
            cp -r "$temp_dir/"*/* "$config_dir/"
            
            # 恢复服务文件
            if [ -d "$temp_dir/*/services" ]; then
                cp -r "$temp_dir/*/services/"* /etc/systemd/system/
            fi
            
            # 清理临时文件
            rm -rf "$temp_dir"
            
            # 重载 systemd
            systemctl daemon-reload
            
            # 重启服务
            echo -e "\n${BLUE_COLOR}正在启动服务...${RES}"
            for conf in "$config_dir"/*.conf; do
                if [ -f "$conf" ]; then
                    local service_name=$(basename "$conf" .conf)
                    systemctl enable "easytier@${service_name}" >/dev/null 2>&1
                    if systemctl start "easytier@${service_name}"; then
                        echo -e "${GREEN_COLOR}服务 ${service_name} 已启动${RES}"
                    else
                        echo -e "${RED_COLOR}警告: 服务 ${service_name} 启动失败${RES}"
                    fi
                fi
            done
            
            echo -e "\n${GREEN_COLOR}所有配置已恢复${RES}"
            ;;
        *)
            echo "恢复操作已取消"
            ;;
    esac
    
    echo -e "\n按回车键继续..."
    read
}

# 恢复单个配置
restore_single_config() {
    local -a backups=("$@")
    local backup_dir="$HOME/.easytier_backup"
    local config_dir="$INSTALL_PATH/config"
    
    if [ ${#backups[@]} -eq 0 ]; then
        echo -e "${RED_COLOR}没有找到单个配置的备份${RES}"
        return 1
    fi
    
    echo -e "\n${BLUE_COLOR}可用的单个配置备份：${RES}"
    local i=1
    for backup in "${backups[@]}"; do
        echo "$i. $(basename "$backup" .tar.gz)"
        ((i++))
    done
    
    echo -n "请选择要恢复的备份 [1-$((i-1))]: "
    read selection
    
    if [ "$selection" -ge 1 ] && [ "$selection" -le $((i-1)) ]; then
        perform_restore_single "${backups[$((selection-1))]}"
    else
        echo -e "${RED_COLOR}无效选择${RES}"
    fi
}

# 执行单个配置恢复
perform_restore_single() {
    local backup_file="$1"
    local backup_dir="$HOME/.easytier_backup"
    local config_dir="$INSTALL_PATH/config"
    
    # 提取配置名称
    local config_name=$(echo "$backup_file" | grep -o "easytier_[^_]*")
    
    echo -e "\n${YELLOW_COLOR}警告：如果存在同名配置，将被覆盖${RES}"
    echo -n "确认恢复？[y/N]: "
    read confirm
    
    case "$confirm" in
        [Yy]*)
            # 停止相关服务
            if systemctl is-active --quiet "easytier@${config_name}"; then
                echo -e "\n${BLUE_COLOR}正在停止服务...${RES}"
                systemctl stop "easytier@${config_name}"
            fi
            
            # 创建临时目录
            local temp_dir=$(mktemp -d)
            
            # 解压备份文件
            tar xzf "$backup_dir/$backup_file" -C "$temp_dir"
            
            # 恢复配置文件
            mkdir -p "$config_dir"
            cp -f "$temp_dir/"*/*.conf "$config_dir/"
            
            # 恢复服务文件
            if [ -d "$temp_dir/*/services" ]; then
                cp -f "$temp_dir/*/services/"* /etc/systemd/system/
            fi
            
            # 清理临时文件
            rm -rf "$temp_dir"
            
            # 重载 systemd
            systemctl daemon-reload
            
            # 启动服务
            echo -e "\n${BLUE_COLOR}正在启动服务...${RES}"
            systemctl enable "easytier@${config_name}" >/dev/null 2>&1
            if systemctl start "easytier@${config_name}"; then
                echo -e "${GREEN_COLOR}服务已启动${RES}"
            else
                echo -e "${RED_COLOR}警告: 服务启动失败${RES}"
            fi
            
            echo -e "\n${GREEN_COLOR}配置已恢复${RES}"
            ;;
        *)
            echo "恢复操作已取消"
            ;;
    esac
    
    echo -e "\n按回车键继续..."
    read
}

# 添加自动备份函数
auto_backup() {
    local backup_dir="$HOME/.easytier_backup"
    local max_backups=5
    
    # 创建定时任务
    cat > /etc/cron.daily/easytier-backup << EOF
#!/bin/bash
# 自动备份 EasyTier 配置
$(declare -f backup_all_configs)
backup_all_configs

# 清理旧备份
cd "$backup_dir"
ls -t *.tar.gz | tail -n +$((max_backups+1)) | xargs rm -f
EOF
    
    chmod +x /etc/cron.daily/easytier-backup
}
