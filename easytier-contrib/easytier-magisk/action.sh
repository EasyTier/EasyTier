#!/data/adb/magisk/busybox sh
MODDIR=${0%/*}
MODULE_PROP="${MODDIR}/module.prop"
IP_RULE_SCRIPT="${MODDIR}/hotspot_iprule.sh"

ET_STATUS=""
REDIR_STATUS=""
IS_RUNNING=false

# 确保辅助脚本有执行权限
chmod +x "${IP_RULE_SCRIPT}" 2>/dev/null

# 更新 module.prop 文件中的 description
update_module_description() {
    local status_message=$1
    # 检查 module.prop 文件存在且 description 发生变化了再写入
    if [ -f "${MODULE_PROP}" ]; then
        local current_desc=$(grep "^description=" "${MODULE_PROP}")
        local new_desc="description=[状态] ${status_message}"
        if [ "${current_desc}" != "${new_desc}" ]; then
            sed -i "s#^description=.*#${new_desc}#" "${MODULE_PROP}"
        fi
    fi
}

# 判断程序启动状态
if [ -f "${MODDIR}/disable" ]; then
    IS_RUNNING=false
    ET_STATUS="主程序已关闭"

elif pgrep -f "${MODDIR}/easytier-core" >/dev/null; then
    IS_RUNNING=true
    if [ -f "${MODDIR}/config/command_args" ]; then
        ET_STATUS="主程序正在运行（启动参数模式）"
    else
        ET_STATUS="主程序正在运行（配置文件模式）"
    fi
    
elif [ -z "$ET_STATUS" ]; then
    # 既没 disable 也没运行，说明是异常停止或未启动
    ET_STATUS="主程序启动失败或未运行"
fi

# 无论主程序是否运行，都允许切换“开关文件”的状态，以便下次生效
if [ -f "${MODDIR}/enable_IP_rule" ]; then
    rm -f "${MODDIR}/enable_IP_rule"
    
    "${IP_RULE_SCRIPT}" del >/dev/null 2>&1
    
    REDIR_STATUS="转发已禁用"
    echo "热点子网转发已禁用"
    echo "[ET-NAT] Action: IP rule disabled." >> "${MODDIR}/log.log"
else
    touch "${MODDIR}/enable_IP_rule"

    if [ "$IS_RUNNING" = true ]; then
        "${IP_RULE_SCRIPT}" del >/dev/null 2>&1
        "${IP_RULE_SCRIPT}" add_once
        echo "转发规则将立即生效，无需重启"
    else
        echo "主程序未运行，转发规则将在下次启动时生效"
    fi
    
    REDIR_STATUS="转发已激活"
    echo "----------------------------------"
    echo "热点子网转发已激活"
    echo "热点开启后将自动将热点加入转发网络"
    echo "需要在配置中提前配置好 cidr 参数"
    echo "----------------------------------"
    echo "[ET-NAT] Action: IP rule enabled." >> "${MODDIR}/log.log"
fi

sync
update_module_description "${ET_STATUS}| ${REDIR_STATUS}"