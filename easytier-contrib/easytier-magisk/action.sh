#!/data/adb/magisk/busybox sh
MODDIR=${0%/*}
MODULE_PROP="${MODDIR}/module.prop"

ET_STATUS=""
REDIR_STATUS=""
# 更新module.prop文件中的description
update_module_description() {
    local status_message=$1
    sed -i "/^description=/c\description=[状态]${status_message}" ${MODULE_PROP}
}


if [ -f "${MODDIR}/disable" ]; then
    ET_STATUS="已关闭"
elif pgrep -f 'easytier-core' >/dev/null; then
    if [ -f "${MODDIR}/config/command_args"]; then
        ET_STATUS="主程序已开启(启动参数模式)"
    else
        ET_STATUS="主程序已开启(配置文件模式)"
    fi
fi

#ET_STATUS不存在说明开启模块未正常运行，不修改状态
if [ -n "$ET_STATUS" ]; then
    if [ -f "${MODDIR}/enable_IP_rule" ]; then
        rm -f "${MODDIR}/enable_IP_rule"
        ${MODDIR}/hotspot_iprule.sh del
        REDIR_STATUS="转发已禁用"
        echo "局域网转发已禁用"
        echo "[ET-NAT] IP rule disabled." >> "${MODDIR}/log.log"
    else
        touch "${MODDIR}/enable_IP_rule"
        ${MODDIR}/hotspot_iprule.sh del
        ${MODDIR}/hotspot_iprule.sh add_once
        REDIR_STATUS="转发已激活"
        echo "局域网转发已激活,热点开启后将自动将热点加入转发网络（要求已配置本地网络cidr=参数）。转发规则将随着热点开关而自动开关。该状态将保持到转发被禁用为止。"
        echo "[ET-NAT] IP rule enabled." >> "${MODDIR}/log.log"
    fi
    update_module_description "${ET_STATUS} | ${REDIR_STATUS}"
else
    ui_print "主程序未正常启动，请先检查配置文件"
fi
