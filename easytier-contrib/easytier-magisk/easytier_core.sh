#!/system/bin/sh

MODDIR=${0%/*}
CONFIG_FILE="${MODDIR}/config/config.toml"
LOG_FILE="${MODDIR}/log.log"
MODULE_PROP="${MODDIR}/module.prop"
EASYTIER="${MODDIR}/easytier-core"
REDIR_STATUS=""

# 更新module.prop文件中的description
update_module_description() {
    local status_message=$1
    sed -i "/^description=/c\description=[状态]${status_message}" ${MODULE_PROP}
}

if [ -f "${MODDIR}/enable_IP_rule" ]; then
    REDIR_STATUS="转发已激活"
else
    REDIR_STATUS="转发已禁用"
fi

if [ ! -e /dev/net/tun ]; then
    if [ ! -d /dev/net ]; then
        mkdir -p /dev/net
    fi

    ln -s /dev/tun /dev/net/tun
fi

while true; do
    if ls $MODDIR | grep -q "disable"; then
        update_module_description "关闭中 | ${REDIR_STATUS}"
        if pgrep -f 'easytier-core' >/dev/null; then
            echo "开关控制$(date "+%Y-%m-%d %H:%M:%S") 进程已存在，正在关闭 ..."
            pkill easytier-core # 关闭进程
        fi
    else
        if ! pgrep -f 'easytier-core' >/dev/null; then
            if [ ! -f "$CONFIG_FILE" ]; then
                update_module_description "config.toml不存在"
                sleep 3s
                continue
            fi

            # 如果 config 目录下存在 command_args 文件，则读取其中的内容作为启动参数
            if [ -f "${MODDIR}/config/command_args" ]; then
                TZ=Asia/Shanghai ${EASYTIER} $(cat ${MODDIR}/config/command_args) --hostname "$(getprop ro.product.brand)-$(getprop ro.product.model)" > ${LOG_FILE} &
                sleep 5s # 等待easytier-core启动完成
                update_module_description "主程序已开启(启动参数模式) | ${REDIR_STATUS}"
            else
                TZ=Asia/Shanghai ${EASYTIER} -c ${CONFIG_FILE} --hostname "$(getprop ro.product.brand)-$(getprop ro.product.model)" > ${LOG_FILE} &
                sleep 5s # 等待easytier-core启动完成
                update_module_description "主程序已开启(配置文件模式) | ${REDIR_STATUS}"
            fi
            ip rule add from all lookup main
            if ! pgrep -f 'easytier-core' >/dev/null; then
                update_module_descriptio "主程序启动失败，请检查配置文件"
            fi
        else
            echo "开关控制$(date "+%Y-%m-%d %H:%M:%S") 进程已存在"
        fi
    fi
    
    sleep 3s # 暂停3秒后再次执行循环
done
