#!/system/bin/sh

MODDIR=${0%/*}
CONFIG_FILE="${MODDIR}/config/config.toml"
LOG_FILE="${MODDIR}/log.log"
MODULE_PROP="${MODDIR}/module.prop"
EASYTIER="${MODDIR}/easytier-core"

# 更新module.prop文件中的description
update_module_description() {
    local status_message=$1
    sed -i "/^description=/c\description=[状态]${status_message}" ${MODULE_PROP}
}

if [ ! -e /dev/net/tun ]; then
    if [ ! -d /dev/net ]; then
        mkdir -p /dev/net
    fi

    ln -s /dev/tun /dev/net/tun
fi

while true; do
    if ls $MODDIR | grep -q "disable"; then
        update_module_description "关闭中"
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

            TZ=Asia/Shanghai ${EASYTIER} -c ${CONFIG_FILE} > ${LOG_FILE} &
            sleep 5s # 等待easytier-core启动完成
            update_module_description "已开启(不一定运行成功)"
            ip rule add from all lookup main
        else
            echo "开关控制$(date "+%Y-%m-%d %H:%M:%S") 进程已存在"
        fi
    fi
    
    sleep 3s # 暂停3秒后再次执行循环
done
