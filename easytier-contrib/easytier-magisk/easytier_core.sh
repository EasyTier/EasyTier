#!/system/bin/sh

MODDIR=${0%/*}
CONFIG_FILE="${MODDIR}/config/config.toml"
LOG_FILE="${MODDIR}/log.log"
MODULE_PROP="${MODDIR}/module.prop"
EASYTIER="${MODDIR}/easytier-core"
REDIR_STATUS=""
LAST_RULE_ADD_ERR=""

has_high_priority_main_rule() {
    # `ip rule show` 的常见输出示例：
    #   9999: from all lookup main
    # 第 1 列是优先级，`$1 + 0` 会把 `9999:` 自动转成数字 `9999`。
    # 只要存在任意一条优先级 < 10000 的 main 规则，就认为条件满足并返回成功(0)。
    ip rule show | awk '
        /from all/ && /lookup main/ {
            if ($1 + 0 < 10000) {
                found = 1
                exit
            }
        }
        END { exit(found ? 0 : 1) }
    '
}

ensure_main_lookup_rule() {
    # 目的：在 Android 策略路由场景下，确保至少有一条高优先级 main 表规则。
    # 若已存在满足条件的规则，直接返回，避免重复添加。
    has_high_priority_main_rule && return 0

    # 添加固定优先级规则；捕获 stderr 以便定位失败原因。
    local err
    err=$(ip rule add pref 9999 from all lookup main 2>&1) && {
        LAST_RULE_ADD_ERR=""
        return 0
    }

    # 竞态场景：本次检查与添加之间，规则可能已被其他路径补上。
    # 这种情况下 `File exists` 视为成功，不需要记录错误。
    case "${err}" in
        *"File exists"*)
            LAST_RULE_ADD_ERR=""
            return 0
            ;;
    esac

    # 守护循环每 3 秒执行一次：相同错误只记录一次，防止日志刷屏。
    [ "${err}" = "${LAST_RULE_ADD_ERR}" ] && return 1
    echo "$(date '+%Y-%m-%d %H:%M:%S') ip rule add failed: ${err}" >> "${LOG_FILE}"
    LAST_RULE_ADD_ERR="${err}"
    return 1
}

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
            if ! pgrep -f 'easytier-core' >/dev/null; then
                update_module_description "主程序启动失败，请检查配置文件"
            fi
        else
            echo "开关控制$(date "+%Y-%m-%d %H:%M:%S") 进程已存在"
        fi
        if pgrep -f 'easytier-core' >/dev/null; then
            ensure_main_lookup_rule
        fi
    fi
    
    sleep 3s # 暂停3秒后再次执行循环
done
