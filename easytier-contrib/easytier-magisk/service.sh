#!/data/adb/magisk/busybox sh
MODDIR=${0%/*}
# MODDIR="$(dirname $(readlink -f "$0"))"
chmod 755 ${MODDIR}/*

# 等待系统启动成功
while [ "$(getprop sys.boot_completed)" != "1" ]; do
  sleep 5s
done

# 防止系统挂起
echo "PowerManagerService.noSuspend" > /sys/power/wake_lock

# 修改模块描述
sed -i 's/$(description=)$[^"]*/\1[状态]关闭中/' "$MODDIR/module.prop"

# 等待 3 秒
sleep 3s

"${MODDIR}/easytier_core.sh" &
"${MODDIR}/hotspot_iprule.sh" add &

# easytier_core.sh 和 hotspot_iprule.sh 都有内部循环做守护，
# 所以这里不需要再做守护了
