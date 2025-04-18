#!/data/adb/magisk/busybox sh
MODDIR=${0%/*}
echo 'Easytier 服务停止中....'

PIDS=$(pgrep -f "^${MODDIR}/easytier-core -c ${MODDIR}/config/config.conf")

if [ -n "$PIDS" ]; then
    kill $PIDS  # 杀死所有匹配的进程
    echo "已停止所有 Easytier 进程 (PIDs: $PIDS)"
else
    echo "Easytier 服务未运行"
fi
echo '重启服务中...'
nohup sh ${MODDIR}/service.sh >> ${MODDIR}/log/start.log 2>&1 &
echo '服务已重启'
exit
