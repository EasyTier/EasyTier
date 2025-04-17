#!/data/adb/magisk/busybox sh
MODDIR=${0%/*}
echo 'Easytier 服务停止中....'
PID=$(ps -ef|grep "${MODDIR}/easytier-core -c ${MODDIR}/config/config.conf" | awk '{print $2}')
kill $PID
echo 'Easytier 服务已停止'
echo '重启服务中...'
nohup sh ${MODDIR}/service.sh >> ${MODDIR}/log/start.log 2>&1 &
echo '服务已重启'
exit