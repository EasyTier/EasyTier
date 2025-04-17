#!/data/adb/magisk/busybox sh
MODDIR=${0%/*}
# MODDIR="$(dirname $(readlink -f "$0"))"
if [ ! -f ${MODDIR}/log ]; do 
    mkdir -p ${MODDIR}/log
done
chmod 755 ${MODDIR}/*
echo $MODDIR
echo $MODDIR >> ${MODDIR}/log/start.log
echo "Easytier 服务启动"
echo "Easytier 服务启动" >> ${MODDIR}/log/start.log

# 启动
nohup ${MODDIR}/easytier-core -c ${MODDIR}/config/config.conf >> ${MODDIR}/log/start.log 2>&1 &

# 检查是否启用模块
while [ ! -f ${MODDIR}/disable ]; do 
    sleep 2
done
PID=$(ps -ef|grep "${MODDIR}/easytier-core -c ${MODDIR}/config/config.conf" | awk '{print $2}')
kill $PID
echo "Easytier 服务停止" >> ${MODDIR}/log/start.log
