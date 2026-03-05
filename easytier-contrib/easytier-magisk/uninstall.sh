MODDIR=${0%/*}
pkill -f "${MODDIR}/easytier-core" # 结束 easytier-core 进程
rm -rf $MODDIR/*