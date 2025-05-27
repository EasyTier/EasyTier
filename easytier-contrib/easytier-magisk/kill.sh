#!/data/adb/magisk/busybox sh
MODDIR=${0%/*}

# 查找 easytier-core 进程的 PID
PID=$(pgrep easytier-core)

# 检查是否找到了进程
if [ -z "$PID" ]; then
    echo "easytier-core 进程未找到"
else
    # 结束进程
    kill $PID
    echo "已结束 easytier-core 进程 (PID: $PID)"
fi
