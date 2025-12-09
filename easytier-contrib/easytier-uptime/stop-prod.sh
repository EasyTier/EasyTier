#!/bin/bash

# EasyTier Uptime Monitor 停止服务脚本

set -e

echo "🛑 Stopping EasyTier Uptime Monitor services..."

# 检查PID文件
if [ -f "logs/backend.pid" ]; then
    BACKEND_PID=$(cat logs/backend.pid)
    echo "🔧 Stopping backend server (PID: $BACKEND_PID)..."
    kill $BACKEND_PID 2>/dev/null || true
    rm logs/backend.pid
    echo "✅ Backend server stopped"
else
    echo "⚠️  Backend PID file not found"
fi

if [ -f "logs/frontend.pid" ]; then
    FRONTEND_PID=$(cat logs/frontend.pid)
    echo "🌐 Stopping frontend server (PID: $FRONTEND_PID)..."
    kill $FRONTEND_PID 2>/dev/null || true
    rm logs/frontend.pid
    echo "✅ Frontend server stopped"
else
    echo "⚠️  Frontend PID file not found"
fi

# 强制杀死可能残留的进程
echo "🔍 Checking for remaining processes..."
REMAINING_BACKEND=$(ps aux | grep 'easytier-uptime' | grep -v grep | awk '{print $2}' || true)
if [ ! -z "$REMAINING_BACKEND" ]; then
    echo "🔧 Killing remaining backend processes..."
    echo $REMAINING_BACKEND | xargs kill -9 2>/dev/null || true
    echo "✅ Remaining backend processes killed"
fi

REMAINING_FRONTEND=$(ps aux | grep 'python3 -m http.server' | grep -v grep | awk '{print $2}' || true)
if [ ! -z "$REMAINING_FRONTEND" ]; then
    echo "🌐 Killing remaining frontend processes..."
    echo $REMAINING_FRONTEND | xargs kill -9 2>/dev/null || true
    echo "✅ Remaining frontend processes killed"
fi

echo "✅ All services stopped successfully!"