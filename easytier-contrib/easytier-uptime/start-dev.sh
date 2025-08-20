#!/bin/bash

# EasyTier Uptime Monitor 开发环境启动脚本

set -e

echo "🚀 Starting EasyTier Uptime Monitor Development Environment..."

# 检查依赖
echo "📦 Checking dependencies..."

# 检查 Rust
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust is not installed. Please install Rust first."
    exit 1
fi

# 检查 Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js first."
    exit 1
fi

# 检查 npm
if ! command -v npm &> /dev/null; then
    echo "❌ npm is not installed. Please install npm first."
    exit 1
fi

# 设置环境变量
export RUST_LOG=debug
export NODE_ENV=development

# 创建必要的目录
echo "📁 Creating directories..."
mkdir -p logs
mkdir -p configs
mkdir -p frontend/dist

# 复制环境配置文件
if [ ! -f .env ]; then
    echo "📝 Creating environment configuration..."
    cp .env.development .env
fi

# 安装前端依赖
echo "📦 Installing frontend dependencies..."
cd frontend
if [ ! -d "node_modules" ]; then
    npm install
fi
cd ..

# 启动后端服务
echo "🔧 Starting backend server..."
cargo run &
BACKEND_PID=$!

# 等待后端服务启动
echo "⏳ Waiting for backend server to start..."
sleep 5

# 启动前端开发服务器
echo "🎨 Starting frontend development server..."
cd frontend
npm run dev &
FRONTEND_PID=$!
cd ..

# 等待前端服务启动
echo "⏳ Waiting for frontend server to start..."
sleep 3

echo "✅ Development environment started successfully!"
echo "🌐 Frontend: http://localhost:3000"
echo "🔧 Backend API: http://localhost:8080"
echo "📊 API Health Check: http://localhost:8080/health"
echo ""
echo "Press Ctrl+C to stop all services"

# 清理函数
cleanup() {
    echo ""
    echo "🛑 Stopping services..."
    kill $BACKEND_PID 2>/dev/null || true
    kill $FRONTEND_PID 2>/dev/null || true
    echo "✅ All services stopped"
    exit 0
}

# 设置信号处理
trap cleanup SIGINT SIGTERM

# 等待用户中断
wait