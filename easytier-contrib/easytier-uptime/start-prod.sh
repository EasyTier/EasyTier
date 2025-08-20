#!/bin/bash

# EasyTier Uptime Monitor 生产环境启动脚本

set -e

echo "🚀 Starting EasyTier Uptime Monitor Production Environment..."

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
export RUST_LOG=info
export NODE_ENV=production

# 创建必要的目录
echo "📁 Creating directories..."
mkdir -p logs
mkdir -p configs
mkdir -p /var/lib/easytier-uptime
mkdir -p frontend/dist

# 复制环境配置文件
if [ ! -f .env ]; then
    echo "📝 Creating environment configuration..."
    cp .env.production .env
fi

# 构建后端
echo "🔧 Building backend..."
cargo build --release

# 构建前端
echo "🎨 Building frontend..."
cd frontend
if [ ! -d "node_modules" ]; then
    npm install
fi
npm run build
cd ..

# 启动后端服务
echo "🔧 Starting backend server..."
nohup ./target/release/easytier-uptime > logs/backend.log 2>&1 &
BACKEND_PID=$!

# 等待后端服务启动
echo "⏳ Waiting for backend server to start..."
sleep 5

# 设置静态文件服务
echo "🌐 Setting up static file server..."
cd frontend/dist
python3 -m http.server 8081 > ../../logs/frontend.log 2>&1 &
FRONTEND_PID=$!
cd ../..

# 等待前端服务启动
echo "⏳ Waiting for frontend server to start..."
sleep 3

echo "✅ Production environment started successfully!"
echo "🌐 Frontend: http://localhost:8081"
echo "🔧 Backend API: http://localhost:8080"
echo "📊 API Health Check: http://localhost:8080/health"
echo ""
echo "Backend PID: $BACKEND_PID"
echo "Frontend PID: $FRONTEND_PID"
echo ""
echo "To stop services:"
echo "  kill $BACKEND_PID"
echo "  kill $FRONTEND_PID"
echo ""
echo "Or use the stop script: ./stop-prod.sh"

# 保存PID到文件
echo $BACKEND_PID > logs/backend.pid
echo $FRONTEND_PID > logs/frontend.pid

echo "✅ PIDs saved to logs/"