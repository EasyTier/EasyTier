#!/bin/bash

# EasyTier Uptime Monitor 集成测试脚本

set -e

echo "🧪 Running EasyTier Uptime Monitor Integration Tests..."

# 检查依赖
echo "📦 Checking dependencies..."

# 检查 Rust
if ! command -v cargo &> /dev/null; then
    echo "❌ Rust is not installed. Please install Rust first."
    exit 1
fi

# 检查 curl
if ! command -v curl &> /dev/null; then
    echo "❌ curl is not installed. Please install curl first."
    exit 1
fi

# 设置环境变量
export RUST_LOG=info
export NODE_ENV=test

# 创建测试目录
echo "📁 Creating test directories..."
mkdir -p test-results
mkdir -p test-logs

# 复制测试环境配置
if [ ! -f .env ]; then
    echo "📝 Creating test environment configuration..."
    cp .env.development .env
fi

# 构建项目
echo "🔧 Building project..."
cargo build

# 启动后端服务进行测试
echo "🚀 Starting backend server for testing..."
cargo run &
BACKEND_PID=$!

# 等待后端服务启动
echo "⏳ Waiting for backend server to start..."
sleep 5

# 检查服务是否运行
echo "🔍 Checking if server is running..."
if curl -f http://localhost:8080/health > /dev/null 2>&1; then
    echo "✅ Backend server is running"
else
    echo "❌ Backend server failed to start"
    kill $BACKEND_PID 2>/dev/null || true
    exit 1
fi

# 运行API测试
echo "🧪 Running API tests..."
if cargo test api_test --lib -- --nocapture > test-results/api-test.log 2>&1; then
    echo "✅ API tests passed"
else
    echo "❌ API tests failed"
    echo "Check test-results/api-test.log for details"
fi

# 运行健康检查测试
echo "🏥 Running health check tests..."
curl -s http://localhost:8080/health | jq . > test-results/health-check.json
if [ $? -eq 0 ]; then
    echo "✅ Health check test passed"
else
    echo "❌ Health check test failed"
fi

# 运行节点管理测试
echo "🔧 Running node management tests..."
# 创建测试节点
curl -s -X POST http://localhost:8080/api/nodes \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Node",
    "host": "127.0.0.1",
    "port": 11010,
    "protocol": "tcp",
    "version": "1.0.0",
    "description": "Test node for integration testing",
    "max_connections": 100
  }' > test-results/create-node.json

# 获取节点列表
curl -s http://localhost:8080/api/nodes > test-results/get-nodes.json

echo "✅ Node management tests completed"

# 停止后端服务
echo "🛑 Stopping backend server..."
kill $BACKEND_PID 2>/dev/null || true
sleep 2

# 强制杀死可能残留的进程
pkill -f easytier-uptime 2>/dev/null || true

echo "✅ Integration tests completed!"
echo "📊 Test results saved to test-results/"
echo "📋 Test logs saved to test-logs/"

# 生成测试报告
echo "📝 Generating test report..."
cat > test-results/test-report.md << EOF
# EasyTier Uptime Monitor Integration Test Report

## Test Summary
- **Test Date**: $(date)
- **Test Environment**: Integration
- **Backend PID**: $BACKEND_PID

## Test Results

### API Tests
- Status: $(grep -q "test result: ok" test-results/api-test.log && echo "PASSED" || echo "FAILED")
- Log: [api-test.log](api-test.log)

### Health Check
- Status: $(jq -r '.success' test-results/health-check.json 2>/dev/null || echo "FAILED")
- Response: $(cat test-results/health-check.json 2>/dev/null || echo "No response")

### Node Management
- Status: COMPLETED
- Create Node: [create-node.json](create-node.json)
- Get Nodes: [get-nodes.json](get-nodes.json)

## System Information
- **Rust Version**: $(rustc --version)
- **Cargo Version**: $(cargo --version)
- **System**: $(uname -a)

EOF

echo "✅ Test report generated: test-results/test-report.md"