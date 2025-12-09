# EasyTier Uptime Monitor

一个用于监控 EasyTier 实例健康状态和运行时间的系统。

## 功能特性

- 🏥 **健康监控**: 实时监控 EasyTier 节点的健康状态
- 📊 **数据统计**: 提供详细的运行时间和响应时间统计
- 🔧 **实例管理**: 管理多个 EasyTier 实例
- 🌐 **Web界面**: 直观的 Web 管理界面
- 🚨 **告警系统**: 支持健康状态异常告警
- 📈 **图表展示**: 可视化展示监控数据

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Frontend      │    │   Backend       │    │   Database      │
│   (Vue.js)      │◄──►│   (Rust/Axum)   │◄──►│   (SQLite)      │
│                 │    │                 │    │                 │
│ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
│ │ Dashboard   │ │    │ │ API Routes  │ │    │ │ Nodes       │ │
│ │ Health View │ │    │ │ Health      │ │    │ │ Health      │ │
│ │ Node Mgmt   │ │    │ │ Instances   │ │    │ │ Instances   │ │
│ │ Charts      │ │    │ │ Scheduler   │ │    │ │ Stats       │ │
│ └─────────────┘ │    │ └─────────────┘ │    │ └─────────────┘ │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 快速开始

### 环境要求

- **Rust**: 1.70+
- **Node.js**: 16+
- **npm**: 8+

### 开发环境

1. **克隆项目**
   ```bash
   git clone <repository-url>
   cd easytier-uptime
   ```

2. **启动开发环境**
   ```bash
   ./start-dev.sh
   ```

3. **访问应用**
   - 前端界面: http://localhost:3000
   - 后端API: http://localhost:8080
   - 健康检查: http://localhost:8080/health

### 生产环境

1. **启动生产环境**
   ```bash
   ./start-prod.sh
   ```

2. **停止生产环境**
   ```bash
   ./stop-prod.sh
   ```

## 配置说明

### 环境变量

#### 后端配置 (.env)

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `SERVER_HOST` | `127.0.0.1` | 服务器监听地址 |
| `SERVER_PORT` | `8080` | 服务器端口 |
| `DATABASE_PATH` | `uptime.db` | 数据库文件路径 |
| `DATABASE_MAX_CONNECTIONS` | `10` | 数据库最大连接数 |
| `HEALTH_CHECK_INTERVAL` | `30` | 健康检查间隔(秒) |
| `HEALTH_CHECK_TIMEOUT` | `10` | 健康检查超时(秒) |
| `HEALTH_CHECK_RETRIES` | `3` | 健康检查重试次数 |
| `RUST_LOG` | `info` | 日志级别 |
| `CORS_ALLOWED_ORIGINS` | `http://localhost:3000` | 允许的跨域来源 |
| `ENABLE_CORS` | `true` | 是否启用CORS |
| `ENABLE_COMPRESSION` | `true` | 是否启用压缩 |

#### 前端配置 (frontend/.env)

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `VITE_APP_TITLE` | `EasyTier Uptime Monitor` | 应用标题 |
| `VITE_API_BASE_URL` | `/api` | API基础URL |
| `VITE_APP_ENV` | `development` | 应用环境 |
| `VITE_ENABLE_DEV_TOOLS` | `true` | 是否启用开发工具 |
| `VITE_API_TIMEOUT` | `10000` | API超时时间(毫秒) |

## API 文档

### 健康检查

```http
GET /health
```

### 节点管理

```http
# 获取节点列表
GET /api/nodes

# 创建节点
POST /api/nodes

# 获取节点详情
GET /api/nodes/{id}

# 更新节点
PUT /api/nodes/{id}

# 删除节点
DELETE /api/nodes/{id}
```

### 健康记录

```http
# 获取节点健康历史
GET /api/nodes/{id}/health

# 获取节点健康统计
GET /api/nodes/{id}/health/stats
```

### 实例管理

```http
# 获取实例列表
GET /api/instances

# 创建实例
POST /api/instances

# 停止实例
DELETE /api/instances/{id}
```

## 测试

### 运行集成测试

```bash
./test-integration.sh
```

### 运行单元测试

```bash
cargo test
```

### 测试覆盖率

```bash
cargo tarpaulin
```

## 部署

### Docker 部署

```bash
# 构建镜像
docker build -t easytier-uptime .

# 运行容器
docker run -d -p 8080:8080 easytier-uptime
```

### 手动部署

1. **构建后端**
   ```bash
   cargo build --release
   ```

2. **构建前端**
   ```bash
   cd frontend
   npm install
   npm run build
   cd ..
   ```

3. **配置环境**
   ```bash
   cp .env.production .env
   # 编辑 .env 文件
   ```

4. **启动服务**
   ```bash
   ./start-prod.sh
   ```

## 监控和日志

### 日志文件

- **后端日志**: `logs/backend.log`
- **前端日志**: `logs/frontend.log`
- **测试日志**: `test-results/`

### 健康检查

系统提供以下健康检查端点：

- `/health` - 基本健康检查
- `/api/health/stats` - 健康统计信息
- `/api/health/scheduler/status` - 调度器状态

## 故障排除

### 常见问题

1. **后端启动失败**
   - 检查端口是否被占用
   - 确认数据库文件权限
   - 查看日志文件 `logs/backend.log`

2. **前端连接失败**
   - 检查后端服务是否运行
   - 确认API地址配置
   - 检查CORS配置

3. **健康检查失败**
   - 确认目标节点可访问
   - 检查防火墙设置
   - 验证健康检查配置

### 性能优化

1. **数据库优化**
   - 定期清理过期数据
   - 配置适当的连接池大小
   - 使用索引优化查询

2. **前端优化**
   - 启用代码分割
   - 配置缓存策略
   - 优化图片和资源

3. **网络优化**
   - 启用压缩
   - 配置CDN
   - 优化API响应时间

## 贡献指南

1. Fork 项目
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 许可证

MIT License

## 支持

如有问题或建议，请提交 Issue 或联系开发团队。