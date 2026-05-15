# 动态节点发现插件架构说明

## 📋 概述

本次重构将**动态节点发现功能**从 EasyTier 核心中提取出来，作为独立的外挂插件。这样做的目的是：

1. **保持核心简洁**：EasyTier 核心专注于 P2P VPN 功能
2. **职责分离**：节点发现属于运维工具，不应混入核心网络逻辑
3. **灵活扩展**：用户可以用任何语言实现自己的节点管理工具
4. **易于测试**：外围工具可以独立测试，不影响核心稳定性

## 🏗️ 架构设计

### 改进前（紧耦合）

```
┌─────────────────────────┐
│   EasyTier Core         │
│                         │
│  ┌───────────────────┐  │
│  │ HttpConnector     │  │  ← 内置自动刷新
│  │ - register()      │  │  ← 全局单例管理器
│  │ - refresh_loop()  │  │  ← TTL 管理
│  └───────────────────┘  │
│                         │
│  ┌───────────────────┐  │
│  │ DnsConnector      │  │  ← 内置自动刷新
│  │ - register()      │  │
│  │ - refresh_loop()  │  │
│  └───────────────────┘  │
│                         │
│  GlobalCtx (过重)       │
└─────────────────────────┘
```

**问题**：
- ❌ 核心代码复杂度高
- ❌ 职责不清（网络 + 节点管理）
- ❌ 难以测试和维护
- ❌ 升级困难（需要重新编译核心）

### 改进后（松耦合）

```
┌─────────────────────┐         REST API        ┌──────────────────────┐
│  EasyTier Core      │ ◄─────────────────────► │  Node Discovery      │
│                     │                         │  Plugin (外挂)       │
│  - P2P VPN          │   POST /connector/add   │                      │
│  - NAT Traversal    │   POST /connector/remove│  - HTTP Discovery    │
│  - Encryption       │   GET  /connector/list  │  - TXT Discovery     │
│  - Routing          │                         │  - SRV Discovery     │
│                     │                         │  - Auto Refresh      │
│  Basic Connectors:  │                         │  - TTL Management    │
│  - HttpConnector    │                         │                      │
│  - DnsConnector     │                         │  Implementation:     │
│  (单次连接，无刷新)  │                         │  - Python Script     │
│                     │                         │  - Bash Script       │
│                     │                         │  - Rust Binary       │
└─────────────────────┘                         └──────────────────────┘
```

**优势**：
- ✅ 核心保持简洁
- ✅ 职责清晰分离
- ✅ 易于测试和维护
- ✅ 可独立升级和替换

## 📦 组件说明

### 1. EasyTier 核心（easytier/）

**职责**：提供基础的 P2P VPN 功能和 REST API

**提供的 API**：
```rust
POST /api/v1/instance/connector/add
{
  "url": "tcp://node1.example.com:11010"
}

POST /api/v1/instance/connector/remove
{
  "url": "tcp://node1.example.com:11010"
}

GET /api/v1/instance/connector/list
// 返回当前所有连接器列表
```

**连接器行为**：
- `HttpConnector`：从 HTTP 响应中解析 URL 列表，批量添加到 ManualConnectorManager
- `DnsConnector`：从 DNS TXT/SRV 记录中解析 URL 列表，批量添加到 ManualConnectorManager
- **不再包含**：自动刷新、TTL 管理、后台任务

### 2. 节点发现插件（easytier-contrib/easytier-node-discovery/）

**职责**：定期从配置源获取节点列表，通过 API 更新 EasyTier 连接器

**支持的功能**：
- ✅ HTTP/HTTPS 协议发现
- ✅ DNS TXT 记录发现
- ✅ DNS SRV 记录发现
- ✅ 定期自动刷新（可配置间隔）
- ✅ 增量更新（只添加新节点，移除旧节点）
- ✅ 失败保护（刷新失败保留现有连接）

**提供的实现**：

#### A. Python 脚本（推荐）
```python
# easytier_node_discovery.py
python3 easytier_node_discovery.py \
  --config-url http://config-server.com/nodes \
  --api-endpoint http://127.0.0.1:15888 \
  --interval 300
```

**优点**：
- 跨平台
- 易于修改和扩展
- 依赖少（只需要 requests 库）

#### B. Bash 脚本
```bash
# refresh-nodes.sh
./refresh-nodes.sh \
  --config-url http://config-server.com/nodes \
  --api-endpoint http://127.0.0.1:15888 \
  --interval 300
```

**优点**：
- 无需安装 Python
- 适合 Linux 服务器环境
- 轻量级

#### C. Rust 二进制（开发中）
```bash
# easytier-node-discovery
./target/release/easytier-node-discovery \
  --config-url http://config-server.com/nodes \
  --api-endpoint http://127.0.0.1:15888 \
  --interval 300
```

**优点**：
- 高性能
- 单文件部署
- 与 EasyTier 技术栈一致

## 🔄 工作流程

### 启动流程

```
1. 启动 EasyTier Core
   $ easytier-core --instance-name mynet --ipv4 10.144.144.1
   
2. 启动 Node Discovery Plugin
   $ python3 easytier_node_discovery.py \
       --config-url http://config-server.com/nodes \
       --interval 300
   
3. Plugin 立即执行首次同步
   - 从 HTTP 服务器获取节点列表
   - 通过 API 添加所有节点到 EasyTier
   
4. Plugin 进入循环
   - 每 300 秒刷新一次
   - 计算差异（新增/移除）
   - 通过 API 更新连接器
```

### 同步流程

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│ Config Server│         │Node Discovery│         │ EasyTier     │
│              │         │   Plugin     │         │   Core       │
└──────┬───────┘         └──────┬───────┘         └──────┬───────┘
       │                        │                        │
       │  1. GET /nodes         │                        │
       │ ◄───────────────────── │                        │
       │                        │                        │
       │  2. Response:          │                        │
       │     tcp://node1:11010  │                        │
       │     udp://node2:11010  │                        │
       │ ─────────────────────► │                        │
       │                        │                        │
       │                        │  3. POST /connector/add│
       │                        │     {url: tcp://...}   │
       │                        │ ─────────────────────► │
       │                        │                        │
       │                        │  4. POST /connector/add│
       │                        │     {url: udp://...}   │
       │                        │ ─────────────────────► │
       │                        │                        │
       │                        │  5. Wait 300s          │
       │                        │                        │
       │                        │  6. Repeat from step 1 │
       │                        │                        │
```

## 📊 对比分析

| 特性 | 改进前（内置） | 改进后（外挂） |
|------|--------------|--------------|
| **核心复杂度** | ⭐⭐⭐⭐⭐ 高 | ⭐⭐ 低 |
| **灵活性** | ⭐⭐ 固定逻辑 | ⭐⭐⭐⭐⭐ 完全自定义 |
| **可测试性** | ⭐⭐ 难 | ⭐⭐⭐⭐⭐ 易 |
| **维护成本** | ⭐⭐⭐⭐ 高 | ⭐⭐ 低 |
| **升级影响** | ❌ 需重新编译核心 | ✅ 独立升级 |
| **资源占用** | ⚠️ 常驻核心内存 | ✅ 独立进程 |
| **故障隔离** | ❌ 影响核心 | ✅ 独立进程 |
| **语言选择** | ❌ 只能 Rust | ✅ Python/Bash/Rust/Go... |
| **社区贡献** | ❌ 需审核核心代码 | ✅ 独立仓库 |

## 🎯 使用示例

### 场景 1: 开发环境（快速迭代）

```bash
# 1. 启动 EasyTier
easytier-core -i 10.144.144.1 -n dev-network

# 2. 启动 Python 脚本（便于调试）
python3 easytier_node_discovery.py \
  --config-url http://localhost:8080/nodes \
  --interval 60  # 快速刷新
```

### 场景 2: 生产环境（稳定运行）

```bash
# 1. 创建 systemd 服务
sudo tee /etc/systemd/system/easytier-node-discovery.service <<EOF
[Unit]
Description=EasyTier Node Discovery
After=network.target easytier.service

[Service]
Type=simple
ExecStart=/usr/local/bin/easytier_node_discovery.py \
  --config-url http://config.internal/nodes \
  --interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 2. 启动服务
sudo systemctl enable easytier-node-discovery
sudo systemctl start easytier-node-discovery
```

### 场景 3: 自定义逻辑

```python
# custom_discovery.py - 实现自己的发现逻辑
import requests
from easytier_node_discovery import NodeDiscoveryManager

class CustomDiscovery(NodeDiscoveryManager):
    def fetch_nodes(self):
        # 从数据库获取节点
        nodes = query_database("SELECT url FROM nodes WHERE active=1")
        
        # 或者从 Kubernetes API 获取
        # nodes = get_k8s_endpoints("easytier")
        
        # 或者从 Consul 获取
        # nodes = consul_catalog("easytier")
        
        return set(nodes)

if __name__ == '__main__':
    manager = CustomDiscovery(
        config_url="custom://database",
        api_endpoint="http://127.0.0.1:15888",
        interval=300
    )
    manager.run()
```

## 🔧 开发指南

### 添加新的发现协议

1. **在 Python 脚本中添加**：
```python
def fetch_custom_nodes(self) -> Set[str]:
    # 实现自定义逻辑
    pass

def fetch_nodes(self) -> Set[str]:
    scheme = urlparse(self.config_url).scheme
    if scheme == 'custom':
        return self.fetch_custom_nodes()
    # ... 其他协议
```

2. **在 Bash 脚本中添加**：
```bash
fetch_custom_nodes() {
    # 实现自定义逻辑
}

fetch_nodes() {
    case "$scheme" in
        custom)
            fetch_custom_nodes
            ;;
        # ... 其他协议
    esac
}
```

### 扩展 API 功能

如果 EasyTier 核心提供的 API 不够用，可以：

1. **提交 PR 到 EasyTier 核心**，添加新的 API 端点
2. **使用现有的 CLI 命令**：
```bash
easytier-cli connector add tcp://node1:11010
easytier-cli connector remove tcp://node1:11010
```

## 📝 总结

通过将动态节点发现功能提取为独立插件，我们实现了：

1. ✅ **核心简洁**：EasyTier 专注于 P2P VPN
2. ✅ **职责清晰**：节点管理作为外围工具
3. ✅ **灵活扩展**：支持多种实现方式
4. ✅ **易于维护**：独立测试、独立升级
5. ✅ **向后兼容**：HTTP/TXT/SRV 连接器仍然可用（只是没有自动刷新）

这种架构符合**单一职责原则**和**开闭原则**，使系统更加健壮和可维护。
