# EasyTier 动态节点发现插件

这是一个独立于 EasyTier 核心的节点发现和管理插件，支持：

- ✅ HTTP/TXT/SRV 协议自动发现节点
- ✅ 批量添加所有发现的节点
- ✅ 定期自动刷新（可配置 TTL）
- ✅ 失败保护（刷新失败保留现有连接）
- ✅ 多实例支持

## 快速开始

### 1. 编译插件

```bash
cd easytier-contrib/easytier-node-discovery
cargo build --release
```

### 2. 运行插件

```bash
# 基本用法
./target/release/easytier-node-discovery \
  --config-url http://config-server.com/nodes \
  --api-endpoint http://127.0.0.1:15888 \
  --interval 300

# 使用 TXT DNS
./target/release/easytier-node-discovery \
  --config-url txt://txt.easytier.cn \
  --api-endpoint http://127.0.0.1:15888 \
  --interval 300

# 使用 SRV DNS
./target/release/easytier-node-discovery \
  --config-url srv://example.com \
  --api-endpoint http://127.0.0.1:15888 \
  --interval 300
```

### 3. 作为 systemd 服务运行

```ini
# /etc/systemd/system/easytier-node-discovery.service
[Unit]
Description=EasyTier Node Discovery Plugin
After=network.target easytier.service

[Service]
Type=simple
ExecStart=/usr/local/bin/easytier-node-discovery \
  --config-url http://config-server.com/nodes \
  --api-endpoint http://127.0.0.1:15888 \
  --interval 300
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable easytier-node-discovery
sudo systemctl start easytier-node-discovery
```

## 配置选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--config-url` | 节点配置源 URL (http/txt/srv) | 必需 |
| `--api-endpoint` | EasyTier API 地址 | http://127.0.0.1:15888 |
| `--interval` | 刷新间隔（秒） | 300 |
| `--instance-name` | EasyTier 实例名称 | default |

## API 端点

插件通过 EasyTier 的 REST API 管理连接器：

- `POST /api/v1/instance/connector/add` - 添加连接器
- `POST /api/v1/instance/connector/remove` - 移除连接器
- `GET /api/v1/instance/connector/list` - 列出连接器

## 开发

### 运行测试

```bash
cargo test
```

### 示例代码

参见 `examples/` 目录。

## 许可证

AGPL-3.0
