# Connector 架构重构 - 实施检查清单

## 检查清单使用说明

- 每完成一个 Task，检查一遍清单中的对应项目
- 用 [x] 标记已完成的项目
- 最终提交前检查所有项目

---

## 文件完整性

### 新增文件

| 文件 | 状态 | 备注 |
|---|---|---|
| `connector/resolver/mod.rs` | [ ] | ConnectorResolver trait, ResolvedCandidate |
| `connector/resolver/static.rs` | [ ] | StaticResolver |
| `connector/resolver/dns.rs` | [ ] | DnsResolver |
| `connector/resolver/http.rs` | [ ] | HttpResolver |
| `connector/resolver/txt.rs` | [ ] | TxtResolver |
| `connector/resolver/srv.rs` | [ ] | SrvResolver |
| `connector/managed.rs` | [ ] | ManagedConnector |

### 修改文件

| 文件 | 状态 | 变更类型 |
|---|---|---|
| `connector/mod.rs` | [ ] | 重写 create_connector_by_url，新增 create_direct_connector，删除 dynamic_connector_manager module |
| `connector/manual.rs` | [ ] | 适配 ManagedConnector |
| `connector/http_connector.rs` | [ ] | 简化：删除 dynamic_manager、多节点注入副作用 |
| `connector/dns_connector.rs` | [ ] | 简化：删除 dynamic_manager、register_for_auto_refresh、多节点注入副作用 |
| `instance/instance.rs` | [ ] | 删除 GlobalDynamicConnectorManager 注册代码 |
| `common/global_ctx.rs` | [ ] | 删除 set/get_manual_connector_manager |

### 删除文件

| 文件 | 状态 |
|---|---|
| `connector/dynamic_connector_manager.rs` | [ ] |
| `connector/dynamic_connector_tests.rs` | [ ] |

---

## 编译与检查

### 编译检查

| 检查项 | 命令 | 状态 |
|---|---|---|
| Rust 编译 | `cargo build` | [ ] |
| Wasm 编译（如有） | `cargo build --target wasm32-unknown-unknown` | [ ] |
| 所有 feature 编译 | `cargo build --all-features` | [ ] |
| Clippy | `cargo clippy --all-targets --all-features` | [ ] |
| Rustfmt | `cargo fmt --all -- --check` | [ ] |

### 测试

| 测试项 | 命令 | 状态 |
|---|---|---|
| 单元测试 | `cargo test --lib` | [ ] |
| 集成测试 | `cargo test --test '*'` | [ ] |
| http_connector 测试 | `cargo test --test http_connector_tests` | [ ] |
| dns_connector 测试 | `cargo test --test dns_connector_tests` | [ ] |
| dynamic_connector 测试 | 删除前确认测试已迁移 | [ ] |
| manual 测试 | `cargo test manual` | [ ] |
| tcp 测试 | `cargo test tcp` | [ ] |
| direct 测试 | `cargo test direct` | [ ] |

---

## 行为验证清单

### URL ⇀ ManagedConnector 映射

| 输入 URL | Resolver 类型 | 说明 | 状态 |
|---|---|---|---|
| `tcp://1.2.3.4:11010` | StaticResolver | 字面 IP，永不刷新 | [ ] |
| `tcp://ddns.example.com:11010` | DnsResolver | 域名，TTL 刷新 | [ ] |
| `tcp://localhost:11010` | DnsResolver | localhost 也是域名，需要 DNS | [ ] |
| `udp://example.com:11010` | DnsResolver | UDP + 域名 | [ ] |
| `quic://example.com:11010` | DnsResolver | QUIC + 域名 | [ ] |
| `ws://example.com:11010` | DnsResolver | WebSocket + 域名 | [ ] |
| `wss://example.com:11010` | DnsResolver | WebSocket Secure + 域名 | [ ] |
| `http://api.example.com/nodes` | HttpResolver | HTTP 拉取节点列表 | [ ] |
| `https://api.example.com/nodes` | HttpResolver | HTTPS 拉取节点列表 | [ ] |
| `txt://txt.easytier.cn` | TxtResolver | DNS TXT 记录 | [ ] |
| `srv://easytier.cn` | SrvResolver | DNS SRV 记录 | [ ] |
| `ring://...` | StaticResolver | Ring 协议，直接使用 | [ ] |
| `unix://...` (cfg(unix)) | StaticResolver | Unix Socket，直接使用 | [ ] |

### 行为验证

| 场景 | 预期行为 | 状态 |
|---|---|---|
| `tcp://1.2.3.4:11010` 连接 | TcpTunnelConnector 连接 1.2.3.4:11010 | [ ] |
| `tcp://ddns.example.com:11010` 首次连接 | DNS 解析 → 连接解析出的 IP | [ ] |
| `tcp://ddns.example.com:11010` 第二次 connect | 如果未过期：复用候选列表；如果过期：重新 DNS 解析 | [ ] |
| DDNS 更新后重连 | maybe_refresh() 重新 DNS 解析，发现新 IP | [ ] |
| `http://api/nodes` 返回多条 URL | 多头候选，每次 connect 随机选一个 | [ ] |
| `txt://domain` 返回多条 URL | 多头候选，每次 connect 随机选一个 | [ ] |
| `srv://domain` 返回多条 URL | 多头候选，weighted_choice 选择 | [ ] |
| Resolver 失败（网络不可达） | 保留旧候选，打印 warning，不阻断 connect | [ ] |
| Resolver 返回空列表 | 保留旧候选，打印 warning | [ ] |
| HTTP 302 重定向 | 跟踪重定向，解析目标 URL | [ ] |
| HTTP 200 body = URL 列表 | 解析每行作为候选 | [ ] |
| `tcp://1.2.3.4:11010` 多候选 | StaticResolver 返回单候选 | [ ] |
| managed_connector.set_ip_version(V6) | 传递给 create_direct_connector | [ ] |
| managed_connector.set_bind_addrs(vec![]) | 传递给 create_direct_connector | [ ] |
| 没有候选时 connect() | 返回 NoCandidates 错误 | [ ] |

### 删除确认

| 删除项 | 确认无残留引用 | 状态 |
|---|---|---|
| `GlobalDynamicConnectorManager` | [ ] grep 无匹配 | [ ] |
| `DynamicConnectorType` | [ ] grep 无匹配 | [ ] |
| `with_dynamic_manager` | [ ] grep 无匹配 | [ ] |
| `register_for_auto_refresh_*` | [ ] grep 无匹配 | [ ] |
| `manual_connector_manager` in GlobalCtx | [ ] 无 getter/setter 引用 | [ ] |

---

## 边界情况

| 边界情况 | 处理方式 | 状态 |
|---|---|---|
| `tcp://不存在的域名:port` | connect() 返回 DomainNotFound | [ ] |
| `http://...` 服务器 500 | Resolver 返回错误，保留旧候选 | [ ] |
| `srv://...` 无记录 | Resolver 返回空候选 | [ ] |
| `txt://...` 无记录 | Resolver 返回空候选 | [ ] |
| 候选列表全不可达（connect 全部失败） | TunnelError 传播到调用方 | [ ] |
| 刷新进行中但 connect 被调用 | 不阻塞，使用当前候选 | [ ] |
| StaticResolver 被多次 refresh | 无操作，返回单候选 | [ ] |
| DnsResolver 解析出 IPv6 被过滤（easytier-managed） | 过滤后回到 IPv4 候选 | [ ] |
