# DNS policy 合并实施说明

## 合并范围

- 原分支：`feat/dns-policy`，`b207b8a7bb8042e54d2772cce9ff7230b254a4ae`。
- 合入的本地 `main`：`f19bcfb400489acbe3293166c896574383946027`；本次没有联网更新远端分支。
- 保留 main 的 `easytier-proto → easytier-core → easytier` 分层，以及 DNS policy 分支的 zone、policy、export、节点聚合和真实监听服务。
- 移除已被 main 拆分替代的旧 connector/instance 实现，以及旧 Magic DNS runtime 和协议，避免同时维护两套 DNS 服务。

## 主要落地变更

### 配置和管理 API

Core 只存储可无损往返的原始 `[dns]` TOML table，不依赖 Hickory。解析、规范化和 zone 校验仍属于 native DNS 模块；`ConfigBase` 移入该模块。

配置文件加载、实例构造和管理入口增加 native 校验。管理器在保存配置、替换正在运行的实例之前调用校验，避免把无效 zone 留到异步运行阶段才报错。

`NetworkConfig.dns_toml` 保存完整 DNS table，解决管理 API 逐字段转换丢失 policy/zone 的问题。已有 GUI 的 `enable_magic_dns` 开关只修改 `disabled`，不覆盖其余策略。旧 TOML 中明确设置的 `accept_dns` 和 `tld_dns_zone` 在没有 `[dns]` 时迁移；不会用旧 flags 的默认值覆盖新 DNS 默认行为。

### 路由和 RPC

DNS protobuf 移到 `easytier-proto`。Native 通过 `CoreDnsPeerAccess` 获取可信路由中的 DNS 摘要、可达节点和导出 RPC，不再获取整个 PeerManager。

本机导出正文和摘要作为一个不可变版本一起发布；OSPF 在路由表发布后通知 DNS 消费者。注册 guard 共享计数，旧 guard 释放不会提前注销仍在使用的服务。

同一 peer 的刷新串行化，RPC 返回后重新核对当前摘要，避免旧响应覆盖新配置或让已离线的 peer 重新出现。取消 peer cache 的 3 秒闲置淘汰：原来的 10 秒对账间隔长于缓存寿命，在线节点也可能在快照重建时丢失。现在由路由撤销、摘要变化和 RPC 失败显式失效。

### DNS 与网卡生命周期

`DnsNode`/`DnsServer` 不再持有 `NicCtx`。实例 runtime 创建 DNS 节点，DNS 通过 `DnsHost` 申请地址及系统 DNS 设置；实际网卡和资源所有权留在 native Host。

Host 按网卡 generation 和 owner 管理资源。相同配置遇到 TUN 替换也会重新应用；失败保持待重试。删除地址按 IP 集合计算，避免删除 UDP 监听时误删仍被 TCP 监听使用的同一个 IP；主接口地址不会被当成 DNS 附加地址删除。

DNS 生命周期独立于 TUN，可以在无 TUN 构建中使用显式监听地址。退出时先清理系统 DNS 设置，再等待实际监听任务结束、释放附加地址，最后释放本机选举 RPC 监听。

移除节点循环中会因 dirty 一直为真而忙循环的空分支；心跳 RPC 可被退出令牌取消。本机聚合节点仍使用心跳过期机制，过期会触发 catalog、地址和监听配置更新。

### 解析器和其他简化

- 统一使用 Hickory 0.26，消除两套重复的全局解析器和 hostname 获取逻辑。
- 保留 main 的 network namespace/socket mark 解析能力。
- `abf03ca5214ee9e4f4b6ff2ed7830a1a23033740` 的系统解析超时和并发限制可以适配到上述结构，因此保留；没有为它退回旧 DNS 架构。
- TXT 解析保留全部记录，并正确拼接同一记录的多个 wire string。
- 系统备用转发器复用过滤过本机监听地址的配置，避免安装系统 DNS 后再次引入自身转发。
- DNS 监听后台任务异常结束时允许重新启动。
- GUI 日志配置改为直接初始化，移除构造器接口差异。

## 验证

按最终要求只运行 `cargo check`，不运行测试。下面的 `--all-targets` 只检查测试等 target 的编译，不执行它们。

已通过（Linux x86_64、Rust 1.95）：

- `cargo check -p easytier-proto --offline`
- `cargo check -p easytier-core --no-default-features --locked --offline`
- `cargo check -p easytier --all-targets --offline`
- `cargo check -p easytier --no-default-features --offline`
- `cargo check -p easytier --no-default-features --features magic-dns --offline`
- `cargo check -p easytier --no-default-features --features magic-dns,tun,management --offline`
- `cargo check -p easytier-core -p easytier-proto -p easytier-web --all-targets --offline`
- `cargo check -p easytier-gui --offline`
- 最后再次执行 `cargo check -p easytier --all-targets --locked --offline`，确认 lock 一致且新增回归代码可编译。

最终要求提出之前，配置子任务曾运行 69 项 core 配置测试并通过；这不代表最终合并代码通过完整运行测试。上述 check 仍有 deprecated/dead-code warnings，不是零警告构建。

## 兼容边界和未验证事项

- 保留 DNS policy 分支的新默认行为及删除旧 CLI DNS flags 的决定；旧 TOML/API 开关仍兼容迁移。GUI 新建配置的旧默认关闭行为没有擅自改为开启。
- 新的 DNS 导出协议需要对端支持；旧 main 节点不会自动拥有新的 policy/export 能力。本机新旧 DNS 实现并行运行的兼容性未验证。
- Linux 自动设置系统 DNS 仍未实现；Windows 清理系统 DNS 的旧实现仍不恢复原设置。未声称本次解决完整的跨平台 DNS 恢复。
- 移动平台不通过桌面网卡接口添加 DNS 地址；未恢复 main 旧有的虚拟 DNS 报文拦截方案，也未验证 Android/iOS 的系统 DNS 接入。
- 多进程选举若由无 TUN 实例获胜，仍无法借用另一个进程的 TUN；本次没有新增跨进程网卡代理。
- Windows/macOS/移动端交叉编译、实际网卡变更、权限相关操作、GUI 前端构建及运行期网络行为没有验证。新增和移植的回归测试保留在代码中，供后续按需运行。
- 合入 main 自身已有两处 whitespace 提示（`CONTRIBUTING.md` 和 FFI `Cargo.toml`），未为本次 DNS 合并改动这些无关文件。

## 工作区保护

按用户最终指示，原工作区的 `Cargo.lock` 改动直接丢弃，不创建 stash。合并使用按新 crate 布局及 DNS 依赖重新解析的 lock，不把旧 workspace 的 lock 原样覆盖回来。前期隔离分析时留下的原始文件及补丁仍位于 `/tmp/easytier-dns-merge.TsWys3/`。

合并以真正的双父提交完成：第一父提交为原分支 `b207b8a7`，第二父提交为 `main` 的 `f19bcfb4`。当前分支历史包含该 main 提交，不再只是工作区中存在合并后的文件。原先两份未跟踪的分析报告保持不动。
