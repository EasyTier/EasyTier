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

`NetworkConfig.dns_toml` 保存完整 DNS table，解决管理 API 逐字段转换丢失 policy/zone 的问题。按后续要求，配置和 API 完全以新版 `[dns]` 为准：删除 `enable_magic_dns`、`accept_dns`、`tld_dns_zone` 字段及其迁移逻辑，旧 protobuf 编号和名称仅标记 reserved，防止将来误复用。`project_dns_config` 随双写逻辑一起删除，两处管理转换直接序列化 DNS table。

GUI 改为编辑 DNS TOML 内容（不带外层 `[dns]`），留空使用新版默认，关闭使用 `disabled = true`。移动 VPN 通过 native 解析器获取 Host 支持的 DNS 地址，不再读取旧开关或硬编码地址。OH 桥接也改为携带 `dnsServers` 列表及对应路由，外部 OH 客户端需要同步该接口。

### 路由和 RPC

DNS protobuf 移到 `easytier-proto`。Native 通过 `CoreDnsPeerAccess` 获取可信路由中的 DNS 摘要、可达节点和导出 RPC，不再获取整个 PeerManager。

删除没有生产调用者的旧 core `gateway/magic_dns` 模块，包括 route record store/publisher、packet resolver 及专属测试；不再保留第二套 DNS 路由和查询入口。被删除的三个已跟踪文件可从 Git 历史恢复。

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

## 合并时验证

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

## 新版配置统一后的验证（2026-09-05）

只进行编译和静态检查，没有运行测试；Cargo.lock 和 pnpm 锁文件保持不变。

- `cargo check --workspace --all-targets --locked --offline` 通过，覆盖 Linux 当前目标下的主程序、core、proto、web、GUI 和 workspace 内的 contrib crates；不代表通过移动目标交叉编译。
- `cargo check -p easytier --no-default-features --features magic-dns --locked --offline` 通过。
- `cargo check -p easytier --no-default-features --locked --offline` 和 `cargo check -p easytier-core --no-default-features --locked --offline` 通过。
- 前端库 proto codegen、`vue-tsc -b` 和 `vite build` 通过。
- VPN 插件 `rollup -c`、GUI `vue-tsc --noEmit` 通过。构建产物均不跟踪。
- `git diff --check` 通过。编译仍有现存 unused/dead-code warnings。

## 当前边界和未验证事项

- 保留 DNS policy 分支的新默认行为：缺省启用，`[dns].disabled = true` 显式关闭。GUI 不再写入旧版默认关闭开关，旧 TOML/API 字段不再迁移。
- 新的 DNS 导出协议需要对端支持；旧 main 节点不会自动拥有新的 policy/export 能力。本机新旧 DNS 实现并行运行的兼容性未验证。
- Linux 自动设置系统 DNS 仍未实现；Windows 清理系统 DNS 的旧实现仍不恢复原设置。未声称本次解决完整的跨平台 DNS 恢复。
- 移动平台尚不能添加新版虚拟 DNS 地址；因此 native VPN 配置接口返回空 DNS 地址列表并记录警告，避免向系统注入没有实际监听器的地址。没有恢复 main 的旧虚拟 DNS 报文拦截方案，Android/iOS/OH 的新版虚拟 DNS 接入仍待实现；显式 DNS listeners 与这项 VPN 地址能力分开。
- 多进程选举若由无 TUN 实例获胜，仍无法借用另一个进程的 TUN；本次没有新增跨进程网卡代理。
- Windows/macOS/移动端交叉编译、实际网卡变更、权限相关操作及运行期网络行为没有验证。OH crate 依赖专用 SDK 且排除在 workspace 外，本轮未编译；它的外部客户端需要同步新的 `dnsServers` 接口。前端已通过类型检查，未验证 GUI 实际交互。新增和移植的回归测试保留在代码中，供后续按需运行。
- 合入 main 自身已有两处 whitespace 提示（`CONTRIBUTING.md` 和 FFI `Cargo.toml`），未为本次 DNS 合并改动这些无关文件。

## 工作区保护

按用户最终指示，原工作区的 `Cargo.lock` 改动直接丢弃，不创建 stash。合并使用按新 crate 布局及 DNS 依赖重新解析的 lock，不把旧 workspace 的 lock 原样覆盖回来。前期隔离分析时留下的原始文件及补丁仍位于 `/tmp/easytier-dns-merge.TsWys3/`。

合并以真正的双父提交完成：第一父提交为原分支 `b207b8a7`，第二父提交为 `main` 的 `f19bcfb4`。当前分支历史包含该 main 提交，不再只是工作区中存在合并后的文件。原先两份未跟踪的分析报告保持不动。
