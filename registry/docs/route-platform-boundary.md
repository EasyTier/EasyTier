# 路由管理：Linux 实现后的平台边界

本轮完成 Linux desktop TUN 的 route controller，并审查下一步平台接入。
本文区分已实现行为和后续方案；Windows / BSD / delegated VPN 没有迁移到新后端。
Linux 实测与提交记录见 [实施进度](/home/luna/EasyTier-route/registry/docs/linux-route-progress.md)。

## 当前能力

| 模式 | RouteHandle | 实际路由 writer / owner | 当前行为 |
| --- | --- | --- | --- |
| Linux desktop + tun + netlink | 有，no_tun 时无 | SharedVirtualNic 的 RouteOutlet / RouteMgr | 实例 scope、出口聚合、ACK、退避、Unknown 核实、applied-state、清理 |
| Linux netlink-only、无 tun | 无 | 可独立使用 backend library；Host 不启动 controller | 不接受没有设备事实来源的 native registration |
| Windows desktop | 无 | NicCtx / IfConfiguer / IP Helper | 保留既有调用和 Windows cost |
| macOS desktop / FreeBSD | 无 | NicCtx / IfConfiguer / route 命令 | 保留既有命令；尚未提供新 backend 合约 |
| Android / iOS / macOS NE / OHOS | 无 | 外部 VPN Host；Rust 接入借用的 TUN fd | 不将借用 fd 的关闭视为 OS route cleanup |

capability 的 cfg 要求 Linux、tun、netlink、not(mobile)，运行时还要求 !no_tun。
`mobile` 的来源是 [build/main.rs](/home/luna/EasyTier-route/easytier/build/main.rs)，
包含 Android、iOS、macOS NE 和 target_env=ohos。
OHOS 的 target_os 是 Linux，但实际 fd / VPN ownership 属于移动端 Host；以前
仅按 Linux + netlink 选择 manager 会提供一个没有 native device facts 的 handle。
该误接入已修正，DNS 和测试 Host 的 cfg 与 consumer 条件保持一致。

## Linux 的实际边界

一个逻辑 NIC 只有一个路由 writer；每实例保留独立 RouteScope 和配置策略。
named TUN 的成员共享物理效果责任，匿名设备使用实例私有逻辑出口。具体
ownership、binding 和成员退出语义见 [出口设计](route-outlet-ownership.md)。

- ConfigStore 只保存权威配置和既有通知。manual_routes 不再拥有 Registration。
  Manager 在注册 / 配置 / 设备通知后读取 snapshot。None 使用 auto union，
  Some 替换 auto，Some(empty) 抑制 auto；Additional 保留。
- generic Registry 保存 producer 的完整声明，entry identity 是一次 registration，
  不是一条 kernel route。Drop 撤销 membership，不能解释为立即删除 kernel route。
- RouteRegistry 是领域 facade，组合声明和 applied-state watch。RouteHandle 可
  Clone，复制发布 / 观察 capability；Registration 不 Clone，控制 source lifetime。
- RouteSpec 是 Linux direct-route request，metric 用 NonZeroU32 表达。相同目标
  取最低 metric，withdraw 后恢复余下 source；该聚合规则由 route resolver 执行。
  普通 route / DNS 为 65535，Public IPv6 默认 route 为 5。
- Manager 分别保存 desired、installed、external-present、unknown。只有自身创建的
  确认结果进入 installed。存在性查询不能证明 ownership；absent 才解除 Unknown。
- Host 设备事实区分 fd registration、logical device generation、选中和 ready。
  非持久化独占 TUN 的最后 IO owner 关闭后可证明 cascade；persistent TUN 没有
  此证明，必须显式删除自身已安装条目。manager / socket 不持有 IO resource。
- Linux 后端固定 main table / static protocol / universe / direct unicast；通过
  nonzero metric + destination + OIF 做一致的 add/delete。发送后丢失 ACK 是
  Unknown，不能从 timeout 推断确定失败。不存在应用 generation 的内核 CAS；
  fd 在 add 中失效时保留物理 key 的 uncertain 责任。
- fd close、Registry close、route cleanup completion 是三个不同事件。清理未完成
  的原 writer 由出口和 guarden observer 保留；Host 的五秒等待 timeout 不 abort，也
  不生成第二个 writer。runtime 本身销毁后不承诺继续执行异步清理。
- IPv4/IPv6 address、link、MTU 和 connected route 是设备 / OS 的职责。Public
  IPv6 source 只发布其额外前缀和显式 default route，不接管地址配置。

ready 反馈表示最后已知的 acknowledged / verified state。DNS 在给定 fd claim
的 fake-IP route 可用后完成启动；不是持续监视任意外部 writer 的保证。
Linux 测试只操作独立 namespace。宿主无 /dev/net/tun，但通过私有 mount namespace
中的测试节点补齐真实 TUN 创建、link / IPv4 address 配置、IO 最后 owner 关闭、
路由 cascade 和 persistent attachment 的核实。fd ownership release 不保证一次
立即的并发接口查询已经观察到 kernel reclamation；测试以有界的只读核实验证
最终实际状态。三个既有 DNS 集成测试覆盖真实 TUN 双向 packet、默认 / 自定义
zone 和记录替换；另有生产 NativeHost / 双 peer 的 Public IPv6 集成，覆盖 lease
发布、实时配置撤销（fd claim 不变）和 shutdown。

## Windows：先确定 OS key 和实际 adapter lifetime

[windows.rs](/home/luna/EasyTier-route/easytier/src/common/ifcfg/windows.rs) 的 ordinary
route cost 默认 9000，DNS 使用 4；Public IPv6 default 是显式 5。不能把 Linux
ordinary 的 65535 自动映射为 Windows 既有默认值。

[luid.rs](/home/luna/EasyTier-route/easytier/src/common/ifcfg/win/luid.rs) 当前 add 使用
CreateIpForwardEntry2；delete 根据 LUID、destination、next-hop 做 GetIpForwardEntry2，
再删除查询结果。它没有将之前安装记录的 metric 和其他属性逐项比对后再删除。
要接管成新 backend，须增加 equivalent-present 核实、确定 absent、参数变化时
保留责任的处理；不能简单把现有 Result<()> 包装成新 trait。

Windows 查询 key 使用 interface + destination + next-hop；route metric 是 interface
metric 的一个 offset，ifindex 不应当作持久 identity。
依据 [GetIpForwardEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardentry2)
和 [MIB_IPFORWARD_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipforward_row2)。

实际设备销毁证据也必须重做：pinned tun crate 先 open 或 create adapter，并以
Arc<Session> 持有 IO；Tun Drop 调用 session.shutdown。这和 Linux nonpersistent
fd close 的契约不同，尚未证明哪个完成事件可以退休 route responsibility。
迁移时优先使用 LUID + Host claim，保守进行 explicit cleanup；只有证据充分
才启用 cascade retirement。需要 Windows runner 验证，而不是模拟 Linux cfg。

## macOS / FreeBSD：命令成功不是完整 backend 合约

[darwin.rs](/home/luna/EasyTier-route/easytier/src/common/ifcfg/darwin.rs) 目前对
IPv4 使用 route -interface -hopcount，默认 7；IPv6 根据 optional cost 是否存在
选择包含或不包含 hopcount 的命令。删除只带目标 / interface，没有 installed
receipt、equivalence inspection、matching ACK 或外部条目保护。

FreeBSD route 命令使用 routing socket，hopcount 属于路由条目的协议相关量；
不能据此推断它等价于 Linux priority。依据 [FreeBSD route(8)](https://man.freebsd.org/cgi/man.cgi?query=route&sektion=8&format=html)。
macOS 的具体行为仍需 macOS 上核实，本文没有用 FreeBSD 手册代替 Darwin 的证据。

建议下一步从一个真实平台的 routing socket 开始，明确 destination/interface/
gateway/FIB 或 scope 的 resolved key、请求 correlation、已存在核实和 absent
查询。若暂用子进程，退出码 / 进程超时必须与 side-effect uncertainty 分离。
在这些契约验证之前，保持现有 writer；不宣布新 controller 已支持此平台。

## 移动端：是 VPN 配置应用，不是逐条 kernel mutation

NativeTunRuntime::install_mobile_tun 接入由 Host 传入的 fd；create_dev_for_mobile
设置 close_fd_on_drop(false)。Rust IO wrapper 的 Drop 不拥有 VPN 配置 / fd 的
最终销毁权限，因此不能沿用 Linux owned-generation cascade 规则。

Android 示例 [EasyTierVpnService.t.kt](/home/luna/EasyTier-route/easytier-contrib/easytier-android-jni/kotlin/com/easytier/jni/EasyTierVpnService.t.kt)
在 VpnService.Builder 上安装 route 和 DNS，然后交付 fd。
OHOS [socket_server.rs](/home/luna/EasyTier-route/easytier-contrib/easytier-ohrs/src/kernel_bridge/socket_server.rs)
根据 instance snapshot 形成 TunRequestPayload（地址、聚合 routes、DNS flag、exit-node）
并发送给 Host；这是一份 VPN 配置，不是本地 netlink ACK。

[routing.rs](/home/luna/EasyTier-route/easytier-contrib/easytier-ohrs/crates/easytier-ohos-core/src/routing.rs)
当前把 manual_routes Vec 和远端 proxy routes 合并并简化前缀，没有 Linux resolver
的 None / Some(empty) override 合约。不能无意中用共同 resolver 改变它的行为；
统一 policy 前必须保留 manual 配置 presence 并确定所需的 override 语义。

后续可复用 scoped declarations 和 snapshot invalidation，但应用层应是一份
versioned VPN desired configuration 加 Host receipt：哪份配置完成、对应哪个
fd claim、失败是否保留旧配置。需要平台重建 / apply 的真实 completion 信号。
不要为了复用 RouteBackend::add/remove 而伪造一串逐条成功结果。

## 后续抽象的明确结论

继续共享 Registry 的 scoped declaration infrastructure 和 route facade 的
发布 / 聚合 / snapshot / 生命周期部分。暂不建立跨 OS policy framework。
Linux 已证明一个小 controller + concrete backend 可以承担完整一类职责；
还没有第二个 OS backend 证明 Linux resolved key / metric / cascade 都通用。

下一步优先做 Windows 的具体 backend 和 adapter ownership 验证，再考虑提取
多平台重复的 diff / retry / Unknown / cleanup infrastructure。平台 key、priority
含义、设备销毁证据和 VPN apply 协议留在各自实现中。若需要 associated type，
只用于真实的平台 resolved key；不增加 lifetime mode、OS enum、callback hooks
或 generic policy 参数以表面支持所有模式。

## 验证状态

- 默认 Linux Host / DNS capability 测试 12 项通过。
- netlink-only、无 tun 的 library cargo check 通过，存在既有 feature-dependent
  unused / dead-code warnings。
- cli,web-client,icmp-proxy,linux-netlink、无 tun 的 Host 测试 5 项通过，包含
  builds_without_a_managed_device_producer_provide_no_route_handle。
- 本机 Linux target 加 --cfg mobile 的 library 编译通过，核对 borrowed IO 和
  no-native-route 分支；这不是实际 Android / OHOS SDK target 构建。
- 最小 netlink-only 的全 library test target 无法编译：仓库其他测试缺少
  management / JSON-RPC / proxy-packet 的完整 cfg gates。路由测试所需 Tokio
  rt-multi-thread 已显式加入 dev-dependencies；没有扩展本任务修复其他测试模块。
- Windows / macOS / FreeBSD / Android / OHOS 目标未编译、未执行；本机只安装
  x86_64-unknown-linux-gnu，实际 SDK / runner 验证仍是迁移的必要步骤。
