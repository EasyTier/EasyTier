# core::config 与 PeerContext 职责收敛方案

> 状态：部分仍有效。后续工作已收敛到
> [`core_refactor_roadmap.md`](core_refactor_roadmap.md) 的 Core instance
> 阶段，实施前需按当前源码重新盘点已完成项。

## 背景

`easytier-core` 已经开始承担可复用的 core 模块职责。`PeerId` 已经位于
`easytier-core::config`，并被 `peers`、`hole_punch::udp`、`proxy`、
`rpc_impl` 等模块共享。但部分纯数据概念仍散落在 peers 运行时接口里，
尤其是 `NetworkIdentity` / `NetworkSecretDigest` 目前定义在
`peers::context`，runtime 层也有同构 DTO。

长期边界应保持为：

- `core::config` 负责 core 级、跨模块共享、无副作用的纯数据概念。
- `peers::context::PeerContext` 只作为 peers 模块的运行时能力接口。
- `hole_punch`、`proxy`、`peer_center` 等非 peers 模块不通过
  `PeerContext` 获取通用配置或运行时能力。

本文档只覆盖阶段 1 到阶段 5。阶段 6 的 peers 内部调用点大规模迁移收益较小，
暂不纳入本轮计划。

## 设计原则

### 纯数据概念归属 core::config

`core::config` 应承载以下类型：

- `PeerId`
- `NetworkIdentity`
- `NetworkSecretDigest`
- `CoreConfig`
- `NodeConfig`
- `RouteConfig`
- `PeerPolicyConfig`
- `TrafficConfig`
- `IpPrefix`
- 可以被多个 core 模块共享的策略快照类型

这些类型应满足：

- 不依赖 `peers`。
- 不依赖 runtime crate。
- 不执行 I/O。
- 不持有任务、socket、channel、metrics recorder、credential manager 等运行时对象。
- 可以作为 proto / runtime config / core module 之间的稳定数据边界。

### PeerContext 只保留 peers 运行时能力

`PeerContext` 可以继续存在于 `easytier-core::peers::context`，但它不是
core-wide global context。它的职责是给 peers 内部提供运行时依赖，例如：

- handshake / session 需要的 network identity 和安全能力。
- route / OSPF / foreign network 需要的本节点运行时信息。
- peer event 发布和订阅。
- credential / trusted key / ACL 查询。
- control-plane metrics 和 limiter。
- STUN 信息读取。

不应新增非 peers 模块对 `ArcPeerContext` 的依赖。如果非 peers 模块需要
配置或能力，应定义自己的窄 DTO / trait，例如 UDP hole punch 当前使用的
`UdpHolePunchPeerSource`、`UdpHolePunchSignaling`、`UdpHolePunchRuntime`
和 `UdpHolePunchTunnelSink`。

## 阶段 1：迁移 NetworkIdentity 到 core::config

### 目标

把 `NetworkIdentity` 和 `NetworkSecretDigest` 从
`easytier-core::peers::context` 移到 `easytier-core::config`。

迁移后：

- `easytier_core::config::NetworkIdentity` 成为 core root 类型。
- `easytier_core::config::NetworkSecretDigest` 成为 core root 类型。
- `peers::context` 不再定义同构类型，只引用 `crate::config`。
- 行为完全保持不变。

### 保留语义

以下语义必须逐字等价迁移：

- `NetworkIdentity::secret_digest()`
- `NetworkIdentity::with_secret_digest()`
- `PartialEq` / `Eq` / `Hash` 基于 `(network_name, network_secret_digest)`。
- `network_secret_digest` 不存在但 `network_secret` 存在时，按现有 digest
  算法计算。
- `Default` 继续使用现有 `network_name` 和默认 digest 语义。
- `SECRET_PROOF_PREFIX` 和 `secret_proof_from_secret()` 暂不移动，除非代码显示
  它们也是跨模块纯数据 helper；本轮优先只移动 root 类型。

### 代码调整

`easytier-core/src/config.rs`：

- 新增 `NetworkSecretDigest`。
- 新增 `NetworkIdentity`。
- 移入 digest helper 中仅为 `NetworkIdentity` equality/hash 服务的私有类型和函数。

`easytier-core/src/peers/context.rs`：

- 删除本地 `NetworkIdentity` / `NetworkSecretDigest` 定义。
- 改为引用 `crate::config::{NetworkIdentity, NetworkSecretDigest, PeerId}`。
- 迁移期可以保留
  `pub use crate::config::{NetworkIdentity, NetworkSecretDigest};`，避免一次性修改
  所有现有 `easytier_core::peers::context::NetworkIdentity` 调用点；后续再把
  调用点收敛到 `easytier_core::config::NetworkIdentity`。
- `PeerContext::network_identity()` 继续返回 `NetworkIdentity`。
- `NoopPeerContext` 行为保持不变。

`easytier/src/common/config.rs`：

- runtime 层的 `NetworkIdentity` 暂时保留为配置 DTO，因为它承担 serde 行为。
- 现有 `From<easytier_core::peers::context::NetworkIdentity>` 应改为
  `From<easytier_core::config::NetworkIdentity>`。
- 如已有反向转换，统一转向 `easytier_core::config::NetworkIdentity`。

### 验证

- `cargo check -p easytier-core --no-default-features`
- `cargo check -p easytier --no-default-features`
- `cargo test -p easytier-core peers::context --no-default-features`
- 现有 NetworkIdentity equality/hash 测试如果缺失，应补充 core-level 单测。

## 阶段 2：消除 runtime PeerId 重复定义

### 目标

runtime crate 不再定义自己的 `PeerId = u32`，改为 re-export core root 类型。

### 代码调整

`easytier/src/common/mod.rs`：

```rust
pub use easytier_core::config::PeerId;
```

替代：

```rust
pub type PeerId = u32;
```

### 约束

- 不改变任何序列化、RPC、日志或 route 行为。
- 不批量重命名调用点。
- 如果类型推导产生歧义，只做最小 import 调整。

### 验证

- `cargo check -p easytier --no-default-features`
- `cargo check -p easytier-core --no-default-features`

## 阶段 3：把 P2P 策略快照从 UDP 局部模型收敛到 core::config

### 背景

`hole_punch::udp::P2pPolicyFlags` 现在是 UDP task collect 使用的策略快照。
它来自 runtime legacy flags，但语义不是 UDP 算法私有概念，而是 P2P 连接策略
的一部分。

### 目标

把 `P2pPolicyFlags` 移到 `easytier-core::config`，作为 core root 策略快照。

建议保留当前命名：

```rust
pub struct P2pPolicyFlags {
    pub disable_udp_hole_punching: bool,
    pub disable_sym_hole_punching: bool,
    pub lazy_p2p: bool,
    pub disable_p2p: bool,
    pub need_p2p: bool,
}
```

### 不做的事

不要在本阶段强行把它和 `PeerPolicyConfig` 合并。

原因：

- `PeerPolicyConfig` 是更抽象的 core config model。
- `P2pPolicyFlags` 是当前 runtime legacy flags 的行为快照。
- 二者字段和默认值语义不完全等价。
- 过早合并会把配置模型设计和 UDP 行为迁移混在一起。

### 代码调整

`easytier-core/src/config.rs`：

- 新增或迁入 `P2pPolicyFlags`。

`easytier-core/src/hole_punch/udp/model.rs`：

- 删除本地 `P2pPolicyFlags` 定义。
- 改为引用 `crate::config::P2pPolicyFlags`。

`easytier-core/src/hole_punch/udp/mod.rs`：

- 如需兼容旧 public path，可临时 `pub use crate::config::P2pPolicyFlags;`。
- 后续调用点逐步改用 `easytier_core::config::P2pPolicyFlags`。

runtime adapter：

- `RuntimeUdpHolePunchPeerSource::p2p_policy_flags()` 返回 root
  `P2pPolicyFlags`。
- 字段映射保持现状。

### 验证

- `cargo test -p easytier-core hole_punch::udp --no-default-features`
- `cargo test -p easytier connector::udp_hole_punch --no-default-features -- --nocapture`

## 阶段 4：声明 PeerContext 边界并阻止扩散

### 目标

把 `PeerContext` 明确定义为 peers 专用 runtime interface，而不是 core 全局
上下文。

### 文档约束

在 peers 重构文档和相关模块注释中声明：

- `PeerContext` 只能由 `easytier-core::peers` 及其子模块直接依赖。
- 非 peers core 模块不得新增 `ArcPeerContext` 字段或参数。
- 需要 peer id、network name、policy、STUN、signaling、tunnel sink 等能力时，
  模块应定义自己的窄 trait 或 DTO。
- runtime crate 的 `GlobalCtx` 可以继续实现 `PeerContext`，但这是 runtime
  到 peers 的 adapter，不代表其他模块可以依赖 `GlobalCtx` 或 `PeerContext`。

### 可选守护

如果后续需要自动约束，可以增加轻量脚本或 CI 检查：

```text
rg "\bArcPeerContext\b|\bPeerContext\b" easytier-core/src \
  --glob '!easytier-core/src/peers/**' \
  --glob '!config.rs'
```

本阶段先以文档约束为主，不引入 CI 行为变化。

### 验证

- 确认 UDP hole punch、proxy、peer_center 不新增 `PeerContext` 依赖。
- 确认现有 `impl PeerContext for GlobalCtx` 仍只作为 peers adapter 使用。

## 阶段 5：引入 PeerRuntimeConfig snapshot

### 背景

`PeerContext` 当前有许多零散 getter，例如：

- `network_identity()`
- `flags()`
- `secure_mode()`
- `stun_info()`
- `instance_id()`
- `ipv4()`
- `ipv6()`
- `hostname()`
- `feature_flags()`

这些方法一部分是配置数据，一部分是运行时状态。直接拆 trait 会造成大范围修改。
更稳妥的方式是先引入 snapshot，让 peers 内部逐步从“很多 getter”收敛到
“一个运行时配置快照”。

### 目标

新增 `PeerRuntimeConfig`，但暂不强制迁移所有调用点。

建议类型位于 `easytier-core::peers::context`，因为它是 peers runtime view，
不是全局 core config：

```rust
#[derive(Debug, Clone)]
pub struct PeerRuntimeConfig {
    pub core: crate::config::CoreConfig,
    pub network_identity: crate::config::NetworkIdentity,
    pub stun_info: crate::proto::common::StunInfo,
    pub feature_flags: crate::proto::common::PeerFeatureFlag,
    pub secure_mode: Option<crate::proto::common::SecureModeConfig>,
}
```

`core` 字段用于承载已经进入 root config model 的静态配置；其他字段保留
peers 运行时视角中仍依赖 proto/runtime 的信息。

### PeerContext API

新增：

```rust
fn runtime_config(&self) -> PeerRuntimeConfig;
```

旧 getter 暂时保留。为降低风险，第一步可以：

- 为 `runtime_config()` 提供默认实现，调用现有 getter 组装 snapshot。
- 保持现有 getter 默认实现不变。
- `GlobalCtx` 可先不覆盖 `runtime_config()`，等行为确认后再做优化。

如果默认实现引入递归风险，应避免让旧 getter 和 `runtime_config()` 双向默认调用。
第一版推荐：

- `runtime_config()` 默认调用旧 getter。
- 旧 getter 继续保持现有默认实现。
- 后续单独提交再让部分调用点改读 snapshot。

### CoreConfig 映射策略

`PeerRuntimeConfig.core` 的字段应由现有 `PeerContext` getter 组装：

- `node.network_name` 来自 `network_identity().network_name`。
- `node.instance_id` 来自 `instance_id()` 的 16 字节表示。
- `node.hostname` 来自 `hostname()`，空字符串可映射为 `None`。
- `routes.ipv4` / `routes.ipv6` 来自 `ipv4()` / `ipv6()`。
- `peer_policy` 第一阶段使用 `PeerPolicyConfig::default()`，除非已有字段可无歧义映射。
- `traffic` 第一阶段使用 `TrafficConfig::default()`，避免误改 limiter 语义。

不要在本阶段把所有 legacy flags 强行映射进 `CoreConfig`。legacy flags 与新的
core config model 需要单独设计。

### 验证

- `cargo check -p easytier-core --no-default-features`
- `cargo check -p easytier --no-default-features`
- 新增 `PeerRuntimeConfig` 组装单测，覆盖：
  - network identity 保留。
  - instance id byte round-trip。
  - hostname 空值处理。
  - IPv4 / IPv6 prefix 转换。

## 推荐提交拆分

为了降低 review 难度，建议按以下顺序提交：

1. `refactor: move network identity to core config`
2. `refactor: re-export runtime peer id from core`
3. `refactor: move p2p policy flags to core config`
4. `docs: define peer context dependency boundary`
5. `refactor: add peer runtime config snapshot`

每个代码提交后都需要触发提交后审查。阶段 4 如果只有文档改动，不需要代码审查。

## 完成标准

阶段 1 到阶段 5 完成后应满足：

- `NetworkIdentity` / `NetworkSecretDigest` 的唯一 core 定义位于
  `easytier-core::config`。
- `easytier-core::peers::context` 不再定义 root 数据类型，只引用 root 类型。
- runtime crate 的 `PeerId` 来自 `easytier_core::config::PeerId`。
- `P2pPolicyFlags` 位于 `easytier-core::config`，UDP hole punch 只引用 root 类型。
- `PeerContext` 的文档边界明确，非 peers 模块不新增依赖。
- `PeerRuntimeConfig` 存在，并可作为后续收敛 peers getter 的入口。
- 阶段 6 的大规模调用点迁移不作为本轮完成条件。

## 风险和处理

### NetworkIdentity 行为漂移

风险：移动类型时改变 digest、equality 或 default 行为。

处理：先复制现有实现，再补 equality/hash/default 单测，确认行为不变。

### PeerContext 默认方法递归

风险：新增 `runtime_config()` 后，如果旧 getter 默认实现也改为读取
`runtime_config()`，容易形成递归。

处理：第一阶段只让 `runtime_config()` 调旧 getter，不反向改旧 getter。

### CoreConfig 过度映射

风险：把 legacy flags、limiter、secure mode 等强行塞进 `CoreConfig`，导致行为
变化或语义不清。

处理：`PeerRuntimeConfig.core` 只映射无歧义字段。其他运行时字段保留在 snapshot
旁路字段中。

### 非 peers 模块重新依赖 PeerContext

风险：为了省事把 `PeerContext` 当成 core global context 使用。

处理：文档明确禁止；需要依赖时定义领域专用窄接口。UDP hole punch 当前模式作为
参考实现。
