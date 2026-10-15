# 路由管理：manual policy 与动态声明的边界

manual policy 的 authority / 通知模型保持如下设计。2026-10-15 已将实际 writer
改为按逻辑出口管理，每实例输入保留在 RouteScope；见 [出口 ownership](route-outlet-ownership.md)。

## 状态与 ownership

`CoreRuntimeConfigStore` 是实例配置的 authority。`services.manual_routes`
是配置策略，没有独立 producer 或 registration lifetime；Store 不保存
`Registration<RouteDemand>`，也不负责向路由 registry 发布配置副本。

`Registry<RouteDemand>` 保存独立 producer 的动态声明：

- `AutoProxy`：OSPF 发布的当前可达 peer proxy CIDRs。
- `Additional`：DNS fake-IP 等额外需求。

每个 registration 代表一个 producer 的整份当前声明。`replace` 保持其
identity；Drop 撤销这个 producer 的贡献。多个 producer 可以需求同一路由，
最终 CIDR 集合在路由领域层合并、去重。

manual policy 的规则不变：`None` 使用 auto 集合；`Some(routes)` 替代整个
auto 集合；`Some(empty)` 抑制 auto。`Additional` 始终参与最终结果。
不存在多个 manual registrations，因而不再需要 duplicate-manual 错误分支。

## 更新链路

```text
Instance 创建配置 Store
  → InstanceRuntimeHost::prepare(packet_plane, runtime_config)
  → NativeRouteRuntime::prepare(runtime_config)
  → 实例 RouteScope 持有同一个 Store
  → 出口 RouteMgr 订阅所有成员 scope 的 service changes

配置写入 → 提交完整快照 → Store 发送既有 service-change 通知
动态声明写入 / Drop → 提交 membership / payload → registry 通知
```

RouteMgr 同时等待各 scope 的这两份通知，分别读取 Store 和 registry 的当前快照。
配置链路没有新增转发任务、callback、专用配置 signal 或 policy trait。
读取初始快照不依赖通知，manual routes 在 registry 为空时也能生效。

两个 watch 都必须在读取输入之前确认 baseline；backend I/O 期间发生的更新
保持 pending，下一轮立即读取新状态。通知表示输入可能变化，既不是每次写入
都必须处理的事件队列，也不表示 kernel 已经完成更新。

配置和动态声明是独立输入，没有跨 Store / registry 的原子事务保证。
每个快照自身一致；连续更新允许合并，manager 最终消费最新输入。
无关 service 配置也可以唤醒 manager，但路由差集为空时不会重复写 kernel。
设备变化由事实通知唤醒；只有 pending 操作、retry 和 Unknown 核实需要 timer。

## Side effect 与 shutdown

Registry 只保存声明，配置 Store 只保存配置。effective CIDRs、desired routes、
installed / external / unknown 状态、retry 和 backend 操作都留在 RouteMgr。

Host cancellation 关闭本实例 scope，registry close 撤销动态声明并拒绝后续
registration / replace。公共出口 manager 继续服务其他实例；只有出口关闭才
停止这个 writer。配置 Store 可以被其他组件继续持有，写入不会重新打开已关闭 scope。

manual policy 与 OS responsibility 是独立边界。出口级 writer、设备 generation、
Unknown 和异步 cleanup supervision 的当前合约见出口 ownership 文档。

## Registry 合约修复

- Registration Drop 在提交移除、释放锁之后先通知，再销毁 retired payload。
  payload destructor 重入或 panic 不再抑制已经提交的撤销通知。
- Registry / Registration 的 Debug 只读取 metadata，并在格式化前释放锁；
  不要求 `T: Debug`，不调用 payload 的 Debug。

## 回归验证

测试覆盖 manual 覆盖 / 空集合 / 恢复最新 auto / Additional 保留、初始 manual
不需要 registration、backend I/O 期间配置更新无需等待设备轮询、Host 收到
同一配置 authority，以及配置继续存活时 manager 的关闭状态。

Registry 测试覆盖 payload panic 前的通知和 metadata-only Debug，并继续运行
既有并发、snapshot、重入析构和 close 测试。真实 kernel / TUN 行为仍需单独
的集成验证。

2026-10-14 在路由工作树实际完成的验证：

- Registry：21 个单元测试、7 个并发测试、1 个文档测试通过。
- RouteMgr：18 个 mock backend 测试通过，包含 idle 和 in-flight 配置更新。
- Core：7 个配置 Store、5 个路由解析、4 个 Host 生命周期测试通过。
- 默认功能的 native / core library 测试目标编译通过，DNS 测试辅助 Host 也参与编译。
- `cargo check -p easytier --lib --no-default-features --offline --locked` 通过，
  仍有 feature-dependent unused / dead-code 警告。
- 所有修改的 Rust 文件通过已安装 stable rustfmt 的格式检查；`git diff --check` 通过。

以上是早期 manual policy 改动的验证记录。后续真实 kernel / TUN 和 DNS
验证见 [实施进度](linux-route-progress.md)，不把此处历史计数当作最终状态。

## Rust 调用点迁移

- `CoreRuntimeConfigStore::new(services, peer)` 不再接收 registration。
- `InstanceRuntimeHost::prepare(packet_plane, runtime_config)` 接收实例的 Store clone。
- `RouteScope::prepare(runtime_config)` 保留同一份 Store，NicCtx 持有出口 binding。
- `RouteMgr` 接收出口设备 facts 和 scope membership，不再持有某个 GlobalCtx。
- `resolve_route_demands(demands, manual_routes.as_ref())` 直接返回 `RouteSet`。
- `RouteDemand::ManualProxy` 被移除，manual policy 的唯一来源是配置快照。

这些是 Rust 内部 API 调整；配置字段及 manual policy 的运行语义保持不变。
