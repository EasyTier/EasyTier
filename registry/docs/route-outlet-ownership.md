# 路由管理：逻辑出口与实例输入的 ownership

Linux desktop 的路由 writer 现在跟随逻辑 NIC 出口。每个实例保留独立
`RouteScope`，共享 NIC 的实例共享一个 `RouteMgr`。Backend 仍只是 OS 操作封装。
本文描述当前实现；其他平台保留既有路由路径。

## 为什么改变按实例的 writer

实例的 manual policy、动态 producer 和 shutdown 确实相互独立，但同一个
共享 TUN 上的一条内核路由只有一份。两个实例各自维护 installed / external
时，后创建者会把前者安装的路由记成 external；前者退出后删除它，后者却仍然
相信路由存在。preferred source 的切换和删除地址引发的 route cascade 也需要
在同一个物理出口上协调。

因此独立的是输入 scope，集中的是同一出口的物理效果责任。不把引用计数、
成员策略或 reconciliation 放到 Backend，也不建立跨所有 NIC 的全局 manager。

## 四个层次

| 对象 | 保存什么 | 谁拥有 / 关闭 |
| --- | --- | --- |
| `RouteScope` | 实例 ID、同一权威 ConfigStore、动态 RouteRegistry、当前 binding、feedback | 实例 Host；close 撤销该实例的 producers |
| `RouteScopeLease` | 一次 scope 到出口的 registration | NicCtx；Drop 撤销这个 binding，不关闭整个 scope |
| `RouteOutlet` / `RouteMgr` | 出口设备事实、成员输入、desired / installed / external / unknown、retry、writer task | SharedVirtualNic；成员退出不停止公共 writer |
| `RouteBackend` | OS socket 和请求 correlation | Manager；只接收 `OsRoute`，不接收实例或 binding identity |

有名字的出口按 netns + device name 共享。没有指定名字时，逻辑 slot 加实例
ID，防止不同实例意外共享匿名设备；同一实例的 NIC 重建仍可复用该逻辑出口。
逻辑出口的寿命可以跨越多个实际 fd generation。

Manager 只持有 NIC 的 Weak 引用、设备 facts 和输入。它不能延长 TUN 的 IO
寿命。实际 fd 的最后 owner 仍是设备销毁事实的来源；scope / lease Drop 不是
物理设备销毁证据。

## 输入、验证和应用

每个 scope 分别执行：

```text
该实例 ConfigStore.manual_routes + 动态 declarations
  → 该实例 RouteSet
  → 共享 NIC 的成员约束 / dispatcher claims
  → 出口 effective routes + concrete preferred source
  → desired OS routes
  → diff / ACK / retry / Unknown inspection
  → 按 binding 发布每个 scope 的反馈
```

manual 的 None / Some(empty) / Some(set) 只影响所属实例的 AutoProxy。
Additional 始终参与。没有 manual registration，也没有配置副本 producer。
Manager 直接订阅每个 scope 的 Store 和动态 registry；没有额外转发 task。

共享 NIC 的约束仍是领域策略：不同成员的地址 / 目的网段不能重叠，标准
Magic DNS fake-IP host route 保留已有例外。不能从“同一个 OsRoute 可以去重”
推导出任意跨网络前缀都允许共享。拒绝的新声明记录 warning，并保留该成员
最后接受的 claims；raw declaration 不被篡改，后续输入变化会重新验证。

同一输入快照中，成功的非空 replacement 可能释放另一个成员需要的前缀；
被阻塞的 proposal 会在本轮有进展后重新验证。各成员 replacement 仍以整份
claims 为单位，不承诺多个独立配置源之间的联合事务或同时交换冲突前缀。

通过成员验证后，同目标取最低非零 metric。多份有效声明只产生一条 OS route。
IPv4 preferred source 使用共享 NIC 现有成员选择规则；IPv6 不增加源地址策略。
成员离开导致 source / metric 改变时，由同一个 Manager 精确删除旧 key 后创建
新 key。删除失败或 Unknown 会阻止替换，不能用 replace 覆盖责任。

dispatcher 使用当前接受的逻辑 claims；它与内核更新不是原子事务。撤销声明
可以立即撤销 forwarding membership，物理 route cleanup 可以滞后。ready
表示已 ACK / 核实的路由满足该 scope 的有效需求，不表示未来不会变化。

## 地址变化和已安装责任

设备层继续管理地址、link、MTU 和 OS 自动产生的 connected routes。Linux
删除 preferred source 地址可能顺带删除 managed route，所以地址变动和成员
配置提交会使出口 route revision 失效。

Manager 在该 revision 后批量只读核实已有 installed receipts：仍存在则保留
之前的 ownership；已不存在则退休 receipt 并按当前需求重建。核实失败保留
责任，暂停 ordinary mutation 和 ready，设置一秒重试。它不从查询认领外部
route，也不在稳态轮询所有路由。

## binding、反馈与并发

scope identity 是实例；binding identity 是一次连接到某个出口的生命周期；
fd registration identity 是一次实际设备 attachment。三者不可互换。

binding ID 单调不复用。旧 lease、旧 Manager 或旧 outlet 的退出只能撤销自身
binding，不能清空已经迁移到新出口的 scope，也不能关闭实例 RouteRegistry。
发布反馈时在同一 binding 锁内检查身份，避免检查后重绑定造成旧反馈覆盖。

membership、配置、declaration、binding、device 和 NIC revision 通知都是
invalidation，不是逐条事件。所有 baseline 在快照读取前确认；backend I/O
期间的新通知保持 pending，先记录当前请求的结果，再停止旧批次。scope
watch 在同一 manager loop 中直接 multiplex，不产生每实例 watcher task。
Store 与声明、不同 scope 之间不提供跨输入原子事务；各自的 snapshot 一致，
允许更新合并并最终读取最新状态。

NIC mutex 只覆盖成员验证和 dispatcher claims 提交，释放后才执行 Backend
route I/O。scope binding mutex 只覆盖 metadata / watch 提交，不执行 OS I/O。
生产出口失去 NIC 后不能退回未验证声明继续写 OS；单纯 controller 测试才使用
无 NIC adapter 的输入投影。

## 退出和清理确认

实例关闭先 close 自己的 scope，撤销 producer capability，再停止自己的 NIC
任务和成员 claims。公共 writer 继续服务其他实例。

scope withdrawal completion 与 registration removal 分开。Manager 记录各
binding 可能涉及的物理 keys：被别的有效 scope 继续需要的 key 可交接；已经
不需要的 key 要等待确定删除、只读确认 absent，或实际 owned fd 销毁的证明。
Unknown 仍 present 时不会报告 cleanup 完成。

Host 最多等待五秒。超时只结束该 Host 的等待，原出口 writer 保留未完成责任。
出口关闭时 revoke 自己的所有 bindings、关闭输入 registry、取消 reconcile
并清理自身 receipts；不关闭可能已迁移的实例 scope。任务 observer 使用既有
guarden，报告原 writer 的完成 / 失败，不 abort，也不创建第二个清理 writer。
不承诺进程退出或创建 writer 的 runtime 被销毁后仍可异步清理。

DNS 启动同时检查 binding 和实际 fd claim，在精确 attachment 的 fake-IP
route ready 后才成功。等待期间任一个被替换都会失败并撤销本次声明。

## abstraction boundary

generic Registry 仍只提供 registration membership、replace、RAII withdrawal、
snapshot 和 invalidation。RouteScope / Outlet / Projection 都是路由领域代码，
没有 generic policy、async extension trait 或 callback hook。共享 NIC 冲突规则、
preferred source、OS ownership、retry、Unknown 和清理不进入 registry core。

Backend 的三个操作对应 exclusive add、参数匹配 delete、只读 inspection。
它原样返回 EEXIST / absent 等 OS 错误；应用层负责解释等价外部路由、删除已
不存在项的成功语义，以及失败 / Unknown 的后续行为。

验证命令、实际结果和未验证的平台见 [实施进度](linux-route-progress.md)。
