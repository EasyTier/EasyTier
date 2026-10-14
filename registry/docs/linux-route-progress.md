# Linux 路由管理实施进度

目标：将已有实验改动整理为可独立审查的提交，继续完成 Linux 路由管理，
然后审查跨平台接入。本文记录实现和验证，不把尚未完成的项目视为已有能力。

## 提交历史

原有 registry 大提交与工作树修改已重建为九个依赖有序的本地提交：

1. 独立升级 guarden。
2. scoped registry、snapshot / invalidation 合约及测试。
3. 动态路由声明与 manual policy 解析。
4. Linux 后端和设备索引读取。
5. RouteMgr 的差异执行与重试。
6. OSPF producer 的发布及撤销。
7. Host 生命周期和 DNS 声明接线。
8. 配置 / registration ownership 文档。
9. 保留原有 Linux 测试 runner 配置。

中间源码提交分别运行相关编译或测试。验证发现 native 暂停时钟测试此前
依赖其他测试包启用 Tokio test-util，已在 native dev-dependencies 显式声明。
最终源码 tree 与整理前完整快照一致，另加该测试依赖修复；原始历史及源码
保存在本地 `refs/codex/route-before-split-20261014` 备份引用中。

## Linux 后端

后端在指定 netns 创建一个 socket。切换 namespace 的短线程结束后，socket
交给 Tokio AsyncFd；后续请求复用它，不再逐条打开 socket 或 spawn_blocking。
设备生命周期独立于 socket，后端不持有 TUN。

每个请求使用不同 sequence，接收端校验内核 sender 与 sequence。ACK 等待
有两秒 deadline，迟到 ACK 不能成为后续请求的结果。内核 negative ACK
表示确定失败；发送后超时、读取或解码失败表示 Unknown。发送前的本地失败
不产生已提交操作；只读核实失败也不产生新的写操作责任。

创建保持 CREATE | EXCL，不覆盖外部路由。EEXIST 后通过 dump 核实完整参数，
只有等价的 direct route 才返回 external-present；其他情况返回冲突。
核实不会将观察到的外部条目认领为本方安装记录。

创建和删除使用同一组已解析参数：地址族、目标 / 前缀、OIF、非零 metric、
main table、static protocol、universe scope、unicast type。正常删除不 dump。
非零 metric 避免 Linux 将零 delete priority 当作 wildcard。IPv4 / IPv6
走同一后端合约；Manager 不再因 IPv6 Additional demand panic。

ACK 及 sequence 依据 [Linux Netlink 文档](https://docs.kernel.org/userspace-api/netlink/intro.html)。
delete priority 的匹配依据 [Linux v6.18 fib_nh_match](https://github.com/torvalds/linux/blob/v6.18/net/ipv4/fib_semantics.c)。

## 设备事实与 fd lifetime

设备输入使用同一份 Host snapshot 区分选中的设备、是否 ready、以及仍有 fd
owner 的 claims。fd registration identity 与 kernel device identity 分离；
新实例 identity 不复用，所以同名同 ifindex 重建且中间通知被合并时仍可识别。
改变选择不表示旧设备已销毁：旧 fd 仍存活时，旧 route 走正常精确删除。
未 ready 或配置失败时暂停普通写入，保留已有安装责任。

TUN IO 的 read/write 两半共享 DeviceResource。它先关闭实际 IO resource，
再释放 lifetime claim；丢弃 NicCtx 元数据或一半 IO 不会提前宣布销毁。
后端和 Manager 均不持有 TUN resource。只有非持久化、本方独占生命周期的
设备使用 owned generation；TUNGETIFF 显示持久化时使用 external identity，
fd 关闭不会被当成 kernel 接口消失，已安装路由仍由 Manager 显式删除。

以上判定依据 [Linux v6.18 TUN driver](https://github.com/torvalds/linux/blob/v6.18/drivers/net/tun.c)。
Descriptor lifetime 测试使用真实 pipe fd；本轮环境没有 /dev/net/tun，尚未运行
完整 TUN 创建 / 关闭集成测试。

## 协调循环

稳态不再定时重读声明；设备事实、配置和 registration 的既有通知驱动刷新。
只有可执行的 pending 操作 / retry 才设置 deadline。blocked addition 的旧
期限不参与唤醒，避免 removal 失败 / Unknown 时忙循环。

重试从收到失败结果的时刻计时，第一次为 100ms；无关通知不清空退避。
替换必须等待同目标的旧条目被确认删除。I/O 中更新输入后，先记录正在执行
的结果，再停止旧批次余下操作并读取最新 snapshot。

27 个 manager 测试通过，新增虚拟时钟测试覆盖以上四项行为。

## 清理任务 ownership

Host 使用既有 guarden 观察原 manager 的结束结果。五秒等待期限包含 task slot
的锁等待；超时保留 observer 和原 writer。Host Drop 将未完成的 observer 交给
创建时捕获的 Tokio runtime，继续报告失败 / Unknown 或 JoinError，不产生第二个
cleanup writer。关闭 TUN 不依赖 route cleanup 完成，Manager 继续读取 fd 事实。

RuntimeHost 十项测试通过，包括超时后完成、锁等待 deadline、任务 panic 和
Host Drop 后 observer 继续执行。

## 当前验证

- native 路由、设备事实、GlobalCtx 与 RuntimeHost 测试：44 项通过。
- 设备事实基础提交单独运行四项合约测试通过；无默认功能的 library 编译通过。
- Netlink wire 既有测试：4 项通过。
- 真实 Linux 测试：4 项通过。测试运行在 user/network namespace 中，每项再
  创建自己的 netns，仅操作 dummy 接口及测试路由。
- 内核测试覆盖 IPv4 / IPv6、同前缀不同 metric / table 的保留、非等价 EEXIST、
  发送后的真实 ACK 超时、迟到 ACK，以及调用线程切换 namespace 后 socket
  仍作用于创建时的 namespace。

可重运行真实内核测试：

```sh
unshare --user --map-root-user --net cargo test -p easytier --lib \
  instance::route::backend::linux::tests::kernel_ --offline --locked \
  --config 'target.x86_64-unknown-linux-gnu.runner="env"' -- --ignored
```

## 仍需完成

- 增加 Unknown 核实，保留无法证明本方 ownership 的不确定记录。
- 清理结束前重读设备事实，完整报告失败和 Unknown；中断不得丢失记录。
- DNS 等依赖实际安装结果的启动链路需要业务层答复，registration 成功本身不是 ready。
- 核对 Linux 上其余路由 writer（包括 Public IPv6）及相关接管边界。
- 完成规模 / 稳态验证后，再审查未迁移平台的具体 OS 合约和测试条件。

Registry core 的边界不变：只保存声明、管理 membership 并通知 invalidation。
平台 I/O、设备事实、反馈、retry、reconciliation 和 shutdown 都在路由领域层。
