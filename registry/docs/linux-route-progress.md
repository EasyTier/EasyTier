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

## 当前验证

- native 路由测试：23 项通过，其中包括 manager 与 ACK / 请求模型测试。
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

- 以 Host 实例 identity 和真实 fd lifetime 发布设备事实，替代索引轮询；
  区分配置失败、暂未 ready、改选设备和确认销毁。
- 改善协调循环的撤销 / 替换依赖、退避和 Unknown 核实，避免被阻塞的重试忙循环。
- 在 backend I/O 期间输入变化时停止旧批次剩余操作，保留已执行结果的责任。
- 停机超时保留任务 ownership；清理结束前重读设备事实，完整报告失败和 Unknown。
- DNS 等依赖实际安装结果的启动链路需要业务层答复，registration 成功本身不是 ready。
- 核对 Linux 上其余路由 writer（包括 Public IPv6）及相关接管边界。
- 完成规模 / 稳态验证后，再审查未迁移平台的具体 OS 合约和测试条件。

Registry core 的边界不变：只保存声明、管理 membership 并通知 invalidation。
平台 I/O、设备事实、反馈、retry、reconciliation 和 shutdown 都在路由领域层。
