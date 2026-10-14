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

后续通过 sudo + 独立 mount/network namespace 的私有 /dev 节点，已补齐实际
TUN 创建 / IP 配置 / 关闭与路由联动测试。宿主 /dev 与网络保持原样。参见
下面新增的真实 TUN 验证；早期的环境限制不再阻止该项测试。

## 协调循环

稳态不再定时重读声明；设备事实、配置和 registration 的既有通知驱动刷新。
只有可执行的 pending 操作 / retry 才设置 deadline。blocked addition 的旧
期限不参与唤醒，避免 removal 失败 / Unknown 时忙循环。

重试从收到失败结果的时刻计时，第一次为 100ms；无关通知不清空退避。
替换必须等待同目标的旧条目被确认删除。I/O 中更新输入后，先记录正在执行
的结果，再停止旧批次余下操作并读取最新 snapshot。

27 个 manager 测试通过，新增虚拟时钟测试覆盖以上四项行为。

Unknown 使用只读批量核实，每个地址族最多一次 dump。确认 absent 才解除隔离、
允许当前声明再创建；present 不证明 ownership，不认领、不盲目删除。核实失败
保留记录。只有存在 Unknown 时才以一秒间隔核实，无关通知不提前 / 重置期限；
未 ready 的设备只允许该只读路径。停机在最终报告前再核实一次。

add 等待结果期间 owned generation 消失时，即使收到成功 ACK，也保留对应
物理 ifindex 的 uncertain 责任；不能假定该迟到写入属于已经级联删除的旧接口。
Linux 不提供应用 generation 的内核 CAS，此处采用保守隔离，并由 absent 核实
恢复。它不声称能阻止外部程序随意重写完全相同的内核 route key。

## 清理任务 ownership

Host 使用既有 guarden 观察原 manager 的结束结果。五秒等待期限包含 task slot
的锁等待；超时保留 observer 和原 writer。Host Drop 将未完成的 observer 交给
创建时捕获的 Tokio runtime，继续报告失败 / Unknown 或 JoinError，不产生第二个
cleanup writer。关闭 TUN 不依赖 route cleanup 完成，Manager 继续读取 fd 事实。

RuntimeHost 十项测试通过，包括超时后完成、锁等待 deadline、任务 panic 和
Host Drop 后 observer 继续执行。

清理逐项提交结果，不提前清空 installed / unknown。等待 remove 结果时先标为
uncertain，取消该等待仍保留责任；确定失败保留 installed，成功才删除记录。
最后再次读取设备事实，避免 fd 在最后一次 I/O 中关闭后仍报告已级联删除的
owned 路由。30 个 manager 测试通过，覆盖中断、确定失败后再清理、以及最终
设备事实变化。

## 当前验证

Linux native TUN 的 Public IPv6 前缀和默认路由也已改为 scoped declarations。
前缀 source 在订阅后读取 CorePacketPlane 的权威 snapshot；broadcast 是
invalidation，lag 后重新读取。默认路由保持 metric 5，只有 IPv6 address 配置
成功才发布，地址撤销时清空，task 结束时由 registration Drop 撤销。

NicCtx 根据实际 RouteHandle capability 选择 managed 路径；无该 capability 的
平台保留原有 IfConfiguer writer。地址、link / MTU 及 OS connected routes 仍由
设备层负责，registry 不管理它们。57 项 native 路由 / DNS / Host 测试通过；
完整 Public IPv6 producer 事件链及 DNS 双向 packet 集成尚未执行。

声明现在使用 RouteSpec(destination, NonZeroU32 metric)；Additional 可以表达
具体优先级，ordinary proxy / DNS 保留 metric 65535。同一目标的 contribution
采用最低 metric，withdraw 后露出余下 contribution。替换仍经过原条目的精确
删除；失败时保持旧 installed 并阻塞新 metric 的创建。反馈和 wait_ready 使用
相同 effective-state 规则，较低 metric 的 direct route 可满足较高 metric 请求。
这一规则只在路由领域 resolver 中，未引入 registry policy trait。

- metric 声明、聚合与替换后相关 native 57 项、core 8 项测试通过。

RouteRegistry 是 route-domain facade：组合 scoped 声明和独立的 applied-state
watch。producer 的 RouteHandle 只能 register / 观察 / wait_ready；不能发布结果或
close。反馈标明选中的 fd registration，只包含 acknowledged / verified 条目，
排除 Unknown；closed 为终态，迟到 reconciliation 不能恢复 ready。

DNS 持有 Additional lease，等待该 fd claim 的 fake-IP 路由结果后才完成系统
DNS 配置。十秒业务 deadline、关闭、设备替换或 construction 取消均撤销 lease。
Manager 在 TUN prepare 前启动，消除启动依赖环。这里的 ready 是最后已知
安装事实，未声称监控任意外部 writer 的后续修改。

- applied-state、DNS startup、manager 与 RuntimeHost：native 56 项及 core 8 项
  通过。包含 membership 不等于 ready、错误设备、关闭后迟到发布、取消撤销、
  timeout 和同 ifindex fd 替换。

- native 路由、设备事实、GlobalCtx 与 RuntimeHost 测试：44 项通过。
- 新增 Unknown 核实后 route 模块测试：43 项通过，五项内核测试默认 ignored。
- 设备事实基础提交单独运行四项合约测试通过；无默认功能的 library 编译通过。
- Netlink wire 既有测试：4 项通过。
- 真实 Linux 测试：5 项通过。测试运行在 user/network namespace 中，每项再
  创建自己的 netns，仅操作 dummy 接口及测试路由。
- 内核测试覆盖 IPv4 / IPv6、同前缀不同 metric / table 的保留、非等价 EEXIST、
  发送后的真实 ACK 超时、迟到 ACK，以及调用线程切换 namespace 后 socket
  仍作用于创建时的 namespace。
- 新增内核核实测试覆盖多条 IPv4 / IPv6 key、不同 metric、应用 generation
  保留、每个地址族一次 dump，以及空集合不请求内核。

真实内核测试现在六项通过，增加完整 RouteMgr 的规模 / 增量 / 清理检查。
WSL Linux 上 debug test binary 的本次测量如下（用于回归证据，不是生产 benchmark）：

| 路由数 | 初次 reconcile | 相同输入 10 次 | 替换一条 | 清理 |
| ---: | ---: | ---: | ---: | ---: |
| 100 | 2.08ms | 1.70ms | 0.22ms | 0.97ms |
| 1,000 | 13.38ms | 17.49ms | 1.72ms | 23.93ms |
| 10,000 | 131.90ms | 217.62ms | 21.95ms | 1,639.02ms |

断言确认：初次 N 次写入，相同输入无写入 / 无 inspection，替换一条仅一次
delete 加一次 add，停机清理所有条目。独立 socket dump 确认最终实际为空。
正常 run 稳态不调用这些重复 reconcile，只有输入更新或 pending deadline 才运行。

新增两项真实 TUN 测试后，八项内核测试全部通过。测试经过 VirtualNic 和实际
AsyncDevice / split IO 包装：丢弃元数据或只关闭 read half 仍保留 fd claim 和
kernel route；最后 writer 关闭后，nonpersistent TUN 及 route 自动级联删除，
manager 不再发出 delete。预先创建的 persistent TUN 则保持 interface / route，
TUNGETIFF 正确识别 attachment，manager 显式删除本方 route。

初次测试把 close 后立即读取 ifindex 当作同步屏障，出现了瞬时观测失败；已改为
两秒以内的只读 kernel dump + interface lookup 来核实实际回收，不添加生产路径
延时。fd ownership 结束和内核回收的并发观测应当区分。最终普通 route / DNS /
Host 合约 57 项通过，8 项 kernel 测试在隔离 fixture 中单独全部通过。

可重运行真实内核测试：

```sh
cargo test -p easytier --lib --offline --locked --no-run
# 使用上一步输出的实际 test binary 路径：
sudo -n sh easytier/tests/linux-route-kernel.sh \
  /absolute/path/to/target/debug/deps/easytier-<hash>
```

fixture 自身创建独立 network/mount namespace，并在私有 /dev 创建 TUN node；
只运行 kernel_ 测试。编译仍由普通用户完成，避免 root 改变工作树文件 ownership。

## 跨平台审查

平台 capability、实际 OS key / metric、借用 fd / VPN ownership 及迁移建议已
记录于 [平台边界](/home/luna/EasyTier-route/registry/docs/route-platform-boundary.md)。
Linux no-TUN / netlink-only 和 OHOS/mobile 不再提供没有设备 facts consumer 的
RouteHandle。默认 Host / DNS 12 项及无 TUN Host 5 项测试通过；最小 library
check 和本机 mobile cfg 编译通过。非 Linux backend 尚未迁移或在真实平台验证。

Registry core 的边界不变：只保存声明、管理 membership 并通知 invalidation。
平台 I/O、设备事实、反馈、retry、reconciliation 和 shutdown 都在路由领域层。
