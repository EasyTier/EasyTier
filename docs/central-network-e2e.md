# 中央网络管理 E2E 验证记录

## 范围与执行约定

- 被测 PR：`feat/web-central-console-v2`；初始代码提交：后端 `5f66627d`，前端 `57a15acb`。
- 测试日期：2026-09-30。先建立本清单，再逐项执行和回填结果。
- 主验证链路：真实浏览器 / HTTP API → 独立 SQLite 数据库 → Web 中央服务 → Docker 内真实 Core → 配置文件 / peer / route / 实际数据包。
- 数据面测试使用隔离 network namespace 和测试专属进程；不修改现有业务节点。
- `通过` 必须有实际执行证据；单元测试、mock 页面测试不能冒充真实 E2E。覆盖不完整标记 `部分通过`，环境障碍标记 `阻塞`，缺陷标记 `失败`，未执行保持 `待测`。
- 首轮只记录缺陷；用户随后批准修复，修复后的专项和受影响链路回归见下文，保留首轮失败证据。
- 本文记录中央网络相关功能；第三方 OIDC/验证码供应商、其他平台原生 GUI 不纳入本轮完整 E2E 承诺。

## 环境与复现入口

- 宿主机 Web：`cargo build -p easytier-web --features embed`，Docker `rust` 中 Core/CLI：`cargo build -p easytier --bins`；版本 `2.7.0-57a15acb`。
- `rust` 容器具备 root、TUN、iproute2、原生 wg、ping、Python。每次数据面测试创建独立 bridge 和四个 network namespace，清理时只删除本次资源。未修改容器全局 IP forwarding。
- 数据面复现：构建后在 `easytier-web/frontend` 执行 `node tests/central-coverage.mjs`。独立 SQLite、随机端口和进程日志保存在 `.test-env/central-e2e-*`。
- 真实 baseline 使用原 `central-e2e.test.mjs`，本次临时副本仅跳过重复构建并增加截图，结束已删除。

## 用例与结果

### 访问与运行模式

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| A01 | 登录与会话 | 真实浏览器登录，未登录访问中央接口被拒绝，登出后会话失效 | 通过 | 真实 Chromium 双账号登录；匿名与登出后中央接口 401。security results。 |
| A02 | 控制台元信息 | 用户名、配置服务器协议/端口、Gateway 开关/地址与启动参数一致 | 通过 | 真实 console-info 核对用户名、协议/端口及模式；Gateway启用/关闭的 peer_url 与 relay_data 均对照启动参数。 |
| A03 | 中央与 Console 模式隔离 | 外部 webhook 模式不暴露中央网络路由；原有内部 Full/Patch API 可用 | 通过 | 外部 webhook 模式中央 GET 404/POST 405；真实 Core internal Full/Patch、Web 重启与删除 TOML 通过。 |
| A04 | Gateway 启动参数校验 | 无 Gateway 时禁止创建 Gateway 网络；外部 webhook 与 Gateway 同时配置被拒绝 | 通过 | 无 Gateway 建网 400；webhook+Gateway、监听协议不匹配、非法地址启动 exit 2。 |
| A05 | 跨租户隔离 | 另一租户不能读写网络、成员、凭据、ACL、设备，也不能代理其节点 RPC | 通过 | 双租户网络/成员/配置/ACL/凭据/设备/在线代理 RPC 全部隔离；另一网络使用原凭据不能接入。 |

### 设备管理

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| D01 | 设备登记 | 真实 Core 使用登记命令连接，机器 ID、主机名、版本、在线状态可见 | 通过 | 隔离 netns 内三个真实 Core 登记，API 返回机器 ID、版本和在线信息。 |
| D02 | 设备展示 | 搜索、排序、列表/卡片、详情及设备所属网络正确 | 通过 | 独立真实浏览器：两 Core 的搜索、排序、列表/卡片、详情与所属网络；刷新一致。 |
| D03 | 别名 | 保存、清空、超长拒绝；刷新和服务重启后保持 | 通过 | 别名设置/清空/超长拒绝；真实 Web 重启后 Persisted Alias 仍在。 |
| D04 | 离线与重连 | Core 停止后显示离线但保留记录，重连后恢复在线且不重复登记 | 通过 | 真实停止/重启 Core，离线变更在重连后实际生效；设备不重复。 |
| D05 | 删除设备 | 移除设备及其成员关系、运行配置和引用；不封禁时允许重新登记 | 通过 | 真实删除并移除成员；非封禁删除后同 machine ID 重新登记成功。 |
| D06 | 封禁与解封 | 删除并封禁后拒绝重连，封禁列表记录尝试；解封后可重新登记 | 通过 | 删除封禁后重连尝试被记录；解封后真实 Core 重登记且不恢复旧成员。 |

### 网络生命周期

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| N01 | Gateway 网络创建 | 浏览器创建安全 Gateway 网络，真实成员连接到正确 Gateway | 通过 | 真实浏览器建安全 Gateway 网络；三个 TUN 成员实际 ping 互通。 |
| N02 | Manual 网络 | 指定自建真实 peer，配置下发后成功连接 | 通过 | 真实自建 A 作为 Manual peer；B 下发相同 URL 并实际 ping A。 |
| N03 | PublicServer 网络 | 使用隔离自建公开 peer 验证 URL 下发和连接，不依赖公网公共节点 | 通过 | PublicServer 指向隔离自建 A；Core 编译后 peer URL 一致并实际互通。运行配置通用表示为 Manual，不要求保留 UI 模式名。 |
| N04 | Standalone 网络 | 允许创建并下发，不自动配置外部 peer | 通过 | Standalone 保存后真实 Core peer_urls 清空，不自动连外部 peer。 |
| N05 | 基础设置与密钥 | 修改显示名、网络名、网段和网络密钥；成员运行配置随之更新 | 通过 | 显示名/网络名/密钥旋转实际 Core 配置收敛并恢复 ping；网段相关见 R03。 |
| N06 | 安全模式 | 安全/非安全网络均可组网，切换后重新收敛 | 通过 | 安全→非安全→安全均实际收敛，期间分别验证 ping。 |
| N07 | 模式切换 | Gateway 与其他模式切换，旧 Gateway 退出、新配置生效 | 通过 | 完整模式切换及实际 ping 通过；独立 unmanaged probe 验证切 Standalone 后旧 Gateway 断开且新连接被拒，切回 Gateway 恢复。 |
| N08 | 网络删除 | 在线/离线成员配置最终清除，删除最后一个网络不残留 Gateway | 通过 | 最后网络删除后在线/离线成员实例与 TOML 清除；独立 probe 确认旧 Gateway 断开且新 probe 无法接入，全程 Web 不重启。 |
| N09 | 非法及重复配置 | 空名字、错误 URL/CIDR、重复网络身份被拒绝且不破坏原配置 | 通过 | 修复后 Manual/PublicServer 在空网创建和已有成员更新时均拒绝 bogus://；合法 discovery 协议仍可保存。原缺陷与修复证据见 F01。 |
| N10 | 多网络汇总 | 同一设备加入两个网络，修改/删除其一不影响另一个 | 通过 | 同一 Core 两实例；删除第二网络后第一个实例保留且运行。 |

### 成员配置

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| M01 | 批量添加/移除 | 真实节点加入/离开；重复/不存在/跨租户设备的批量请求不部分提交 | 通过 | 三真实节点添加；重复 ID 409、部分未知/外租户 404，成员与实例均无部分提交；移除另见 D05/N08。 |
| M02 | 主机名与静态 IP | 设置和清空成员主机名、IP，运行节点反映修改；重复/越界 IP 被拒绝 | 通过 | 真实成员主机名/IP 设置与清空、重复/越界拒绝；配置生效后实际 ping 通过。 |
| M03 | 代理子网 | IPv4 子网配置、路由广播及转发一致；当前不支持的 IPv6 输入原子拒绝 | 通过 | IPv4 代理子网真实路由和 ping 通过；IPv6 输入保存前400，数据库及两Core TOML保持。原缺陷见 F02。 |
| M04 | 高级配置 | 读取、保存、重置覆盖配置；运行与持久化一致 | 通过 | 高级 MTU 1300 下发；读取覆盖、清空重置均经真实 API 验证。 |
| M05 | 中央所有权 | 高级配置不能覆盖中央身份、凭据、ACL；直接 REST/RPC 修改中央实例被拒绝 | 通过 | 独立实测伪造/清空 identity、secure_mode、managed_credentials、ACL 均保留中央值且 MTU 生效；真实 TOML/RPC 核对。直接 run/save/delete 与凭据写 RPC 均 409。 |
| M06 | 离线下发 | 设备离线期间修改/删除，重连后恢复最新完整配置 | 通过 | 离线修改主机名 → Web 重启 → Core 重连读到最新值并能 ping；baseline另验证离线删除 TOML。 |
| M07 | 并发操作 | 同时修改不同成员/网络，最终完整配置包含全部成功变更 | 通过 | 同时修改两个真实成员主机名，最终成员配置同时保留两次成功修改。 |
| M08 | 成员编辑竞态 | 迟到的 A 成员配置响应不能污染 B 成员表单和保存目标 | 通过 | route.fetch 取得真实 A 响应后延迟交付；切到 B，迟到响应未覆盖 B，PUT 与持久化目标均正确。 |

### 凭据及临时节点

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| C01 | 凭据生成与展示 | 生成、列表、复制/接入信息、TTL 和复用属性一致，刷新仍可查看 | 通过 | 真实浏览器生成一小时/nonreusable凭据；读取剪贴板核对 secret/CLI/TOML；刷新保持，执行复制命令成功接入。 |
| C02 | 多节点复用 | 两个真实临时 Core 使用同一 reusable 凭据，成员/凭据视图均展示 | 通过 | 真实 baseline 两个独立 Core 使用同一 reusable 凭据；成员和凭据页均展示两个 peer。 |
| C03 | 非复用约束 | 同一 non-reusable 凭据的并发连接受限 | 通过 | 两个真实 Core 共用不可复用凭据，仅一个身份进入管理员路由；停止赢家后另一节点接替。控制连接数量不是路由独占的判断标准。 |
| C04 | 撤销 | 撤销后既有连接断开且不能重新连接，视图清理 | 通过 | 真实 baseline 撤销后两 Core 断开，等待 6 秒仍不能重连，临时节点视图清空。 |
| C05 | 过期 | 短 TTL 凭据到期后连接被清理，不能再次接入 | 通过 | 15 秒 TTL 到期后实际远端路由移除；用同一凭据重启 Core，6.5 秒仍不能重连。 |
| C06 | 临时托管成员 | 临时成员收到专属凭据而非网络密钥，IP/子网与权限一致 | 通过 | 真实 TOML/credential grant 校验；临时 C→B 指定 ACL 允许而 A 被阻断；C 代理子网实际访问按 ACL 区分 A/B。 |
| C07 | 受引用与非法凭据 | 被成员引用的凭据不可单独撤销，非法 TTL/重复 ID 不破坏原状态 | 通过 | 被临时成员引用撤销 409；TTL 0/超一年 400、负值 422、重复 ID 409且原列表保持。 |

### ACL 策略

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| L01 | 编辑流程 | 浏览器新增、编辑、禁用、排序、删除规则，刷新后保持 | 通过 | 真实浏览器 ACL 新建、编辑、禁用、拖拽排序、删除；API 与页面刷新均确认持久化。 |
| L02 | 默认策略 | 真实数据包验证默认 allow/deny，而不只检查保存成功 | 通过 | 实际 ICMP：默认 allow 可达 → deny 阻断 → allow 恢复。 |
| L03 | 成员与组选择 | 真实安全组成员匹配，未授权成员不能借用另一成员权限 | 通过 | 实际安全成员组：指定 A→B 允许，未授权 C→B 被阻断。 |
| L04 | 协议与端口 | 实际 TCP/UDP/ICMP 流量验证允许/拒绝及端口范围 | 通过 | 五个真 echo 端口先确认存活；TCP 18080 通/18082 断；UDP 范围两端 18081、18082 通/18083 断；跨协议和 ICMP 另有实测。 |
| L05 | 子网目标 | 验证成员代理子网规则的编译和真实转发效果 | 通过 | IPv4 代理子网实际 ICMP；仅允许子网时节点 VIP 不可达；临时成员代理权限另独立实测通过。IPv6输入缺陷见 F02。 |
| L06 | 统计 | 产生流量后节点 ACL 统计可查询并对应命中规则 | 通过 | 产生 ping 后真实 ACL RPC stats 返回对应规则 ID、命中包和字节计数。 |
| L07 | 删除引用与非法规则 | 移除成员清理引用；错误选择器/端口被拒绝且旧策略保持 | 通过 | 真实 baseline 移除成员清理 ACL 引用；14 种非法规则全部 400，每次读回旧策略完全相等。 |

### WireGuard 管理

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| W01 | 启用与关闭 | 成员高级配置启用 WireGuard；关闭保留私钥和客户端，再启用恢复 | 通过 | 原生 wg 客户端实际流量：关闭阻断；服务端私钥和客户端保留；重新启用恢复。 |
| W02 | 客户端增删与清空 | 中央成员通过配置保存管理客户端；普通实例热更新同步持久化 | 通过 | 中央完整配置添加/清空；普通 Console 模式 RPC 添加/移除/清空，对照实际 Core、Web SQLite、TOML 与重启恢复。 |
| W03 | 真实 WireGuard 接入 | 原生 wg 客户端完成握手，通过隧道访问真实网络节点 | 通过 | 原生 Linux wg latest-handshakes 非零；通过 Portal 实际 ping 另一真实 Core。 |
| W04 | 地址/权限校验 | 重复/非法地址与未声明组被拒绝，已有有效客户端不受损 | 通过 | 中央配置重复地址/名称、非法IP、网络/广播/节点地址、未知组均400，原配置及流量保持；普通实例验证同前。见 F02。 |
| W05 | 撤销与重启持久化 | 移除客户端后不能访问；保留客户端在节点/服务重启后仍能接入 | 通过 | 原生 wg 清空客户端后实际 ping 被阻断；有效客户端跨 Core 重启可重新握手和访问。 |

### 运行详情与数据面

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| R01 | 节点详情 | 真实节点 peer、route、TOML、版本/错误等展示与 RPC 一致 | 通过 | 真实浏览器 peer/route IP/CIDR、连接计数、版本与 RPC 一致；导出 TOML 与真实 RPC 逐字相同。 |
| R02 | 日志级别 | 读取/设置真实节点日志级别并读回确认 | 通过 | 真实浏览器逐级设置六种日志级别、RPC读回与整页刷新回显均正确；省略字段显示Disabled，中文选项正确。见 F03。 |
| R03 | DHCP 全动态网络 | 两个全 DHCP 节点在无静态 IP 时分配不同地址并能互通 | 通过 | 三个全 DHCP Core 无静态成员，获得三个不同 10.126.126.x 地址并实际互通。 |
| R04 | DHCP 地址保持 | 已有地址节点暂时失去其他 IPv4 广播，不切回默认网段 | 通过 | 另独立验证 A DHCP 从 B 继承非默认10.88.99.1/24；停B、route只剩无IPv4 Gateway后，18秒9次读回均保留原地址。 |
| R05 | Gateway 同端口分流 | 管理连接和普通/Noise 组网连接共用端口，相互不串流 | 通过 | 同一 TCP端口承载三 Core 的配置登记及 Gateway secure/普通组网，切换安全模式后实际 ping 均通过。 |
| R06 | Gateway 中继开关 | 以只经 Gateway 的拓扑确认 relay_data 开关效果 | 通过 | 真实 Gateway 拓扑禁用成员 P2P；relay_data 开→ping通，重启关→ping断，重启开→恢复。 |

### 恢复与兼容性

| ID | 测试点 | 步骤 / 预期断言 | 状态 | 结果与证据 |
|---|---|---|---|---|
| P01 | Web 服务重启 | 网络、成员、凭据、ACL、Gateway 与设备别名恢复，运行配置不丢失 | 通过 | 真实 Web 重启恢复网络/成员/凭据/Gateway/别名及离线新配置；另保持 default deny 的 UDP 范围 ACL 重启，GET 完全相同且实际允许/拒绝均保持。 |
| P02 | Core 重启 | 持久化 TOML 恢复并与最新中央配置收敛 | 通过 | 真实 Core 重启后最新中央配置恢复；WireGuard 保留客户重新接入。 |
| P03 | 普通实例兼容 | 非中央实例已有保存/运行/停止及 WireGuard 操作保持可用 | 通过 | 外部 Console webhook 模式真实普通实例保存/启动/停止/重启/删除及 WG 热更新；核对 Web SQLite 与 Core TOML。 |
| P04 | HTTP 安全随机 | 普通 HTTP 无 randomUUID 时 ACL ID 和网络密钥仍用安全随机源 | 通过 | loopback HTTP 页面手动禁用 randomUUID，观测 getRandomValues；ACL ID 与密钥成功生成，新密钥落入真实 Core TOML。 |
| P05 | 浏览器交互补充 | 导航/刷新、暗色/多语言/移动端及错误恢复；明确区分真实 E2E 与 mock UI 测试 | 通过 | 真实中英/明暗/桌面移动布局、导航刷新及 Web 真停机→Retry→重启重登录恢复；另有16项mock UI补充。 |

## 执行记录与证据索引

首次执行 59 个功能条目：**55 通过、4 失败、0 待测**。当时失败的 N09、M03、W04、R02 归为下述三组发现；不把同一无效配置造成的后续失败重复计数。主数据面基线 22/22 通过不代表整体验收通过；审查补强和定向复测单独列出，未隐藏测试等待条件问题。

原始日志、截图、临时密钥/DB 和辅助脚本保留在本机忽略目录 `.test-env/`，不提交测试密钥和数据库。下表路径相对于仓库根目录；辅助报告中保留原 `/tmp` 来源路径，但其内容也已复制归档。

| 证据 | 最终执行 | 归档位置 |
|---|---|---|
| 主真实数据面 | 22/22 组通过 | `.test-env/central-e2e-2316549/results.json` 与各进程日志；复现脚本 `easytier-web/frontend/tests/central-coverage.mjs` |
| 审查后加强端口断言的主套件 | 21/22 通过；M02 等待条件修正后定向4/4通过 | `.test-env/central-e2e-2745102/results.json`；`.test-env/central-e2e-2971552/results.json` |
| 原真实 baseline | 1/1 通过，18.24 秒 | `.test-env/central-e2e-evidence-20260930/central-e2e-baseline-evidence/baseline.log`，3 张真实截图 |
| Dashboard mock 补充 | 16/16 通过，33.56 秒 | 同上 `dashboard.log`；此项不计为真实后端验证 |
| 访问/隔离/Console/非法 URL | 14 组通过，N09 失败 | `.test-env/central-e2e-evidence-20260930/central-security-e2e-vM8P3H/` |
| Gateway 在线生命周期 | 3/3 通过，Web PID 全程不变 | `.test-env/central-e2e-evidence-20260930/central-security-e2e-CY4Q6S/` |
| 非法 ACL | 14 个请求全部正确拒绝 | `.test-env/central-e2e-evidence-20260930/central-security-e2e-qw5Fsn/` |
| 凭据生命周期 | 1 综合场景通过，55.39 秒 | `.test-env/central-e2e-evidence-20260930/central-e2e-credential-evidence/` |
| 批次原子性/浏览器凭据复制 | 1 综合场景通过，6.46 秒 | `.test-env/central-e2e-evidence-20260930/central-e2e-batch-evidence/` |
| 同协议端口范围/非默认 ACL 重启 | 4/4 通过 | `.test-env/central-e2e-port-range-2757460/results.json` |
| 中央 override 所有权 | 2/2 通过 | `.test-env/central-e2e-evidence-20260930/central-security-e2e-eOCOeK/` |
| 临时成员真实包权限 | 3/3 通过 | `.test-env/central-e2e-temporary-2280549/results.json` |
| 非默认 DHCP 地址保持 | 1/1 通过，18 秒连续观察 | `.test-env/central-e2e-dhcp-hold-2439398/results.json` |
| 真实 UI/竞态/随机数/故障恢复 | 6/6 通过 | `.test-env/central-e2e-evidence-20260930/central-ui-e2e-YhcgUD/`，16 张截图 |
| 普通实例/WG/IPv6诊断 | 12/12 组通过 | `.test-env/central-e2e-evidence-20260930/central-security-e2e-F7VjL0/` |
| 中央 WG 非法配置 | 3 个非法请求均暴露 F02 | `.test-env/central-e2e-evidence-20260930/central-security-e2e-HvHrqo/` |
| 真实节点详情/日志级别 UI | R01 通过、R02 失败 | `.test-env/central-e2e-evidence-20260930/central-node-ui-e2e-5UwmgY/`，6 张截图 |

执行过程中修正过测试假设：CIDR 地址不能直接作为 ping 目标；连续配置发布后需等待实例收敛；protobuf JSON enum 返回名称且默认零值省略；Core 通用 peer 配置不保留 PublicServer UI 名称；切到 DHCP 需清除之前固定的成员 IP；Docker 创建的 600 权限 TOML 通过容器读取；不可复用凭据检查可路由身份而非物理连接数量。这些不是产品缺陷。早期数据面记录保留于 `.test-env/central-e2e-audit-*`、`.test-env/central-e2e-2067723/`，主套件完整正向基线使用 `2316549`，端口范围同时由 `2745102` 与独立 `2757460` 实测。`2745102` 的 M02 在地址已上报但路由尚未收敛时立即 ping 失败；脚本改为等待实际可达后，原步骤定向重跑 `2971552` 4/4 通过；IPv6 阻塞证据仍使用早期运行，并由独立 Core 请求复核。

## 首轮缺陷及修复状态

### F01：不支持的 peer 协议可保存并触发连续失败（已修复）

- **major / high confidence**；对应 N09。
- 有效网络已有真实 Core，PATCH 网络为 Manual，`peer_urls=["bogus://127.0.0.1:9999"]`。
- 实际 HTTP 200，SQLite 网络意图被替换；真实 Core 报 `unsupported core manual connector URL`。18 秒观察内有 292 次实例创建失败重试。
- 预期保存前拒绝并保持有效配置。根因入口 `easytier-web/src/central_network/compiler.rs:232`，目前仅检查 URL 能否解析。
- 证据：归档 `central-security-e2e-vM8P3H/results.json` 的 `N09-protocol` / `N09-runtime-evidence`，`central.log:1221` 起。
- `http://` 和 `https://` 是 Core 支持的 discovery connector，不在非法协议之列。

### F02：中央完整配置缺少 Core 可执行性校验（已修复已发现路径）

- **major / high confidence**；对应 M03、W04。属中央编译/发布边界的局部架构问题，不能把后续每次下发失败作为新 bug。
- 成员 PATCH `proxy_cidrs=["198.18.240.0/24","2001:db8:240::/64"]` 返回 200，但 Core 的代理网段转换只接受 IPv4；该设备 TOML 保持旧值，后续主机名/网络身份更新也不收敛。独立验证开启 IPv6 同样失败，移除 IPv6 网段成功，排除测试环境关闭 IPv6 的影响。
- 中央成员完整配置 PUT 分别加入重复 WireGuard IP、`virtual_ip="invalid-ip"`、`groups=["not-declared"]`，都返回 200；真实 Core 分别报 duplicate IP、parse error、unknown ACL group。三轮均从有效基线独立开始并恢复。
- 普通实例的 WG 客户端 PATCH 对上述非法输入会拒绝，且 Web DB/运行配置保持。因此普通热更新验证不能替代中央 Full 的验证。
- 证据：`.test-env/central-e2e-audit-1689346/` 的成员快照、DB 与旧 TOML；归档 `central-security-e2e-F7VjL0/results.json`；`central-security-e2e-HvHrqo/results.json` 和 `central-full-validation.log:29` 起。
- 修复已在中央编译阶段复用 Core 配置转换、可移植配置规范化和 Portal 客户端校验；Core 只开放原有纯校验函数。

### F03：日志级别页面回显错误（已修复）

- **minor / high confidence**；对应 R02；实际设置日志级别能够生效。
- 六个下拉选项显示翻译函数源码；初始 DISABLED RPC 返回 `{}`，页面误显示 Info；设置 WARNING 后 RPC 返回 `{"level":"WARNING"}`，重开详情显示 Loading。
- 两处局部问题：`easytier-web/frontend/src/components/NetworkDetail.vue:456-463` 使用函数作为 option label；`easytier-web/frontend/src/modules/api.ts:457-463` 未转换 protobuf 字符串枚举且零值默认不正确。
- 证据：归档 `central-node-ui-e2e-5UwmgY/results.json` 的 R02-initial/options/after-set/reopen 与四张 R02 截图。修复后六级设置、刷新和翻译均经真实浏览器与 RPC 重新验证。

## 修复回归（2026-09-30）

**当前清单 59 项均为通过，0 项待测、0 项未关闭缺陷。** 原55项的证据保留；本次重跑受影响的主数据面、原浏览器生命周期及专项，未声称将首轮所有独立脚本再执行一遍。

- 后端：在数据库写事务开始前的中央 `compile()` 里检查候选配置。网络级 URL 复用 Core 支持规则，覆盖无成员的网络；成员配置先合并中央字段与 override，再执行 Core 转换及 Portal 客户端校验。失败返回400，旧数据库和运行状态不变。
- Core：只公开现有 `validate_manual_url`、`validate_clients`，没有改变实例运行逻辑、增加 RPC 或读取远端设备状态；不执行主机能力校验。
- 前端：protobuf 日志枚举转换为数字，省略字段对应 Disabled=0；下拉项使用随语言更新的翻译字符串。
- IPv6 代理子网按当前 Core 转换能力拒绝，本轮未扩展 IPv6 代理功能。

| 回归 | 结果 | 本机证据 |
|---|---|---|
| 后端完整测试 | 232/232 通过，含协议/成员配置/事务不变回归 | `.test-env/central-fix-20260930/central-fix-web-tests.log` |
| 前端构建与 Web embed 构建 | 通过 | `.test-env/central-fix-20260930/central-fix-web-build.log` |
| Dashboard 浏览器回归 | 17/17 通过，含日志枚举专项；mock API | `.test-env/central-fix-20260930/central-fix-dashboard.log` |
| 真实主数据面 | 22/22 通过 | `.test-env/central-e2e-6121215/results.json` |
| 原真实浏览器生命周期 | 1/1 通过，15.92 秒 | `.test-env/central-fix-20260930/central-fix-baseline.log` |
| 配置拒绝与原子性专项 | 14/14 通过 | `.test-env/central-validation-6182364/results.json`；脚本 `easytier-web/frontend/tests/central-validation.mjs` |
| 真实日志级别 UI/RPC | R01/R02 均通过；六级逐次设置、刷新、中文选项 | `.test-env/central-fix-logger-20260930/evidence/results.json` |

专项的12个非法请求均返回400：对照3张中央意图表完整行、网络与成员配置、两个真实 Core 的 `show_node_info` TOML，全部不变；拒绝期间每条连续15个 ping，共180包零丢包。合法 HTTP/HTTPS/TXT/SRV × Manual/PublicServer 共8次空网保存成功；IPv4代理路由/实际ping、有效WireGuard客户端和清空均通过。

原 baseline 最初在旧断言“IPv6代理保存200”处失败，这正是本次修复改变的行为。现改为先断言IPv6返回400，再用受支持的IPv4代理子网完成浏览器ACL流程，重跑通过；旧输出保留在 `central-fix-baseline-old-expectation.log`，不计为新的产品回退。

### 覆盖边界

- 本轮覆盖所列中央管理功能在 Linux + Chromium + TCP Gateway 下的真实链路；不据此声称所有操作系统、浏览器、底层传输协议组合或长时间压力场景均通过。
- PublicServer 使用隔离自建真实 peer；外部 Console 仅模拟第三方 webhook 的 validate-token 响应，其 Web、Core、SQLite、Full/Patch 路径真实执行。
- HTTP 随机数用例在 loopback origin 手动禁用 randomUUID，实际调用 getRandomValues；不冒充公网非安全 origin 的浏览器兼容矩阵。
- 所有测试专属 Web/Core、bridge 和 network namespace 均已清理；保留忽略目录证据。修复只涉及中央编译器、Core 校验函数可见性、日志页面及回归测试；未修改 ClientManager，未 push。
