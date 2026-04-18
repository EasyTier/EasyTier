## 目标

将 `instance/dns_server` 重写为单独的 `dns` 模块，为如下的配置项提供支持：

```toml
[dns]
name = "localhost" # optional, replaces hostname, default to system hostname
domain = "localdomain" # optional, replaces tld_dns_zone, default to et.net

addresses = [
    "100.100.100.101:53",
] # optional, default to [ "100.100.100.101:53" ]
# any UDP packet or ICMP packet to these addresses will be hijacked by the dns server
# the server does *not* bind to/listen on these addresses!

listeners = [
] # optional, default to empty
# let the dns server bind to these addresses
# could be useful when no_tun = true

# these two options supersede accept_dns
# setting both of them to empty is equivalent to set accept_dns = false, but zones are still broadcasted

# this policy applies to all zones with origin "example.com"
[dns."example.com".import]
whitelist = ["*"]
blacklist = []
disabled = true # optional, whether to reject zones with this origin from connected peers, default to false
recursive = true # optional, apply this policy to all subzones, default to false

[[dns.zone]]
origin = "example.com" # required, name of the zone
ttl = 3600 # optional, default to 0
records = [
    "www 60 IN A 123.123.123.123",
    "app IN CNAME www",
] # optional, custom DNS records

forwarders = [
    "1.1.1.1",
] # optional, forward DNS requests to these servers

fallthrough = false # optional, whether to fall back to next zone (with same origin) if request doesn't match any record in this zone, default to true

# this policy applies to the current zone block
[dns.zone.export] # if present, export this zone to connected peers
whitelist = ["*"] # optional
blacklist = [] # optional

# same zone, but not exported
[[dns.zone]]
origin = "example.com"

forwarders = [
    "tcp://192.168.0.53:5353",
]
```

<details>
<summary><h2>计划和进展</h2></summary>

每个 peer 会默认拥有一个专用 zone，它的 origin 是这个 peer 的 fqdn，唯一的记录是指向该 peer 的 ip 的 A、AAAA 记录

## protobuf

- `ZoneData`：包含 Zone 配置，以及一个 ID，该 ID 在读取 TOML 时生成
- `GetExportConfigResponse` (`DnsExportConfig`)：包含全部 export 的 `ZoneData`（特别地，包含专用 zone）、该 peer 的 fqdn
- `HeartbeatRequest`: DnsNode 发送的心跳，包含：id、digest、`Option<Snapshot>`
- `DnsSnapshot`: 所有 DnsServer 需要的配置

## RoutePeerInfo

为预防用户提交大量自定义 DNS 记录导致 RoutePeerInfo 泛洪造成带宽压力：

- 在 `RoutePeerInfo` 中只保存本地 DNS 配置的 hash
- 收到 `RoutePeerInfo` 后读取其中 DNS 的 hash，若与本地不同，通过 RPC 拉取 Peer 的 DNS 配置

## DnsNode

1. - [x] 监听配置更新/IP 地址变化，重建快照
2. - [x] (`GlobalCtx` 的扩展 trait) 使用自己的 name 和 domain 创建一个专用 zone，让 name 指向自身 IP（为 DNS 一致性避免使用 127.0.0.1 作为 IP，若没有 IP 则不创建这个 zone）
3. - [x] 每次获得 RoutePeerInfo 时，读取其中的 dns 字段（和一些别的身份标记字段），这是远程 Peer 的 dns 配置（不含 addresses 和 listeners）的 digest
   - [x] 接收后检查 digest 和本地配置是否一致，如果一致，不做修改，否则标记 dirty，下一次心跳时将重建快照
4. - [x] 每隔一小段时间向 DnsServer 发送心跳和当前 digest： 
   1. 如果没有 dirty 标记，心跳不含 snapshot；
   2. 如果有 dirty 标记，重建 snapshot 并在心跳中包含；
   3. 如果 DnsServer 返回 resync，立刻重新发送带有 Snapshot 的心跳
5. - [x] 一个 RPC 接口，供 Peer 拉取 DNS 配置
6. - [x] 一个独立循环，用于选举 DnsServer，每次循环尝试绑定 DNS_SERVER_RPC_ADDR 监听 RPC 请求
   1. 一台机器上所有 EasyTier 实例一起尝试绑定 DNS_SERVER_RPC_ADDR，绑定成功的那个就启动 DnsServer（当然也启动 DnsNode），失败的那些就只有 DnsNode
   2. 每隔一小段时间或者 DnsNode 心跳失败（notify）后立刻尝试 bind，如果 bind 成功就说明 DnsServer 真挂了，那就自己在这个已有的 SocketAddr 上启动 DnsServer（忽略 bind 失败或启动失败，启动失败就直接释放 socket），这样才能保证服务不断

## DnsServer

1.  - [x] 提供一个 RPC 接口接受 DnsNode 的心跳，如果心跳 digest 和本地不符则返回 resync
2.  - [x] 收到含有 snapshot 的心跳时替换本地配置；如果 snapshot 中的 listeners 或者 addresses 不同则 rebind
3.  - [x] (`moka::Cache`) 持续检查是否有过期（丢失心跳）的 DnsNode，需要把这些 DnsNode 提供的所有配置清除
4.  - [x] 每次更新 zone 时自动添加 root zone
    - [x] (`Zone::system`) 并把它的 forwarder 设置为系统 DNS
5.  - [x] 使用 snapshot 更新 zone。不用合并同名 zone，直接用 Zone 结构体提供的 ChainedZoneHandler 按顺序插入 Catalog 就行，不过注意要先插入 MemoryZoneHandler，这些都是 records，后插入 ForwardZoneHandler，这都是 forwarders
6.  - [x] 更新 zone 的时候自动去掉 forwarder 中导致回环的那些，就是把 addresses 和 listeners 去掉（root zone 也需要这个逻辑）
7.  - [x] 内部接口，控制 DnsServer 是否 bind 到某些 socket（也就是配置中的 listeners）
8.  - [x] Listeners 绑定失败打印日志（失败一个打印一次然后就跳过），即便这时 addresses 为空也不要停机。（否则释放 socket 绑定后会有 instance 抢占 socket 试图启动 server，然后就死循环）
9.  - [x] 内部接口，更新 addresses。目前这些用来 hijack 的 addresses 都是只支持 udp 简单查询，就是一个 UDP 包查询，tcp 完全不管。但是可以支持除了 53 之外的端口，这个不难。
    - [x] 并且给 tun 添加删除这些 addresses 的路由
10. - [x] 启动时，往 packet pipeline 上挂一个 filter，和目前 magic dns 的操作一样，给 addresses 添加路由并劫持所有目的为配置中 addresses 的 UDP 包，直接作为 DNS request 读取并交给 DnsServer 解析
    - [x] 这个 addresses 可能还得 append 到 resolv.conf 之类的地方
11. - [x] Addresses 和 Listeners 更新时~~需要检查所有 zone 的 forwarder~~直接更新所有 zone，之前为了避免回环可能去掉了一些 forwarder，或者有新的 forwarder 要去除

此外，还有以下几个设计要点：

- Zone 允许只有 forwarder，这时候就是纯转发器
- Zone 允许没有 forwarder，这时候要检查是不是有 SOA 和 NS 记录，如果没有可能需要添加？
- 另一种方案是 DnsNode 挂 filter，自己处理 UDP 劫持，用某种方式（如 RPC）把 DNS 请求代理给 DnsServer，该方案的优势在于完全解耦 DnsServer 的实现，特别是解决了 DnsServer 所在实例可能 no_tun 的问题，缺点是：
  - 性能更差
  - 操作路由表或 /etc/resolv.conf 时会有多个 instance 同时修改，修改结果没有确定性
  - DnsServer 仍然需要得知 addresses 以进行回环检测
  - debug 更麻烦
  - 难以实现策略 DNS，比如不同来源的 DNS 请求走不同的 zone

另外任何关于系统 DNS 的操作，清理都参考现有的 magic dns。

## 已知但无需/无计划解决的问题

- the ttl option isn't working because of https://github.com/hickory-dns/hickory-dns/pull/3450
- [minor] address 路由绑定必须在有 tun 的实例上做；listener 绑定则与 tun 无关，现有竞选机制无法保证有 tun 的实例能优先启动 DnsServer
  - 不妨假设大多数情况下一台机器上所有实例的 no_tun 设置相同，这时候这个问题实际上不存在
- [minor] DnsServer 更新 zone 的时候需要更精细的合并/去重控制，如延迟低者/本地优先
- [minor] 更新 forwarder 时还需要检查间接回环，如 DNS 请求发送给某个 Peer，这个 Peer 又把请求转发回自己了
- [minor] 防止死锁/挂起的 DnsServer 占用 socket
- ~~[minor] RoutePeerInfo 可能不能过大~~
- [minor] 增量 Zone 更新
- DNS 策略

## TODO

- [x] 配置解析
- [ ] 重写 DNS 系统配置修改（参考 https://github.com/mullvad/mullvadvpn-app/tree/main/talpid-dns ？）
- [ ] 单元测试
- [ ] cli 输出状态

</details>

<details>
<summary><h2>Related Issues</h2></summary>

- closes https://github.com/EasyTier/EasyTier/issues/742
- closes https://github.com/EasyTier/EasyTier/issues/771
- closes https://github.com/EasyTier/EasyTier/issues/927
- closes https://github.com/EasyTier/EasyTier/issues/1071
- closes https://github.com/EasyTier/EasyTier/issues/1142
- closes https://github.com/EasyTier/EasyTier/issues/1322
- closes https://github.com/EasyTier/EasyTier/issues/1381
- closes https://github.com/EasyTier/EasyTier/issues/1488
- closes https://github.com/EasyTier/EasyTier/issues/1597
- closes https://github.com/EasyTier/EasyTier/issues/1645
- closes https://github.com/EasyTier/EasyTier/issues/1764
- closes https://github.com/EasyTier/EasyTier/issues/1814
- closes https://github.com/EasyTier/EasyTier/issues/1826
- closes https://github.com/EasyTier/EasyTier/issues/2004

---

- (maybe) related to https://github.com/EasyTier/EasyTier/issues/937
- (maybe) related to https://github.com/EasyTier/EasyTier/issues/1016
- (maybe) related to https://github.com/EasyTier/EasyTier/issues/1348
- (maybe) related to https://github.com/EasyTier/EasyTier/issues/1699
- (maybe) related to https://github.com/EasyTier/EasyTier/issues/1873

</details>
