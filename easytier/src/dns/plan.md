## 目标

将 `instance/dns_server` 重写为单独的 `dns` 模块，为如下的配置项提供支持：

```toml
[dns]
name = "localhost" # optional, replaces hostname, default to system hostname
domain = "localdomain" # optional, replaces tld_dns_zone, default to et.net

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

# this policy applies to the current zone block
[dns.zone.export] # if present, export this zone to connected peers
whitelist = ["*"]
blacklist = []

# same zone, but not exported
[[dns.zone]]
origin = "example.com"

forwarders = [
    "tcp://192.168.0.53:5353",
]
```

可能会支持的配置

```toml
[dns]
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
```

<details>
<summary><h2>计划和进展</h2></summary>

## protobuf

- `ZoneConfigPb`：包含所有 Zone 配置，以及一个 ID，该 ID 在读取 TOML 时生成
- `DnsConfigPb`：包含 `name`、`domain` 和需要广播的 `ZoneConfigPb`
- `DnsHeartbeat`: DnsClient 发送的心跳，包含：id、checksum、`Option<Snapshot>`
- `DnsSnapshot`: 所有 DnsServer 需要的配置，以及与上一次 Snapshot 之间的变化 `delta`

## DnsClient

对于每个实例，它启动时读取 TOML 配置，然后用这个配置启动一个 DnsClient ，它需要做到：

1. 启动时（配置更新时？）将 listeners 和 addresses 添加进 delta
2. 使用自己的 name 和 domain 创建一个专用 zone，让 name 指向自身 IP，并监听 IP 地址变化事件（为 DNS 一致性避免使用 127.0.0.1 作为 IP，若没有 IP 则不创建这个 zone）
3. 每次获得 PeerRouteInfo 时，读取其中的 dns 字段（和一些别的身份标记字段），这是个 protobuf message (DnsConfigPb)，保存了远程 Peer 的 dns 配置（不含 addresses 和 listeners），接收后它需要：
   1. 用远程配置中的 name 和 domain 创建远程 peer 的专用 zone，让这个 name 指向 peer 的 ip（这些 ip 是在 PeerRouteInfo 中的）
   2. 检查 2., 3.i. 中得到的 zone、PeerRouteInfo 报告的 zone、本机 TOML 配置中的 zone 是否有变化，如果有变化，将变化的 Zone ID 添加进 delta
4. 每隔一小段时间向 DnsServer 发送心跳，如果 delta 非空，发送 delta、当前配置的全量快照、checksum(checksum + delta)

## DnsServer

每个 EasyTier 实例都会启动一个 DnsClient，但是一台机器上的所有实例共享一个唯一的 DnsServer。
每个实例启动时：

- 尝试绑定一个预先给定的 SocketAddr（是个常数，目前是 MAGIC_DNS_INSTANCE_ADDR）监听 RPC 请求（一台机器上所有 EasyTier 实例一起尝试绑定该 SocketAddr，绑定成功的那个就启动 DnsServer（当然也启动 DnsClient），失败的那些就只有 DnsClient），另外这个启动 DnsServer 的操作其实是个循环，每隔一小段时间或者 DnsClient rpc 失败后立刻尝试 bind，如果 bind 成功就说明 DnsServer 真挂了，那就自己在这个已有的 SocketAddr 上启动 DnsServer（忽略启动失败），这样才能保证服务不断

DnsServer 需要做到：

1.  提供一个 RPC 接口接受 DnsClient 的心跳
2.  收到含有 delta 的心跳时，计算 checksum(local checksum + delta)，如果相等用 delta 更新本地配置，如果不相等就全量替换本地配置
3.  持续检查是否有过期（丢失心跳）的 DnsClient，需要把这些 DnsClient 提供的所有配置清除
4.  启动时自动添加 root zone，并把它的 forwarder 设置为系统 DNS
5.  使用 delta 更新 zone。不用合并同名 zone，直接用 Zone 结构体提供的 FallbackAuthority 按顺序插入 Catalog 就行，不过注意要先插入 InMemoryAuthority，这些都是 records，后插入 ForwardAuthority，这都是 forwarders
6.  更新 zone 的时候自动去掉 forwarder 中导致回环的那些，就是把 addresses 和 listeners 去掉（root zone 也需要这个逻辑）
7.  内部接口，控制 DnsServer 是否 bind 到某些 socket（也就是配置中的 listeners）
8.  Listeners 绑定失败打印日志（失败一个打印一次然后就跳过），即便这时 addresses 为空也不要停机。（否则释放 socket 绑定后会有 instance 抢占 socket 试图启动 server，然后就死循环）
9.  内部接口，更新 addresses，并且给 tun 添加删除这些 addresses 的路由。目前这些用来 hijack 的 addresses 都是只支持 udp 简单查询，就是一个 UDP 包查询，tcp 完全不管。但是可以支持除了 53 之外的端口，这个不难。
10. 启动时，往 packet pipeline 上挂一个 filter，和目前 magic dns 的操作一样，给 addresses 添加路由并劫持所有目的为配置中 addresses 的 UDP 包，直接作为 DNS request 读取并交给 DnsServer 解析（这个 addresses 可能还得 append 到 resolv.conf 之类的地方）
11. Addresses 和 Listeners 更新时需要检查所有 zone 的 forwarder，之前为了避免回环可能去掉了一些 forwarder，或者有新的 forwarder 要去除

此外，还有以下几个设计要点：

- Zone 允许只有 forwarder，这时候就是纯转发器
- Zone 允许没有 forwarder，这时候要检查是不是有 SOA 和 NS 记录，如果没有可能需要添加？

另外任何关于系统 DNS 的操作，清理都参考现有的 magic dns。

## 问题

- [ ] [minor] the ttl option isn't working because of https://github.com/hickory-dns/hickory-dns/pull/3450
- [minor] address 路由绑定必须在有 tun 的实例上做；listener 绑定则与 tun 无关，现有竞选机制无法保证有 tun 的实例能优先启动 DnsServer
  - 或许让 DnsClient 控制关于 address 的路由和 filter，并通过 RPC 转发 DNS 请求？有两个问题：DnsServer 必须得知 addresses 否则无法进行环路检测；多个 DnsClient 同时修改 resolv.conf 添加自己得 address 容易出问题
  - 或许不妨假设大多数情况下一台机器上所有实例的 no_tun 设置相同，这时候这个问题实际上不存在
- [minor] DnsServer 更新 zone 的时候需要更精细的合并/去重控制

## TODO

- [x] 配置解析
- [ ] 用 OSPF 传播需要广播的配置
- [ ] 用 DNS RPC 更新收到的配置，合并相同的域，延迟低的 peer 配置优先
- [ ] cli 输出状态

</details>

<details>
<summary><h2>Related Issues</h2></summary>

- related to https://github.com/EasyTier/EasyTier/issues/742
- related to https://github.com/EasyTier/EasyTier/issues/771
- related to https://github.com/EasyTier/EasyTier/issues/1071
- related to https://github.com/EasyTier/EasyTier/issues/1142
- related to https://github.com/EasyTier/EasyTier/issues/1322
- related to https://github.com/EasyTier/EasyTier/issues/1488
- related to https://github.com/EasyTier/EasyTier/issues/1597
- related to https://github.com/EasyTier/EasyTier/issues/1645
- related to https://github.com/EasyTier/EasyTier/issues/1764
- related to https://github.com/EasyTier/EasyTier/issues/1814

---

- (maybe) related to https://github.com/EasyTier/EasyTier/issues/937
- (maybe) related to https://github.com/EasyTier/EasyTier/issues/1873

</details>
