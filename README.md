# EasyTier

```diff
! NOTICE: THIS SOFTWARE IS STILL BEGIN DEVELOPPING, ONLY POC VERSION IS PROVIDED
```

A simple out-of-box alternative of ZeroTier & TailScale in rust. Bring all devices to one virtual net.

this software can serve as a substitute for Zerotier or TailScale in certain scenarios due to following features:

1. Easy to deploy. 

    No roles (moons/derp or other dedicated relay server). All nodes are equal and rely on some p2p algorithms to communicate.

2. Smart route decision.

   Use links charged by traffic to reduce latency but free links for high throughout app.

3. Break the UDP throttling.

   Try use TCP to achieve better performance under enviraonment with throttled UDP. Also use some methods to avoid HOL-blocking of TCP over TCP.

4. High availibility.

    Support multipath and switching to healthy paths when high packet loss rate or network error are detected

EasyTIer also have following common features which are already supported by other softwares, but may be easier to use.

1. Multi-platform support.

2. Effcient P2P hole punching, both UDP & TCP.

3. High performance. Try use multiple wan interface.

5. Subnet Route. node can advertise and proxy one or more subnets, so other nodes can directy access these subnets without any iptables/nft trickys.


# Usage

Currently a server with public ip is needed.

run first node on the public node:

```
sudo easytier-core --ipv4 <VIRTUAL_IP>
```

run other nodes

```
sudo easytier-core --ipv4 <VIRTUAL_IP> --peers tcp://<public_ip>:11010
```

use cli tool to inspect nodes with direct link.

```
easytier-cli peer
```

cli tool can also be used to inspect the route table

```
easytier-cli route
```


# RoadMap

- [x] Windows / Mac / Linux support
- [x] TCP / UDP tunnel.
- [x] NAT Traverse with relaying.
- [x] NAT Traverse with UDP hole punching.

- [x] Support shared public server. So users can use it without a public server.
- [x] Broadcast & Multicast support.
- [ ] Encryption. With noise framework or other method.
- [ ] Support mobile platforms.
- [ ] UI tools.
