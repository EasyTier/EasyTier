# EasyTier Core Module Layout

> Status: implemented through S11 on 2026-07-18. Strict layer convergence
> remains incremental; residual edges are recorded below.

This document records the accepted re-plan of the `easytier-core` module
tree. The ownership refactor closed the core/native boundary; it did not
organize the inside of the core crate. The result is 23 flat top-level
modules with mixed layering, several reverse dependency edges, and domain
concepts split across unrelated modules. This plan reorganizes the crate
into explicit layers with physically nested directories. It changes no wire
behaviour and re-opens no ownership decision from
[`core_refactor_roadmap.md`](core_refactor_roadmap.md) or the ADRs.

The vocabulary follows [`CONTEXT.md`](../CONTEXT.md): Module, Interface,
Implementation, Seam, Adapter, Depth, Locality, Leverage, deletion test.

## Problems addressed

Found by a static audit on 2026-07-17 (four parallel source walks plus a
module-level dependency scan):

1. **Flat top level.** 23 modules in `lib.rs` mix four different strata:
   infrastructure (`task`, `runtime_time`, `token_bucket`, `compressor`,
   `stats_manager`), configuration (`config`, `runtime_config`), transport
   seams (`packet`, `socket`, `tunnel`, `listener`), and domain/instance
   features (the rest). `config.rs` (static schema) and `runtime_config.rs`
   (live store) differ by one prefix word while holding unrelated roles.
2. **Inconsistent `foo.rs` + `foo/` pairs.** `tunnel.rs` is a thin
   root-traits file; `instance.rs` is a 3370-line composition root next to
   its own directory; `packet.rs` (wire format) and
   `packet/udp_broadcast.rs` (L3 broadcast relay normalization) share no
   types and the latter has no in-core consumer.
3. **Domains split across modules.** UDP hole punching lives in three
   same-named files (`hole_punch/udp/*`, `instance/udp_hole_punch.rs`,
   `instance/udp_hole_punch/rpc.rs`) while the TCP binding stays inside
   `hole_punch/tcp/`. Public IPv6 is split three ways
   (`peers/public_ipv6.rs`, route hooks in `peers/route_trait.rs`,
   `instance/public_ipv6_provider.rs`). STUN is declared connectivity logic
   in `CONTEXT.md` but sits as a separate top-level module; UPnP port
   mapping sits in `hole_punch/udp/port_mapping.rs` while
   `StunInfoProvider::get_udp_port_mapping` lives in `stun/`.
4. **Reverse edges and cycles.** `socket/host/packet.rs` imports
   `crate::instance::PacketSink` (lowest seam depends on the composition
   root); `socket` also reaches up into `stun`, `listener`, and
   `hole_punch`; `peers` and `peer_center` import each other;
   `hole_punch/tcp/manager.rs` holds `Arc<PeerManagerCore>` while
   `peer_manager.rs` implements the hole-punch tunnel-sink traits;
   `connectivity/protocol/raw.rs` and `listener/transport.rs` form a cycle,
   and peer-admission (`impl AcceptedTunnelHandler for PeerManagerCore`)
   lives in the listener module.
5. **`socket/` is a host-capability grab-bag.** `socket/host/{dns,
   environment, packet}` and `socket/dns.rs` are Host Adapter seams (DNS,
   connector environment, packet sink), not sockets, contradicting the
   module documentation in `socket/mod.rs`.
6. **`instance.rs` god module.** 3370 lines: a 30-field struct, a ~310-line
   `new()`, dependencies on 14 of 23 top-level modules, ~25 management
   query facades, 43% tests, plus types owned by other domains
   (`UdpBroadcastRelayStats`, `AclWhitelistSnapshot`,
   `CredentialCreateOptions`, `MagicDnsResolverRegistration`,
   `ExternalListenerFactory`, `CoreStunDnsAdapter`) and a
   `prepare_listener_plan` that duplicates `listener::plan`.
7. **`proxy/` internals.** A vendored copy of `tokio-smoltcp` sits inside
   the module; four unrelated types are named "runtime"
   (`proxy/runtime.rs` traits, `udp_socket_runtime.rs`,
   `gateway/runtime.rs::GatewayModule`, `service.rs::CoreProxyRuntime`);
   `socks5.rs` and `socks5_protocol/` are two halves serving one consumer.
8. **Visibility hygiene.** `hole_punch` exposes `pub mod udp` solely for
   ~7 port-mapping traits; private modules declare unreachable `pub`
   structs; `CoreHostAdapters` transitively leaks types from ~10 sibling
   modules.

## Target layout

```text
easytier-core/src
├── lib.rs                    declares layer modules only
├── foundation/               L0 infrastructure; depends on no domain module
│   ├── task.rs               <- task.rs (PeerTaskManager)
│   ├── time.rs               <- runtime_time.rs
│   ├── token_bucket.rs       <- token_bucket.rs
│   └── stats.rs              <- stats_manager.rs
├── config/                   L1 configuration
│   ├── mod.rs                <- config.rs (static schema)
│   ├── gateway.rs            gateway and proxy runtime configuration
│   └── runtime.rs            <- runtime_config.rs (live store)
├── packet/                   L1 wire format
│   ├── mod.rs                <- packet.rs; udp_broadcast moves out
│   ├── compressor.rs         compression beside packet tail types
│   └── hole_punch.rs         UDP hole-punch wire codec
├── socket/                   L2 pure socket primitives: tcp/udp/ring/virtual + SocketContext
├── host/                     L2 Host Adapter seams (CONTEXT.md "Host capability")
│   ├── dns.rs                <- socket/dns.rs + socket/host/dns/
│   ├── environment.rs        <- socket/host/environment/
│   ├── packet.rs             <- PacketSink (instance/packet_io.rs) + socket/host/packet/
│   ├── socket/               <- socket/host/{factory,listener,udp}.rs + HostSocketRuntime
│   └── wasi/                 <- socket/host/wasi_* (WASI mechanism backend)
├── tunnel/                   L3 unchanged (already root-traits/dir-impls)
├── listener/                 L3 <- listener.rs + listener/{plan,transport}.rs in one directory
├── connectivity/             L4 connectivity domain (CONTEXT.md "Connectivity")
│   ├── manual/  direct/  protocol/  transport/  composite.rs
│   ├── stun/                 <- stun/ folded in
│   └── hole_punch/           <- hole_punch/ folded in
│       ├── tcp/   udp/       engines; udp/ gains binding.rs + rpc.rs (<- instance/udp_hole_punch*)
│       └── port_mapping.rs   <- hole_punch/udp/port_mapping.rs raised; generic P2P policy/BackOff raised
├── peers/                    L5 peer graph domain (files move unchanged)
│   ├── peer_center/          <- peer_center/ folded in (breaks the peers<->peer_center cycle)
│   └── public_ipv6/          <- three split locations gathered
├── rpc/                      L5 <- rpc_impl/ renamed; transport (client/server/bidirect/registry/packet)
│   └── standalone.rs           management-plane submodule
├── gateway/                  L6 packet-plane features (CONTEXT.md "Gateway dataplane", broadened)
│   ├── proxy/...             engines+services, cidr_*, wrapped_*; the four "runtime"s settle
│   ├── socks5/               <- socks5.rs + socks5_protocol/ merged
│   ├── smoltcp/              private smoltcp implementation subtree
│   │   ├── stack.rs          <- smoltcp_stack
│   │   └── tokio_smoltcp/    vendored async wrapper
│   ├── magic_dns.rs  dhcp.rs  vpn_portal.rs  udp_broadcast.rs
├── instance/                 L7 slimmed composition root
│   ├── mod.rs                construction + lifecycle (foreign types return to their owners)
│   ├── management.rs         <- the ~25 management query facades
│   ├── packet_plane.rs  runtime_driver.rs
│   └── wasi.rs               <- instance/host.rs + host/wasi.rs renamed (no clash with top-level host/)
└── process_runtime.rs        process-level CoreProcessRuntime stays top level
```

## Dependency rule

```text
foundation <- config/packet <- socket <- host <- tunnel
           <- listener/connectivity <- peers/rpc <- gateway <- instance
```

Modules should depend downward. The migration closed these scoped
counter-examples rather than hiding them behind compatibility re-exports:

| Current violation | Resolved by |
| --- | --- |
| `socket -> instance::PacketSink` | S3: PacketSink moves to `host/packet.rs` |
| `peers <-> peer_center` | S6: fold peer_center into `peers/` |
| `socket -> stun/listener/hole_punch` | S10-S11: `SocketListener` sinks to `socket/`, the STUN adapter stays in connectivity, and the hole-punch wire codec moves to `packet/` |
| peer tunnel-sink implementation in `peers` | S10: `impl TunnelSink for PeerManagerCore` moves to the hole-punch adapter side |
| `connectivity/protocol/raw <-> listener/transport` | S10: raw dialer/listener settle at the tunnel/listener layer |
| peer admission impl in `listener/transport.rs` | S10: moves to the peers side |
| `foundation/compressor -> packet` | S10: compressor tail types or the module settle at the packet layer |
| `foundation/stats -> rpc_impl::metrics` | S10: the RpcMetrics trait settles in `foundation` |
| `foundation/token_bucket -> peers::context::ByteLimiter` | S10: the ByteLimiter trait settles in `foundation` |

Enforcement is by convention plus
[`script/check-core-module-boundaries.py`](../script/check-core-module-boundaries.py):
`pub(crate)` by default with each layer's `mod.rs` declaring its outward
surface, and a source gate for the boundaries that have converged. Rust has
no package-level visibility; the compiler is not expected to enforce layers.

### Enforcement scope and residual edges

The S11 gate checks the clean foundation and packet layers, production socket
code, the host seam, the resolved config/listener/peers/gateway directions,
obsolete module paths, and the required physical layout. Its dependency-free
scanner ignores comments and literals, expands Rust `use` trees, and resolves
explicit `crate`/`self`/`super` paths. It remains a source gate rather than a
compiler-resolved dependency graph.

The following pre-existing upward edges remain explicit architecture debt and
are not presented as solved by this layout series:

- `config/runtime.rs -> peers` for peer runtime snapshots and peer-owned
  service configuration types;
- `tunnel/web_security.rs -> peers/secure_datagram.rs`;
- connectivity orchestration adapters in `direct`, `manual`, and
  `hole_punch` that still name `PeerManagerCore` or peer RPC implementations.

Removing those edges requires separate Interface extraction and composition
work, not visibility edits. A new upward edge still requires updating
`CONTEXT.md` and this plan first. Likewise, S11 does not mechanically rewrite
the crate-wide backlog of unreachable member-level `pub` declarations; it
narrows the moved module boundaries and keeps that larger cleanup separate.

## Migration series

Bottom-up, one independently verifiable series per step. Pure moves and
behaviour changes land in separate commits; the native crate and contrib
crates update their `use` paths inside the same series.

| # | Series | Closes |
| --- | --- | --- |
| S1 | `foundation/` pure move | flat infrastructure files |
| S2 | `config/` merge | config vs runtime_config confusion |
| S3 | `host/` seam + `socket/` reset | socket grab-bag, socket->instance edge |
| S4 | `connectivity/` folds stun+hole_punch; UDP binding/rpc settle and rename | three same-named files, TCP/UDP asymmetry |
| S5 | `listener/` single directory | listener.rs + listener/ mix |
| S6 | `peers/` folds peer_center + public_ipv6 | cycle, three-way split |
| S7 | `rpc/` rename + standalone submodule | rpc_impl mixing |
| S8 | `gateway/` domain: proxy cleanup, socks5 merge, tokio_smoltcp out, features gathered | four runtimes, vendored crate, flat features |
| S9 | `instance/` slimming: management.rs, foreign types home, listener planning returned | god module |
| S10 | scoped cycle breaking | reverse edges listed above |
| S11 | boundary visibility, physical layout, CI gate, and docs | asymmetric module visibility and regression prevention |

S1-S11 are implemented. The residual edges above are deliberately excluded
from that completion claim and require their own architecture series.

Each series runs the relevant rows of the validation matrix in
[`core_refactor_roadmap.md`](core_refactor_roadmap.md): native unit tests,
`wasm32-wasip1` default/no-default/all-features builds and tests, and the
`easytier-go-host` suite. Module path moves do not change the WASI ABI
(`extern "C"` symbol names are path-independent); the S9 move of
`instance/wasi.rs` still re-verifies the Go host suite explicitly.

## Non-goals

- Splitting `peer_ospf_route.rs` (4637 lines) or `peer_manager.rs` (4233
  lines) internally — a separate series after this layout lands.
- Generalizing the peer-flavoured `PeerId` out of the RPC transport.
- Moving the WS/WSS, QUIC, or WireGuard engines (settled by the roadmap's
  protocol dependency constraints).
- Any wire or behaviour change. This is structure plus cycle-breaking only.
