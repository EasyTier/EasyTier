# EasyTier Core Ownership Finalization

This document is the current ownership contract after the portable-core
refactor. Earlier component documents remain useful design history, but this
file is authoritative when paths or intermediate facades disagree.

## Target boundary

`easytier-core` owns every portable state machine and its lifecycle:

- peer graph, sessions, routes, foreign networks, relay, credentials, ACL and
  statistics;
- manual/direct connectivity, endpoint discovery, TCP and UDP hole punching;
- STUN collection and projection;
- transport listener planning/runtime and the running-listener registry;
- public-IPv6 provider resolution, configuration-race retries, lifecycle and
  desired NDP state;
- TCP/UDP/Ring transport construction, UDP mux/session classification and
  portable proxy/VPN orchestration;
- configuration snapshots and task cancellation for those Modules.

The native `easytier` crate owns only:

- product configuration parsing and normalization into core snapshots;
- process-wide OS capabilities (`NativeHostRuntime`) and narrow instance Host
  Adapter facts (`NativeInstanceEnvironment`);
- concrete native protocol engines such as QUIC, WireGuard, WebSocket,
  FakeTCP and Unix streams;
- composition, management protobuf projection, UI/RPC presentation and real OS
  integration.

`cfg` remains valid for guest capabilities and native normalization. Core must
not perform a concrete host system call or infer the Go host OS from the WASI
target.

## Native Module map

| Role | Native location | Constraint |
| --- | --- | --- |
| composition | `instance/composition.rs` | Builds one core instance; no parallel manager ownership |
| normalized plan | `instance/config.rs` | Converts product config to immutable core snapshots |
| process Host Adapter | `host_runtime.rs` | Process-wide socket/DNS implementation; no `GlobalCtx` |
| instance environment | `instance/host.rs` | Instance facts only; no socket creation or I/O |
| listener Adapter | `instance/listeners.rs` | Creates requested Unix/FakeTCP sockets; no plan or lifecycle |
| management projection | `instance/management` | Converts core snapshots to protobuf; no domain manager construction |
| protocol engines | `tunnel/protocol.rs` and engine Modules | Upgrade a core TCP stream or UDP session; no connector policy |
| UDP port mapping | `instance/udp_hole_punch.rs` | UPnP/NAT-PMP lease Adapter only |
| public IPv6 platform | `instance/public_ipv6_provider.rs` | Linux observation and NDP/sysctl/netlink operations only; no provider state machine |

The old `easytier/src/connector`, `easytier/src/peers`, and native
`peer_center` facade directories are deleted. They must not be recreated as
compatibility or test-only shells.

`instance/config.rs` is the single native normalization boundary for core
snapshots and connectivity options. `instance/composition.rs` consumes those
values while wiring Host Adapters into one `CoreInstance`; it must not grow a
second set of ACL, STUN, proxy, listener, or connector policy builders.

Native utility facades are subject to the same rule. Packet types are imported
directly from `easytier_core::packet`, and IDN normalization plus its tests live
with core manual connectivity; native `tunnel/packet_def.rs` and
`common/idn.rs` must not be recreated as re-export or test-only Modules.
Portable tunnel framing is likewise imported directly from
`easytier_core::tunnel::framed`; native `tunnel::common` contains only concrete
socket behavior and native integration helpers. TCP/UDP data-plane behavior is
tested beside the core gateway runtime. Native gateway tests must cover real
Host Adapters or concrete engines instead of rebuilding a portable core test
through `GlobalCtx`.

Native protocol engines also import the core `Tunnel`, split stream/sink,
packet stream, error, and IP-version types directly. `easytier::tunnel` owns
only native protocol modules plus URL/scheme and OS-resolution helpers; it is
not a public forwarding namespace for the portable tunnel model.

The obsolete native `tx_throughput` benchmark was removed with the manager
facades it depended on. A replacement peer-graph or raw-transport benchmark
must be owned by `easytier-core`; a native benchmark may measure only a public
host-facing API or a concrete native protocol engine. Benchmark code must not
recover `PeerManager` or connector-manager access through `Instance`.

## Test ownership

Portable tests follow the same ownership boundary as production code. Runtime
snapshot updates, connector/listener lifecycle, source-proxy lifecycle,
wrapped destination sessions, listener-registry projection, cancellation and
multi-instance isolation are exercised through `CoreInstance` in
`easytier-core`. The portable host harness is `cfg(test)` and substitutes only
socket, DNS and packet-plane resources; it does not add production Interfaces
or bypass Module construction.

Native `instance/composition.rs` tests are limited to the native composition
root: normalized config and Adapter construction, concrete listener wiring,
and a vertical TCP listener connection. Product-config-to-core mapping is
tested directly beside `instance/config.rs`, rather than indirectly repeating
portable lifecycle tests through `GlobalCtx`.

The repository nextest archive includes both `easytier` and `easytier-core`.
Moving a behavior test into core must not silently remove it from CI, and a
concurrent behavior test must retain its required Tokio runtime flavor.

## Listener truth

`CoreInstance` accepts normalized listener URLs, IPv6 policy, and one
`SocketContext`. It derives the implicit Ring URL from the final peer instance,
classifies schemes from protocol and external resource capabilities, and owns
one `CoreListenerRuntime` for Ring, TCP, UDP-session, Unix, and FakeTCP
listeners. Required listeners, optional IPv6 shadows, retries, accept tasks,
rollback, events, and stop ordering therefore have one owner.

That runtime creates the only `RunningListenerRegistry`. Direct connectivity,
node snapshots, and proxy loop prevention read this registry. `GlobalCtx` may
mirror core events for presentation, but it does not receive a plan, manage
external listener tasks, or submit a second running-listener list.

`GlobalCtx` is likewise not a peer-policy store. Native configuration is
normalized once into `PeerRuntimeSnapshot`; core owns live relay preference,
feature-flag derivation, ACL groups, secret-proof behavior and public-IPv6
provider/lease/route policy. `GlobalCtx` receives public-IPv6 delta events for
native consumers but does not retain a queryable mirror of that state.
It also carries no STUN provider or projection: core constructs and owns the
slot, while deterministic native integration tests inject a provider only at
the `CoreInstanceAdapters` test seam.

The Go create schema is version 12. It submits the same URL-level listener
configuration and core public-IPv6 options as native. It has no internal
transport plan, `environment.running_listeners`, or host-supplied
`managed_ipv6s` policy field.

## Process-scoped portable state

`CoreProcessRuntime` is the only process-scoped portable owner. It currently
owns the Ring transport registry so core instances and one-shot connectors in
the same host process can rendezvous without exposing that registry to the
host. Native and in-process composition roots may create and share the opaque
runtime handle, but they must not construct, inspect, or replace its internal
managers. The WASI lifecycle ABI owns one runtime per instantiated module and
shares it across handles created in that module; an `Arc` is never passed
through the Go ABI. Separate WASM module instances have separate linear
memories and therefore use host TCP/UDP sockets, not Ring, to communicate.

Per-instance state still belongs to `CoreInstance`; process scope is reserved
for resources whose identity must be shared across instances. New portable
managers must not be added to `CoreProcessRuntime` merely to make composition
convenient.

## Socket and protocol seam

The host creates TCP, UDP and listener resources. Core/Tokio drives their
read/write/accept scheduling. Connector and listener Modules produce only a
raw core TCP stream, UDP session, or Ring transport. Native protocol engines
then upgrade those values to QUIC, WireGuard, WebSocket or other concrete
protocols.

`ConnectorRuntime` is the process capability Interface for external byte
streams, route probes, interface observations and preferred IPv6 source
queries. `NativeInstanceEnvironment` contains no runtime handle and cannot
perform those operations; it exposes only `SocketContext` and instance facts.
The runtime performs fresh interface observation. Core's per-instance
`ConnectorHostAdapter` owns the bounded observation cache, keys it by the full
socket context and coalesces concurrent refreshes only within that context.

The native protocol Adapter receives an immutable WireGuard configuration at
composition time. It does not retain `GlobalCtx` and cannot observe identity
changes halfway through a handshake.

## Public IPv6 provider seam

`PublicIpv6ProviderService` reads the core runtime snapshot and owns provider
resolution, stale-configuration retries, Disabled/Pending/Active state,
reconcile scheduling, state-change logging and shutdown cleanup. It derives an
optional `PublicIpv6NdpDesired` value; native does not reconstruct that state
machine. The same core-created `CorePublicIpv6Runtime` supplies provider and
lease state to the peer context and public-IPv6 service. It is passed as an
internal core dependency, never as a Host Adapter.

The native platform Adapter may inspect Linux forwarding, routes and
interfaces and apply NDP proxy entries. A separate narrow host sink emits the
existing lease and route delta events, without storing provider prefix, lease,
route, or active state in `GlobalCtx`. Direct connectivity asks
`PeerManagerCore` whether an IPv6 address is EasyTier-managed, so native and Go
environment snapshots cannot become a second policy authority. The platform
Interface has no start/stop, config retry, state resolution or policy methods.
Tests for the portable state machine live in core; native retains only Linux
selection, syscall/resource and vertical integration tests.

## Static deletion gates

The following searches must remain empty in native production code:

```text
crate::connector
crate::peers
RuntimeConnectorHost
GlobalCtx.*running_listener
get_conn_manager
ManualConnectorManager (native facade)
RuntimeListenerService
ListenerServiceGroup
runtime_listener_plan
TransportListenerConfig (native production)
RuntimePublicIpv6ProviderHost
PublicIpv6ProviderRuntimeState (native production)
reconcile_public_ipv6_provider_runtime
PeerPublicIpv6HostAdapters
impl PeerPublicIpv6State for GlobalCtx
impl PublicIpv6Runtime for GlobalCtx
GlobalCtx.public_ipv6_lease
GlobalCtx.public_ipv6_routes
GlobalCtx.advertised_ipv6_public_addr_prefix
GlobalCtx.public_ipv6_provider_active
GlobalCtx.stun_info_collection
HostConnectorEnvironmentSnapshot.managed_ipv6s
easytier/src/tunnel/packet_def.rs
easytier/src/common/idn.rs
easytier/src/common/acl_processor.rs
pub use easytier_core::tunnel::framed (native production)
pub use easytier_core::tunnel::{ (native production)
easytier/src/gateway/tests.rs
easytier/benches/tx_throughput.rs
runtime_core_instance_owns_* (native composition tests)
```

Direct imports from `easytier_core` are preferred over shallow native
re-export Modules.

## Verification gates

Before declaring the refactor complete, verify:

1. all `easytier-core` tests with all features;
2. `easytier-core` for `wasm32-wasip1` with all features;
3. native `easytier` unit-test compilation and selected Docker integration
   tests for TCP, UDP, WireGuard, QUIC and WebSocket;
4. Go host unit/race tests and the two-peer WASM route/packet exchange;
5. the static deletion gates above and the absence of OS calls in portable
   Modules.

Fine-grained Cargo feature slicing is intentionally deferred until these
ownership gates remain stable.
