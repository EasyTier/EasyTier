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

The old `easytier/src/connector`, `easytier/src/peers`, and native
`peer_center` facade directories are deleted. They must not be recreated as
compatibility or test-only shells.

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
feature-flag derivation, ACL groups and secret-proof behavior. The only dynamic
peer fact retained by the native host is whether its OS public-IPv6 provider is
active, exposed through the narrow `PeerPublicIpv6State` Adapter.

The Go create schema is version 11. It submits the same URL-level listener
configuration as native and has no internal transport plan or
`environment.running_listeners` field.

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
