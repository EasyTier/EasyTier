# Tunnel Ownership Closure

> Status: historical TCP/UDP/Ring closure snapshot. Updated 2026-07-13.
> [`CONTEXT.md`](../CONTEXT.md) defines the authoritative final ownership for
> concrete Tunnel Modules.

## Result

`easytier-core` is the sole owner of the portable TCP, UDP, and Ring Tunnel
implementations. The native `easytier` crate supplies real socket Adapters and
concrete protocol engines; it no longer defines a parallel connector/listener
abstraction or native raw Tunnel implementation.

The production peer-connectivity pipeline is:

```text
network manual / direct / TCP hole-punch / UDP hole-punch
  -> ConnectedTransport (TCP socket/byte stream or UDP session)
  -> protocol upgrader
  -> easytier_core::tunnel::Tunnel
  -> core peer admission

network host listener
  -> AcceptedTransport (TCP socket/byte stream or UDP session)
  -> protocol upgrader
  -> easytier_core::tunnel::Tunnel
  -> core peer admission

core Ring registry / listener
  -> easytier_core::tunnel::RingTunnel
  -> core peer admission
```

No production connectivity state machine in `easytier` combines resource
creation with protocol upgrade or peer admission.

## Ownership Map

| Responsibility | Owner | Boundary |
| --- | --- | --- |
| TCP framing and raw TCP Tunnel construction | `easytier-core` | `TcpTunnelUpgrader`, `TcpTunnelDialer`, `TcpTunnelListener` over injected virtual TCP sockets |
| UDP mux, session classification, lifecycle and raw UDP Tunnel construction | `easytier-core` | `UdpSessionLayer`, `UdpSessionSocketListener`, `UdpTunnelUpgrader`, `UdpTunnelDialer`, `UdpTunnelListener` over injected virtual UDP sockets |
| Ring transport, registry and Tunnel construction | `easytier-core` | core Ring socket/listener/dialer and `RingTunnel` types |
| Network manual/direct/hole-punch orchestration | `easytier-core` | returns `ConnectedTransport`; protocol selection and admission remain core-owned |
| Network listener lifecycle and admission orchestration | `easytier-core` | accepts `AcceptedTransport`; Host Adapters only realize requested resources |
| Real Tokio TCP/UDP/Unix/FakeTCP resources | native `easytier` | `RuntimeTcpSocket`, `RuntimeUdpSocket`, factories and platform bind helpers implement core socket Interfaces |
| QUIC and WS/WSS protocol engines | native `easytier` | narrow protocol-upgrade Adapters consume established streams or core UDP sessions |
| WireGuard protocol engine | migration from native to `easytier-core` | target ownership is core; the native engine recorded by this snapshot is temporary debt |
| FakeTCP and Unix | native socket resources | Host Adapters produce a virtual TCP socket or byte stream; core owns portable framing |
| Go-owned sockets, DNS and host policy | `easytier-go-host` | opaque handles implement the same core Host Adapter requests; core/Tokio initiates I/O |

Native protocol-specific standalone dialers/listeners may remain for tests,
the web entry point, or VPN portal composition. They implement the core
`TunnelDialer` / `SocketListener` contracts and reuse the same protocol
upgrade helpers. They are not a second manual/direct/hole-punch orchestrator
and do not own raw TCP, UDP, or Ring Tunnel implementations.

## Deleted Native Ownership

The closure removed:

- `easytier/src/tunnel/tcp.rs`;
- `easytier/src/tunnel/udp.rs`;
- `easytier/src/tunnel/ring.rs`;
- `easytier::tunnel::TunnelConnector`;
- `easytier::tunnel::TunnelListener`;
- `easytier::tunnel::TunnelConnCounter`;
- test-only `CoreTunnelDialer` / `CoreTunnelListener` wrappers;
- the `easytier-web` legacy listener wrapper.

Rust source compatibility for these paths is intentionally not retained.

## Invariants

1. Hosts create and authorize real sockets; core describes bind/dial policy
   and never performs native OS calls.
2. Core owns TCP/UDP/Ring framing, UDP session mux/classification, connection
   lifecycle, retries, protocol selection and peer admission.
3. Network manual, direct and hole-punch connectors stop at an established byte
   stream or UDP session. A protocol upgrader is the only layer that creates a
   network protocol Tunnel. Ring is core-local and directly creates a core
   Ring Tunnel.
4. Native QUIC/WS/WSS engines do not move surrounding connectivity policy back
   into `easytier`; WireGuard's target owner is core.
5. Listener and session workers are cancelled with their owning listener; an
   accepted UDP session keeps its core layer alive only for its own lifetime.
6. Host-OS choices such as reuse, marks, devices and netns are request data and
   Host Adapter behavior, not `wasm32-wasip1` target inference.

## Verification

The ownership deletion checks are:

```bash
test ! -e easytier/src/tunnel/tcp.rs
test ! -e easytier/src/tunnel/udp.rs
test ! -e easytier/src/tunnel/ring.rs
! rg '\b(TunnelConnector|TunnelListener|TunnelConnCounter|CoreTunnelDialer|CoreTunnelListener|LegacyTunnelListener)\b' \
  easytier easytier-core easytier-web --glob '*.rs'
```

The closure was verified with `easytier` and `easytier-web` checks; core-trait
WS/WSS, QUIC, WireGuard, Unix and root FakeTCP ping-pong tests; core UDP session
listener tests; runtime IPv4/IPv6 hole-punch forwarding tests; and the existing
TCP/UDP multi-node scenarios. The final validation matrix remains the one in
[`core_refactor_roadmap.md`](core_refactor_roadmap.md).

## Follow-up Boundary

Feature slicing and dependency-size work may now remove optional protocol
engines, but it must not recreate native raw Tunnel owners or compatibility
traits. QUIC and WS/WSS remain behind narrow native upgrade Adapters to preserve
their current dependencies and wire behaviour. WireGuard is explicitly being
migrated to core; FakeTCP and Unix remain Host socket transports rather than
protocol engines.
