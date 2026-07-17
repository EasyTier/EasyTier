# EasyTier Architecture Context

## Purpose

This document defines the domain language and ownership rules for the ongoing
EasyTier core refactor. New plans, code, tests, and reviews should use these
terms consistently.

The north star is a single `easytier-core` crate that owns almost all portable
EasyTier logic. Native EasyTier and a Go wasm host provide platform capabilities
through Adapter seams. `easytier-core` must compile for `wasm32-wasip1` and must
not perform real OS networking, DNS, TUN, file-system configuration, process, or
service-manager operations.

## Domain language

### Core

The portable EasyTier implementation in the single `easytier-core` crate. Core
owns protocol state, peer state, routing decisions, connection orchestration,
packet processing, and lifecycle rules that do not require direct OS calls.

Core may use `cfg` for guest-target capabilities. Host-OS policy must arrive as
configuration because a wasm guest sees `target_os = "wasi"`, not the OS that
runs the Go host.

### Module layers

Inside the crate, modules are grouped into layers that may only depend
downward:

`foundation <- config/packet <- socket <- host <- tunnel <-
listener/connectivity <- peers/rpc <- gateway <- instance`

- `foundation/` holds infrastructure with no domain dependency (task
  supervision, time facade, rate limiting, and stats).
- `packet/` owns wire types plus packet compression and control-packet codecs.
- `config/` holds the static configuration schema and the live runtime
  configuration store.
- `host/` is the single home of every Host capability seam; `socket/`
  keeps only socket primitives.
- `connectivity/` contains the whole connectivity domain, including STUN
  and hole punching.
- `peers/` contains the peer graph, the peer center, and public IPv6.
- `rpc/` is the peer-flavoured RPC transport plus the management-plane
  standalone server.
- `gateway/` contains the Gateway dataplane and the other packet-plane
  features.
- `instance/` is the slim composition root.

Modules are `pub(crate)` by default; each layer's `mod.rs` declares its
outward surface. The full layout and migration series are recorded in
[`refactor-doc/core_module_layout.md`](refactor-doc/core_module_layout.md).
The layer order is the target direction. CI enforces the boundaries already
converged by the layout series; explicitly recorded residual upward edges are
architecture debt, not patterns for new dependencies.

### Core instance

One independently configured and independently stopped EasyTier network
instance. A core instance is the authoritative owner of its peer graph,
connectivity state, listener state, route state, proxy state, task lifecycle,
and runtime configuration.

`CoreInstance::new(CoreInstanceConfig, CoreHostAdapters)` is the sole public
construction Interface. Hosts supply one normalized configuration and their
platform capabilities; core validates them and constructs its peer graph,
runtime store, STUN, listeners, packet plane, proxy state, and lifecycle
Modules. Native and WASI composition roots must not construct or inject those
portable managers through alternate instance entry points.

Process-global registries must not contain instance-specific state.

### Host

The program that embeds or runs core and owns platform resources. There are two
primary hosts:

- the native `easytier` crate;
- a Go program embedding a `wasm32-wasip1` artifact, initially through wazero.

### Host capability

A platform operation core is allowed to request but not implement directly.
Host capabilities include DNS, real TCP and UDP socket creation and system
calls, TUN or packet ingress and egress, platform route changes, persistent
storage, clock/random facilities when not supplied by WASI, and platform-policy
discovery.

Inside core, every Host capability seam lives in the `host/` module: DNS,
connector environment, packet sink, socket factories, and the WASI mechanism
backend.

### Host Adapter

A concrete native or Go implementation of host capabilities at a seam owned by
core. The native and Go implementations are the two real Adapters that validate
the seam.

### Process host runtime

The process-level implementation of stateless or shared platform capabilities.
Native TCP/UDP creation, listeners, DNS, Unix/FakeTCP resources, route probes,
and request-scoped connector interface discovery use one shared runtime. The
runtime must not capture an instance `GlobalCtx`, netns, socket mark, or mutable
connectivity state.

Instance differences are request data. `SocketContext` carries IP-family policy,
an optional exact socket mark, and an opaque netns token. The host interprets
those values only while performing the requested OS operation.

### Instance host projection

A narrow view of facts belonging to one core instance, such as mapped/running
listeners, protected ports, managed addresses, and collected interface/public
address observations. It may retain a native instance composition object, but
it is not a socket factory, DNS resolver, or portable state owner. Real OS
operations delegate to the process host runtime with explicit request context.

### Socket

A host-authorized communication endpoint below EasyTier protocol framing. A
socket may represent TCP stream I/O, peer-scoped UDP datagrams, an in-process
ring, or another raw transport shape.

Core owns the socket Interface, I/O scheduling, backpressure, and socket
orchestration. The host authorizes and creates the real endpoint, owns its
platform resource, and executes OS operations through a Host Adapter or WASI.
Host-backed I/O does not imply host-owned I/O scheduling or protocol state.

### Tunnel

An EasyTier packet connection produced by applying framing, metadata, and any
protocol handshake to a socket. Peer admission consumes a tunnel; network
dial, listener accept, and hole punching produce sockets or UDP sessions. Ring
stays entirely inside core and may produce a Ring Tunnel directly.

Core owns raw TCP and UDP Tunnel construction, TCP framing, UDP mux/session
classification and lifecycle, and Ring Tunnel/registry state. A native
protocol engine may perform an unavoidable non-WASI handshake behind an
upgrader Adapter, but it is not a second raw Tunnel owner.

Each concrete Tunnel protocol is an atomic Module: its client and server
upgrade, handshake, framing, protocol configuration, lifecycle and protocol
tests belong to one crate. Splitting those responsibilities between core and
native is forbidden. The target ownership is TCP, UDP and Ring in core, with
WebSocket/WSS, QUIC and WireGuard in native because their current dependencies
cannot provide the required WASI implementation without changing wire
behaviour or modifying third-party protocol engines during this refactor.
FakeTCP and Unix are Host socket transports rather than distinct EasyTier
Tunnel Modules: they produce a virtual TCP socket or byte stream that core
wraps with its portable framing.

### Listener runtime

The per-instance Module that turns normalized listener URLs into Ring, TCP,
UDP-session, or external socket listeners. Core owns scheme classification,
implicit Ring identity, IPv6 shadow policy, required-versus-optional startup,
retry, accept scheduling, the running-listener registry, and orderly shutdown.

The host supplies real TCP/UDP factories and, where needed, a narrow external
listener factory for Unix or FakeTCP resources. That Adapter advertises resource
capabilities and creates one requested `SocketListener`; it does not receive a
listener plan, handler, event sink, or lifecycle responsibility.

### Connectivity

The logic that decides how and when to obtain a socket for a peer. It includes
manual reconnect, direct candidate selection, TCP and UDP hole punching,
blacklists, retry/backoff, listener reuse, and task lifecycle.

Connectivity belongs in core. STUN codec, probing, retry, NAT inference, public
endpoint state, port mapping, and lifecycle are connectivity logic and also
belong in core. DNS resolution, real socket creation, UPnP, NAT-PMP, interface
enumeration, netns, socket marks, and bind-device operations belong to Host
Adapters.

### Peer graph

The authoritative set of peers, peer connections, next hops, routes, sessions,
relay state, and foreign-network state for a core instance. The host may present
or cache snapshots but must not maintain a second source of truth.

### Foreign network

A peer graph projected for a different network identity and relayed through the
current core instance. Core owns foreign-network admission, identity and
credential checks, relay policy, per-network peer state, routes, traffic state,
task lifecycle, and management snapshots. A Host Adapter may create
platform-backed connector resources, persist credentials, and project events;
it must not decide whitelist, relay, connection-limit, or feature policy.

### Native peer facade

The small native Module that assembles peer Host Adapters and translates native
management models. It is not a peer graph owner. The deletion test for this
Module should leave only composition and presentation work at callers; routing,
admission, relay, lifecycle, and packet decisions must not reappear there.

### Gateway dataplane

The portable packet classification, proxy/NAT state, header transformation,
session lifecycle, and forwarding decisions used by gateway features. These
belong to core. Transparent-destination lookup, raw sockets, TUN, netns, real
listeners, and concrete KCP/QUIC engines remain Host Adapter implementations
when they require platform or non-WASI dependencies.

The named deep gateway Modules are:

- `WrappedTcpDestinationPlanner`, which owns CIDR/group mapping, loop and
  listener policy, self/no-TUN rewrite, ACL chain selection, and first-packet
  planning for KCP and QUIC Adapters;
- the portable SOCKS protocol Module, which owns wire framing, authentication,
  command and DNS sequencing, TCP copying, UDP association lifecycle,
  transport choice, entry/session state, and peer-packet routing;
- `VpnPortalClientTable` and `VpnPortalClientSession`, which own client
  identity, replacement-safe registry lifecycle, packet validation, and
  dispatch independently of the concrete WireGuard engine.

A native channel or smoltcp pump that only composes these core Interfaces with
real resources is Adapter glue, not a second policy owner. Do not move it
behind a shallow wrapper merely to relocate lines.

The `gateway/` module also hosts the other instance-level packet-plane
features: DHCP IPv4 allocation, magic DNS, the VPN portal server Module, and
UDP broadcast relay normalization.

### Runtime configuration

The normalized configuration consumed by core. Native TOML, CLI flags, web
configuration, and Go configuration are input formats; they are not
authoritative runtime state after a core instance starts.

Platform defaults are resolved by the host before or while producing runtime
configuration.

### Native composition root

The thin `easytier` layer that loads native configuration, constructs Host
Adapters, creates a core instance, and presents native management interfaces.
It must not reconstruct core routing or connectivity decisions.

## Ownership map

| Area | Core owns | Host owns |
| --- | --- | --- |
| Configuration | normalized state, validation, defaults independent of host OS | input parsing, persistence, host-OS default selection |
| Peers | peer graph, admission, sessions, RPC dispatch, routing | presentation and external persistence |
| Connectivity | candidates, retries, backoff, blacklists, hole-punch state, STUN protocol/state/NAT inference | DNS, real sockets, UPnP/NAT-PMP, platform policy and interface facts |
| Socket | Interface, I/O scheduling, backpressure, requests, listener planning/lifecycle, peer-scoped UDP session logic | creation policy, OS handles, syscalls, readiness mechanism, external Unix/FakeTCP listener resources |
| Tunnel | portable framing and protocol logic | non-portable protocol engines only when unavoidable |
| Packet plane | classification, transformation, proxy/NAT state | TUN/raw socket ingress and egress |
| Gateway | wrapped destination policy, SOCKS protocol/session state, VPN portal client state | concrete engines, real listeners/sockets, netns, product events/configuration and RPC presentation |
| Lifecycle | core task ownership and orderly shutdown rules | process lifecycle and hard-kill watchdog |
| Time/random | portable Tokio/WASI use by default | replacement only when a host contract requires it |

## Architectural invariants

1. `easytier-core` is a single crate.
2. `easytier-core` may not perform real OS socket, DNS, TUN, file-system
   configuration, process, or service-manager operations.
3. A host-OS decision cannot depend only on core's compile-time target when core
   is built as wasm; it must be represented in runtime configuration.
4. Each core instance owns its mutable state. Instance-specific global
   registries are forbidden.
5. Dial, accept, and hole-punch paths stop at the socket seam before tunnel
   upgrade.
6. Peer admission consumes tunnels and does not call connectivity modules.
7. The host controls every real socket creation and DNS request. Core does not
   bypass those Host Adapters.
8. Core and Tokio own socket I/O scheduling, backpressure, and protocol state,
   even when each actual OS operation crosses a Host Adapter or WASI.
9. A Go host never blocks the only guest executor inside an individual socket or
   DNS import.
10. Calls into one wasm instance are serialized and non-reentrant.
11. Graceful cancellation is cooperative. Closing the wasm Module is a hard-kill
    fallback, not ordinary shutdown.
12. Compatibility with existing `easytier::*` public paths is not a refactor
    requirement.
13. Feature slicing follows stable deep Modules after ownership is settled; it
    is not an early migration goal.
14. The process-level socket/DNS Host Runtime contains no instance state.
    Instance-specific OS requests carry explicit context; instance projections
    contain facts and policy inputs but do not create connector resources.
15. `CoreInstance::new(CoreInstanceConfig, CoreHostAdapters)` is the only public
    core construction Interface. Hosts do not inject prebuilt peer graphs,
    runtime stores, or other core-owned managers.
16. Core modules respect the layer order in "Module layers". A new upward
    edge requires updating that section and the layout plan first.

## Architecture vocabulary

Architecture discussions use these terms:

- **Module**: an Interface plus an Implementation.
- **Interface**: everything callers must know, including types, invariants,
  ordering, errors, configuration, and performance.
- **Seam**: where an Interface lives and behaviour can be replaced.
- **Adapter**: a concrete implementation at a seam.
- **Depth**: behaviour and leverage hidden behind a small Interface.
- **Leverage**: capability callers receive per unit of Interface.
- **Locality**: related state, decisions, bugs, and tests concentrated together.

New abstractions should pass the deletion test: deleting a deep Module should
force its complexity to reappear in multiple callers. Deleting a pass-through
Module should not merely make the system easier to understand.
