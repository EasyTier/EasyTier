# EasyTier Core Architecture

## Status and scope

This document describes the current architecture after the portable-core
refactor. It is the source of truth for ownership, dependency direction,
feature boundaries, and validation. It intentionally records the resulting
design rather than the migration history.

The refactor has three principal crate roles:

- `easytier-core` owns portable EasyTier configuration, protocol state,
  routing, peer state, connectivity orchestration, packet processing, and
  instance lifecycle.
- `easytier` is the native composition root. It owns operating-system
  resources, native protocol engines, process integration, CLI and native
  presentation.
- `easytier-proto` owns generated protobuf and RPC types, descriptor data, and
  the feature slices needed by core and presentation users.

`easytier-core` is designed to compile without direct operating-system network
access. It supports native hosts through Rust traits and has a target-only WASI
adapter and ABI implementation under `easytier-core/src/wasi`.

This architecture does not require compatibility with old internal module
paths. Wire compatibility, configuration compatibility, management semantics,
and externally used application behaviour remain compatibility requirements.

## Architectural vocabulary

The following terms have specific meanings in this document:

- **Module**: an interface and the implementation hidden behind it.
- **Host**: the process or runtime embedding core and owning platform
  resources.
- **Host capability**: an operation core may request but must not implement
  with direct OS calls.
- **Adapter**: a concrete implementation of a Host capability or protocol
  extension.
- **Composition root**: code that creates core configuration, Host Adapters,
  instances, and process-level services.
- **Runtime configuration**: the authoritative normalized state used after an
  instance starts.
- **Packet plane**: portable packet classification, routing, transformation,
  proxy/NAT state, and forwarding decisions.

New abstractions should pass a deletion test: deleting a useful deep Module
should force non-trivial policy or lifecycle logic to reappear in multiple
callers. A pass-through wrapper with no independent invariant is not an
architectural boundary.

## Crate dependency direction

The principal dependency direction is:

```text
easytier-proto <- easytier-core <- easytier
```

Presentation crates and platform integrations consume these crates. Portable
policy must not move outward merely because one current consumer is native.
Conversely, core must not absorb an OS mechanism or a protocol engine whose
dependencies cannot satisfy the core target contract.

### `easytier-proto`

The protobuf crate is split by public Cargo features:

- `core` provides the common wire messages, peer RPC messages, generated RPC
  runtime, and descriptor bytes needed by core.
- `api` adds management API messages.
- protocol-specific features add only their generated message modules.
- `json-rpc` enables the well-known protobuf JSON types used by the management
  plane.
- `full` is the compatibility aggregate used by complete products.

The core crate depends on `easytier-proto` with default features disabled and
enables only `core`, adding API or JSON-RPC types through its own management
features.

The main core/native path has no `prost-reflect` dependency. OSPF route
reflection uses the focused wire editor in
`peers/route/route_peer_wire.rs`. It retains the original encoded
`RoutePeerInfo`, replaces only the fields credential filtering is allowed to
change, and leaves all other top-level and nested fields intact. This is
required so unknown fields survive mixed-version, multi-hop propagation.
Generated Rust types remain responsible for normal message construction and
validation.

Descriptor sets are still generated and embedded by `easytier-proto`; removing
runtime reflection did not remove descriptor data used by configuration and
RPC tooling. The OHOS integration has its own schema service and dependency
policy and is outside this replacement.

### `easytier-core`

Core owns portable behaviour and exposes capability seams. Its normal
dependencies use Tokio runtime, time, synchronization, and I/O traits without
requiring the full Tokio feature set.

Core may depend on optional portable engines when their owning feature is
enabled. It does not create real native TCP/UDP sockets, alter routes, open a
TUN device, enter a network namespace, configure system DNS, manage a service,
or invoke UPnP/NAT-PMP directly.

### `easytier`

The native crate owns:

- process startup, shutdown, signals, service management, and allocators;
- filesystem configuration input and persistence;
- real TCP/UDP, DNS, TUN, raw-socket, route, interface, namespace, and socket
  option operations;
- UPnP and NAT-PMP operations;
- Unix and FakeTCP resources;
- WebSocket/WSS, QUIC, WireGuard, and KCP concrete engines;
- native Magic DNS serving and system DNS integration;
- CLI, web, GUI, FFI, and native management presentation.

Native code may translate values and assemble Adapters. It must not maintain a
second peer graph, reproduce core routing or hole-punch policy, or invent an
alternative instance lifecycle.

## Internal core layers

The physical module layout follows this downward order:

```text
foundation
  <- config / packet
  <- socket
  <- host
  <- tunnel
  <- listener / connectivity
  <- peers / rpc
  <- gateway
  <- instance
  <- management
```

`process_runtime` is a process- or module-scoped owner shared by instances.
`wasi` is target integration and is compiled only for tests or the WASI target;
it is not an additional portable domain layer.

### Foundation

`foundation/` contains task supervision, the time facade, rate limiting, and
statistics primitives. It must not depend on a domain layer.

### Configuration and packets

`config/` owns:

- the complete `TomlConfig` model;
- parsing, serialization, and validation;
- OS-independent defaults;
- peer, encryption, gateway, and API input models;
- normalized runtime snapshots and the live runtime configuration store.

The Host supplies platform facts through `CoreInstanceHostConfig`. Core applies
the policy that combines those facts with TOML input. This is especially
important for a WASI build: the compile-time guest target cannot be used as a
proxy for the Host operating system.

`packet/` owns EasyTier packet structures, compression, STUN and hole-punch
wire codecs. It does not own socket I/O or connection policy.

### Socket and Host seams

`socket/` contains transport-neutral primitives:

- `SocketContext`, including IP-family policy, optional socket mark, and an
  opaque network-namespace token;
- virtual TCP socket, listener, and factory traits;
- virtual UDP socket and factory traits;
- UDP session multiplexing, classification, and lifecycle;
- in-process Ring sockets.

`host/` is the single home of Host capability seams:

- DNS and DNS record resolution;
- connector environment observations;
- packet ingress and egress;
- Host socket operation bridges and handle-based TCP/UDP/listener adapters.

Core owns scheduling, backpressure, cancellation, UDP session state, and
protocol state even when each actual operation crosses a Host Adapter. A Host
Adapter owns the real resource and performs the OS operation.

The native `NativeHostRuntime` is process-wide and does not retain an instance
`GlobalCtx`, namespace guard, socket mark, or connectivity state. Differences
between instances travel in each request's `SocketContext`. A narrow
instance-host projection may expose listener and interface facts, but it does
not become another socket factory.

### Tunnel and listener

A socket is a raw communication endpoint. A Tunnel is an EasyTier connection
created by adding framing, metadata, handshakes, and protocol lifecycle.

Core owns:

- raw TCP framing and upgrade;
- UDP tunnel/session framing and classification;
- Ring Tunnel identity and registry state;
- encryption and secure-datagram policy that is portable;
- client/server protocol selection interfaces;
- listener planning, optional/required listener policy, retry, accept
  scheduling, running-listener registry, and orderly shutdown.

Native protocol Adapters own WebSocket/WSS, QUIC, WireGuard, and KCP engines.
Unix and FakeTCP are socket resources that feed a core protocol upgrader; they
are not independent owners of EasyTier peer state.

Each protocol registration must provide a coherent client/server Adapter.
Unavailable configured transports must be rejected during validation or
protocol selection, rather than silently falling back to another transport.

### Connectivity

`connectivity/` owns:

- manual connection and endpoint discovery policy;
- direct candidate selection;
- retry, backoff, blacklists, and listener reuse;
- STUN requests, responses, probing, NAT inference, and published endpoint
  state;
- TCP and UDP hole-punch state machines;
- UDP port-mapping policy and lease lifecycle;
- conversion of successful sockets into protocol-upgrade requests.

The Host owns DNS execution, socket syscalls, interface enumeration, bind
device/mark/namespace operations, and concrete UPnP/NAT-PMP calls. STUN-only
hole punching remains available when the Host does not supply a port-mapping
Adapter.

Some connectivity files intentionally implement peer-facing adapter traits for
`PeerManagerCore`. These are localized integration edges between adjacent
domains, not permission for lower socket or Host layers to depend on peers.

### Peers and RPC

`peers/` is the authoritative owner of:

- admission and connection sessions;
- peer maps and connection lifecycle;
- ACL and whitelist decisions;
- OSPF route calculation and graph algorithms;
- peer and credential RPC registration;
- foreign-network admission, identity, relay, and lifecycle;
- peer-center state and public IPv6 policy;
- traffic metrics and peer snapshots.

Submodules progress from kernel types and utilities, through ACL/context,
connection state, route state, manager services, and finally foreign-network
and peer-center composition. Callers consume the public surface declared by
the domain rather than reaching into a parallel native peer owner.

`rpc/` owns the peer-flavoured RPC transport, packet fragmentation, client and
server lifecycle, handler registry, and standalone listener/client lifecycle.
Generated service descriptors and message types remain in `easytier-proto`.

### Gateway

`gateway/` owns portable packet-plane features:

- proxy CIDR state and monitoring policy;
- packet parsing, reassembly, NAT/proxy state, and TCP/UDP/ICMP decisions;
- the smoltcp-backed portable dataplane selected by its feature;
- SOCKS5 framing, authentication, association, routing, and session state;
- wrapped-transport planning and session state used by KCP and QUIC Adapters;
- DHCP allocation policy;
- Magic DNS route and response policy;
- VPN portal client/session policy;
- UDP broadcast classification and rewrite policy.

TUN, raw sockets, transparent-destination lookup, concrete protocol engines,
native DNS servers, namespace operations, and route application stay in native
Adapters.

Optional gateway capabilities are selected by cohesive Modules. Disabled
implementations retain stable lifecycle calls and report unsupported
configuration where a stable interface is required; they do not duplicate
portable policy.

### Instance and management

`CoreInstance::new(CoreInstanceConfig, CoreHostAdapters)` is the sole direct
construction path for a normalized instance. `CoreInstance::from_toml` uses
the same normalization and construction path. Core constructs the peer graph,
runtime store, STUN collector, connectivity managers, listener runtime, packet
plane, gateway runtimes, and lifecycle owners.

A core instance:

- owns all mutable portable state for one network;
- is one-shot after `stop`;
- serializes lifecycle operations;
- owns cooperative cancellation and component shutdown order;
- exposes `CorePacketPlane` as the narrow packet/route projection used by Host
  dataplane Adapters;
- treats its normalized runtime store as authoritative after construction.

`CoreHostAdapters` contains the required Host, DNS, packet sink, and
`CoreProcessRuntime`, plus optional protocol and platform capabilities. The
bundle carries capabilities, not preconstructed portable managers.

`InstanceManager<F>` is the canonical UUID-indexed instance collection for one
Host composition. Its `InstanceFactory` constructs one complete record before
the manager performs an atomic uniqueness check. The manager owns collection
membership; it does not own startup order, persistence, daemon policy, cached
errors, ABI handles, or RPC projections.

`management/` consumes the canonical manager and instances. It owns:

- stable UUID/name selection;
- read-only instance and peer management RPC;
- full process mutation and configuration transactions when enabled;
- persistence and logger-control capability interfaces;
- management listener/client lifecycle and JSON-RPC presentation.

There is one process-level management entry. Instances and the manager do not
depend on management response projections.

## Process-scoped state

`CoreProcessRuntime` owns portable resources shared across instances in one
process or instantiated module:

- the Ring Tunnel registry and namespace;
- a reference-counted protected TCP-port registry.

The composition root creates and shares one runtime. Management listener ports
are protected before bind and held by leases after the concrete port is known.
Native and target adapters supply bound resources but do not implement a
second protected-port registry.

Process-global capability objects may contain stateless or shared platform
mechanisms. They must not contain instance-specific peer, route,
configuration, or connectivity state.

## Runtime configuration authority

`TomlConfig` is an owned construction input. After startup, it is not a second
mutable source of truth.

The normalized core runtime store is authoritative for:

- peer feature flags and routing policy;
- listeners and initial peers;
- ACL and whitelist inputs;
- manual and VPN portal CIDRs;
- gateway and connectivity settings;
- runtime configuration patches.

Host persistence is an effect following a successful core transaction. A Host
Adapter must not call back into an instance to obtain a hidden configuration
snapshot while core is applying an operation.

Non-serializable resources such as TUN descriptors, packet sinks, execution
domains, and native protocol engines are construction context, not TOML
fields.

## Logging

The main native runtime uses a small logger implemented in
`easytier/src/common/log`:

- `log` records and `tracing` events share console and file sinks;
- timestamps, compact formatting, optional terminal colours, `NO_COLOR`, and
  basic `RUST_LOG` target/level filters are implemented directly;
- file rotation uses the existing EasyTier rolling appender;
- management RPC can reload the file level;
- an atomic maximum-level gate rejects disabled events before target matching
  or file-filter locking;
- concurrent file-level reload serializes the filter and atomic-level update.

File logging and no-file logging are separate selected backends. The default
tracing backend records events and deliberately ignores span trees. The
optional `tracing` feature selects the tokio-console subscriber integration;
only that diagnostic profile pulls the main crate's `tracing-subscriber` and
`console-subscriber` dependencies.

Contrib applications and platform integrations may have independent logging
requirements and are not implicitly wired to the native process logger.

## Feature model

Features represent coherent capabilities, not arbitrary source fragments.
Important core feature relationships are:

- `management-rpc` enables generated management API types and read-only
  management services.
- `management` adds configuration writes, full management composition, rich
  errors, and JSON-RPC.
- `proxy-packet` enables portable packet parsing/proxy machinery and the
  required smoltcp packet features.
- `proxy-smoltcp-stack` adds the async TCP/UDP smoltcp stack.
- `dns-resolver` is the shared Hickory resolver leaf used by endpoint
  discovery and Magic DNS without coupling either capability to the other.
- `endpoint-discovery` adds HTTPS endpoint discovery dependencies.
- `magic-dns` enables its DNS server, management wire messages, and portable
  packet-query integration.
- `tcp-hole-punch` enables the TCP hole-punch runtime.
- `dhcp-ipv4`, `public-ipv6-provider`, `vpn-portal`,
  `wrapped-transport`, and `proxy-cidr-monitor` are independent gateway or
  platform-policy leaves.
- `extended-services` is the compatibility aggregate for those leaves.
- encryption and compression engines remain independently selectable.

The native crate maps product features to the core and protocol features it
actually consumes. A protocol feature must not accidentally enable unrelated
gateway or management capabilities.

Production feature and platform selection belongs at Module or Adapter
boundaries rather than inside shared implementations. The logger demonstrates
the intended pattern: file and tracing variants are complete backend modules
with one stable interface, so shared event processing contains no feature
branches.

## Module boundaries

The dependency directions in this document define the intended module
boundaries. Changes that require a new upward edge must first define a stable
lower-layer interface or explicitly revise this architecture.

Modules are `pub(crate)` by default. Each domain's `mod.rs` declares its
outward surface. Public visibility is used for real cross-crate Host,
configuration, management, packet-plane, or test-support interfaces.

## Architectural invariants

1. Portable EasyTier policy has one owner in `easytier-core`.
2. Core does not perform real OS socket, DNS, TUN, route, filesystem
   configuration, process, or service-manager operations.
3. Host-OS policy is runtime input; a WASI compile target is not Host policy.
4. Every real socket and DNS operation crosses a Host capability seam.
5. Core owns socket scheduling, backpressure, protocol state, and cancellation.
6. Dial, accept, and hole-punch paths produce sockets before protocol upgrade.
7. Peer admission consumes upgraded transports and does not create OS
   resources.
8. Each instance owns its mutable peer, route, connectivity, gateway, and
   runtime configuration state.
9. One Host composition has one canonical UUID-to-instance manager.
10. Process-level runtimes do not capture instance state.
11. `CoreInstance::new` is the sole normalized direct construction entry.
12. The manager owns membership, not lifecycle or presentation.
13. Management consumes the manager; the manager does not return management
    projections.
14. Unknown protobuf fields in reflected route information survive forwarding
    and credential filtering.
15. Feature selection is localized at cohesive Module/Adapter boundaries.
16. Unsupported configured capabilities fail explicitly rather than changing
    wire protocol or silently falling back.

## Validation

Changes to these boundaries should run, at minimum:

```text
cargo fmt --all -- --check
cargo check -p easytier-core -p easytier-proto -p easytier --features full
cargo test -p easytier-core --lib
```

Feature work should add focused checks for the changed no-default, isolated,
default, full, and cross-target profiles. Socket, TUN, namespace, protocol
engine, and multi-node changes require the relevant Docker integration tests.
WASI ABI or Adapter changes require a `wasm32-wasip1` build and target-side
tests. These compiler-resolved profiles are the authority for feature and
target boundaries.

CI path filters include `easytier-core`, `easytier-proto`, native, web, GUI
Tauri, and contrib. The archived Rust test suite contains both `easytier` and
`easytier-core`.

## Known limitations and debt

- Some production feature and platform gates still select fields or statements
  inside shared implementations. New code should prefer complete Module or
  Adapter variants, and existing cases should move only when their owning
  Module is changed.
- Connectivity retains localized Adapter implementations that name
  `PeerManagerCore`; further decoupling requires an interface extraction, not
  a visibility-only move.
- Native Linux namespace guards exist in paths that can cross async suspension.
  Because `setns` is thread-local, those operations should eventually be kept
  on one non-migrating execution context.
- A dropped or aborted post-Host startup waiter does not yet have a separate
  supervisor owner. Explicit `CoreInstance::stop` remains the supported
  cancellation path.
- QUIC session retirement after failed or exhausted accepted sessions remains
  separate native-engine correctness work; it must preserve multiple
  connections sharing one QUIC endpoint/session.

These limitations are not reasons to add fallback owners or parallel state.
Fixes should preserve the ownership rules above and address the responsible
Module directly.
