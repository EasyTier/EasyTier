# EasyTier Core Refactor Roadmap

> Status: core ownership migration complete; feature slicing and production
> hardening remain follow-up work. Updated 2026-07-15.

## Outcome

The refactor is complete when a Go host can create a `wasm32-wasip1` build of
the single `easytier-core` crate, supply normalized configuration and Host
Adapters for sockets, DNS, and packet I/O, and form an EasyTier network without
reimplementing peer, route, connectivity, or protocol decisions.

The native `easytier` crate remains a composition root and native host. It may
parse platform configuration and implement Host Adapters, but it must not be a
second owner of portable runtime logic.

This roadmap follows the ownership rules in [`CONTEXT.md`](../CONTEXT.md) and
these accepted decisions:

- one portable core crate: [ADR 0001](../docs/adr/0001-portable-logic-belongs-in-one-core-crate.md);
- Go supplies host-created sockets to a current-thread Tokio WASI core:
  [ADR 0002](../docs/adr/0002-go-host-drives-wasi-core-with-tokio.md);
- host-OS policy is runtime configuration:
  [ADR 0003](../docs/adr/0003-host-os-policy-is-runtime-configuration.md).

## Current baseline

The `refactor_core` line is a long-running vertical migration series after
`f24735a8`. Its accumulated diff is useful history, but raw commit, file, and
line counts are not acceptance metrics; ownership and deletion tests are.

Already established:

- `easytier-core` builds for `wasm32-wasip1` with default, no-default, and all
  feature configurations;
- the default and no-default wasm test artifacts pass 220 tests, and the
  all-features artifact passes 239 tests under pure-Go wazero 1.12.0;
- peer routing, peer RPC, route state, stream framing, core-side TCP and UDP
  socket Interfaces, DNS Interface, and substantial hole-punch logic have moved
  into core;
- manual, direct-connect, TCP hole-punch, UDP hole-punch, and inbound listener
  paths now produce host-created TCP streams, byte streams, or core UDP sessions
  before protocol upgrade and peer admission;
- ordinary TCP and UDP connectors share one core-owned manual Connectivity
  Module for URL state, DNS, IP-family ordering, retries, status, and admission;
- core owns the raw TCP, UDP, and Ring Tunnel implementations, including TCP
  framing, UDP mux/session classification and lifecycle, Ring registry state,
  and the injected-socket dialer/listener contracts;
- the native crate already contains Adapter implementations for several core
  Interfaces.
- `easytier-core` exports a versioned WASI lifecycle ABI and host-visible timer
  deadlines; a Go/wazero host drives it without periodic polling;
- two isolated release wasm instances form a raw-TCP EasyTier connection and
  exchange an IPv4 packet using Go-owned DNS, sockets, packet sinks, and
  connector-environment operations.
- the Go harness now exposes reusable, non-test `Bridge`, `SocketFactory`,
  `DNSResolver`, `ConnectorEnvironment`, `CoreModule`, and `CoreInstance` APIs;
  socket creation is injectable while read/write/accept scheduling remains
  core/Tokio-owned.
- one process-level native `NativeHostRuntime` implements real socket, listener,
  DNS, Unix/FakeTCP, route-probe, and interface-discovery capabilities; instance
  netns and mark differences arrive through `SocketContext` rather than captured
  `GlobalCtx` state;
- STUN codec, probing, retry, UDP/TCP NAT inference, public endpoint/port state,
  collector construction, and per-instance lifecycle are core-owned and shared
  by manual, direct, TCP hole-punch, UDP hole-punch, peer, IP-collection, and
  UPnP composition; native `GlobalCtx` keeps only an empty live projection slot;
- host create schema v11 passes route-probe socket context, normalized STUN
  server configuration, and core-owned gateway runtime configuration while
  exposing no Go STUN state or mapping operations. Listener input is normalized
  URLs plus IPv6 policy and `SocketContext`; core derives the internal plan.

The ownership architecture is now closed. Deliberate follow-up boundaries are:

- Unix, FakeTCP, KCP/quinn, WireGuard, real socket/listener, TUN, netns, route,
  DNS, and product-presentation work remains in Host Adapters where it is a
  real resource or a concrete non-WASI protocol engine; Ring ownership is
  core-local and no longer a native Host Adapter responsibility;
- the wasm ABI and reusable Go bridge are functional reference contracts, but
  quantitative latency/resource measurement and hard-kill isolation remain
  production-readiness work;
- feature slicing intentionally starts only now that deep Module ownership is
  stable; it was not mixed into the ownership migration.

The ownership migration and its closure evidence are recorded in
[`core_remaining_ownership_refactor.md`](core_remaining_ownership_refactor.md).
That document is now the authoritative closure record for native peer,
`GlobalCtx`, foreign-network, and gateway ownership.

Current closure status on 2026-07-14:

- the Core instance, native and Go completion domains, runtime configuration,
  and process-scoped Ring registry now have single authoritative owners;
- the foreign-network ownership move is complete: core owns policy, state,
  lifecycle, snapshots, context/resource construction, and manager assembly;
  native management code only converts core snapshots to protobuf;
- the native `PeerManager`, `connector`, `peers`, and test-only `peer_center`
  facades are deleted;
- `GlobalCtx` no longer implements `PeerContext`; peer configuration, events,
  credentials, trusted keys, relay preference, and runtime changes have
  explicit core owners and narrow capability seams;
- core owns gateway packet policy and state through TCP/UDP/ICMP services,
  CIDR and ACL Modules, `WrappedTcpDestinationPlanner`, portable SOCKS
  protocol/session Modules, and VPN portal client state;
- native gateway code contains concrete engines, real resources, composition,
  configuration/events, and presentation rather than a second policy owner.
- process-level Host Adapters have one composition root. Core's composite Host
  Adapter pairs them with a narrow `NativeInstanceEnvironment` that has no
  socket operations;
- core STUN and process Host Runtime closure evidence is recorded in
  [`host_runtime_stun_refactor.md`](host_runtime_stun_refactor.md).
- `CoreProcessRuntime` hides shared portable process resources from native
  composition; the WASI module lifecycle creates the corresponding module-local
  runtime. Ring registry construction and access are core-local.
- `CoreInstance` owns listener planning and one lifecycle manager for Ring,
  TCP, UDP-session, Unix, and FakeTCP listeners. Native listener code is a
  stateless Unix/FakeTCP resource Adapter and contains no plan or manager.

## Definition of done

The whole refactor is done only when all of these hold:

1. The same core behaviour is used by the native host and Go host.
2. Go can form and maintain a multi-peer network by supplying configuration,
   DNS, socket, and packet-plane Implementations.
3. Core contains no direct real-OS networking, DNS, TUN, route, process, or
   service-manager calls.
4. A core instance is the sole owner of its peer graph, connectivity state,
   listeners, routes, proxy state, tasks, and shutdown.
5. Every dial, accept, and hole-punch path produces a socket before portable
   tunnel upgrade and peer admission.
6. Host-OS choices are explicit runtime configuration rather than accidental
   consequences of `target_os = "wasi"`.
7. Native integration tests and wasm/Go-host conformance tests cover the same
   key behaviours.
8. Deprecated native ownership and compatibility forwarding paths are deleted.

These ownership criteria are met. Phase 4 feature slicing and the quantitative
production-hardening items below are separately tracked follow-up work; they
do not reopen native ownership of portable state or decisions.

## Phase 0: prove the Go/WASI socket and executor model

This validation remains required before the Go/WASM socket ABI is finalized,
but it does not block Phase 1 ownership migrations that can be verified through
the existing native and in-memory Adapters. Do not claim the Go host path is
production-ready until this phase exits.

Implement the bounded experiment in
[`go_wasi_host_poc.md`](go_wasi_host_poc.md). It must first test whether Go can
create a socket, register it as a guest virtual fd, and let Tokio drive its I/O.
It must compare that preferred model with an opaque-handle Socket Adapter and,
only when necessary, a host operation/completion fallback. Every model must show
that Tokio timers and unrelated connections continue while one socket remains
pending.

Exit gate:

- a selected socket reference, readiness mechanism, and executor-drive
  Implementation meets every functional, scheduling, lifecycle, and isolation
  gate in the PoC;
- the selected wasm Interface and ownership rules are recorded in a follow-up
  ADR;
- failure produces a written architectural decision before more migration. A
  failed PoC is not patched with per-operation blocking imports.

Current result: public WASIp1 virtual fds are rejected for Tokio socket I/O;
opaque Model B passes the functional socket, DNS, environment, lifecycle,
two-instance peer, route, and packet gates. Tokio remains responsible for
read/write scheduling over host-created sockets. Quantitative measurement and
deeper failure/isolation cases remain before declaring the ABI
production-ready.

## Phase 1: close the socket-to-tunnel seam

Make the transport pipeline uniform:

```text
Connectivity decision -> Socket -> portable tunnel upgrade -> peer admission
```

Work:

1. Inventory every outbound and inbound path and classify the first point that
   touches a real OS resource.
2. Convert manual reconnect and direct-connect to request sockets through the
   core Interface.
3. Convert TCP and UDP hole-punch completion to return sockets rather than
   upgraded tunnels.
4. Express every supported inbound listener as a Host Adapter producing core
   socket events, with portable handshakes and framing in core.
5. Keep platform knobs such as netns, bind-device, socket marks, UPnP, and
   NAT-PMP in Adapter Implementations; requests carry policy, not syscalls.
6. Delete each legacy tunnel-producing path as soon as its replacement passes
   native and wasm conformance tests.

Current boundary result: production manual, direct-connect, TCP hole-punch, UDP
hole-punch, and listener admission no longer construct tunnels inside their
connect/accept state machines. They pass `ConnectedTransport` or
`AcceptedTransport` values to the shared protocol upgraders. Core owns the raw
TCP/UDP/Ring Tunnel types and injected-socket standalone dialers/listeners.
Native protocol-specific standalone endpoints reuse the same upgrade helpers
for tests, the web entry point, and VPN portal composition; the parallel native
`TunnelConnector` / `TunnelListener` traits and adapters have been deleted.
See the [Tunnel ownership closure](tunnel_ownership_refactor.md).

### Current protocol dependency constraints

The WS/WSS accepted-socket upgrade is core-owned. The outbound upgrade still
uses native `tokio-websockets::ClientBuilder::connect_on` because the current
EasyTier fork couples its `client` feature to `tokio/net`, even when the caller
provides an established stream. Enabling that feature in `easytier-core` breaks
the stable `wasm32-wasip1` Tokio profile.

Complete the outbound move by splitting an established-stream client handshake
feature from socket creation in the existing fork. Do not hide the client path
with a WASI `cfg`, replace the wire implementation during the refactor, or let
the host perform the WebSocket handshake.

QUIC already receives a core `ConnectedUdpSession`, and Quinn's abstract-socket
Interface can drive that session without creating a socket. However, Quinn
0.11 still compiles `socket2` for `wasm32-wasip1`; the dependency fails before
the abstract-socket path can be used. Keep the Quinn engine behind the narrow
native protocol-upgrade Adapter until the dependency can build its protocol and
abstract-socket runtime without the OS socket implementation. Core continues to
own protocol selection and the UDP-session seam.

WireGuard configuration and key derivation are core-owned. The current
`boringtun-easytier` 0.6.1 protocol engine fails on `wasm32-wasip1` because its
monotonic-clock implementation only selects Windows or Unix. Its mock-clock
feature is not a production substitute because timers advance only when a test
drives them. Keep the BoringTun engine behind the narrow native
protocol-upgrade Adapter until the dependency supplies a real WASI clock; do
not freeze protocol timers or hide the engine with a guest-target `cfg`.

Exit gate:

- a repository search finds no native connectivity path that directly creates
  a tunnel for peer admission;
- all supported connection methods enter peer admission through the same
  tunnel Interface;
- socket cancellation, backpressure, listener shutdown, and address/error
  normalization behave consistently across native and Go test Adapters;
- native multi-node and hole-punch integration tests pass in the Docker test
  environment.

Ownership part of this gate is complete. The native raw TCP/UDP/Ring modules,
legacy connector/listener traits, and migration adapters are deleted. The
quantitative Go/WASI and production-hardening gates remain the Phase 0
follow-up described above.

## Phase 2: establish the authoritative Core instance

Create one deep lifecycle Module inside `easytier-core`. Avoid a pass-through
wrapper: the Core instance must actually own state and enforce ordering.

Work:

1. Define a normalized `CoreConfig` independent of CLI, TOML, web, and Go input
   shapes.
2. Move start, reconfiguration, task ownership, stop, and join ordering behind
   the Core instance Interface.
3. Move instance-specific DNS overrides, ring registries, peer maps, route
   state, proxy state, and cancellation state out of process globals.
4. Reduce `PeerContext` to peer-domain state. It must not remain a container for
   every cross-cutting runtime dependency.
5. Make native `Instance` construct Adapters, translate management input and
   output, and delegate lifecycle; remove duplicate state and decisions.
6. Provide snapshots/events for management views instead of sharing mutable
   internals with hosts.

Exit gate:

- two core instances in one process can use different configuration, DNS,
  sockets, and shutdown without state leakage;
- there is one owner for every mutable runtime state identified in the
  ownership inventory;
- repeated start/stop and partial-start failure leave no tasks or handles;
- native and Go hosts exercise the same Core instance lifecycle Interface.

## Phase 3: migrate the remaining portable logic

With the two major seams stable, move the remaining logic by vertical slice.
For each slice, move state, decisions, lifecycle, tests, and management
projection together so Locality improves rather than merely moving files.

Candidate slices, ordered by dependency and leverage:

1. packet ingress/egress orchestration and TUN-independent packet processing;
2. DHCP, ICMP proxy, SOCKS/proxy-NAT, magic DNS, and public-IPv6 routing logic;
3. listener and protocol selection policy not completed in Phase 1;
4. remaining lifecycle and configuration reconciliation;
5. portable management commands and state snapshots.

OS-dependent Implementations stay in the native or Go host. If a third-party
protocol engine cannot build for WASI, keep a narrow Adapter seam rather than
moving the surrounding policy out of core.

Each slice exits only after:

- core owns the state and decisions;
- native and Go or in-memory Adapters pass the same conformance suite;
- the old native ownership is deleted;
- direct OS dependencies remain outside `easytier-core`.

## Phase 4: simplify and slice features

Feature work starts after Modules and ownership are stable.

1. Delete obsolete forwarding types, compatibility exports, unused bridges,
   duplicate configuration, and stale migration tests.
2. Measure dependency and binary-size cost by Module.
3. Place feature seams at deep optional Modules such as optional protocols,
   management surfaces, or packet-plane functions.
4. Keep the default build coherent; avoid features that expose half of an
   Interface or create a combinatorial test matrix without meaningful savings.
5. Test default, no-default, selected feature profiles, all-features, native,
   and `wasm32-wasip1` builds.

Exit gate:

- every public feature corresponds to a documented capability and measurable
  dependency or size saving;
- supported feature combinations have explicit CI coverage;
- removing an optional Module does not leak conditional logic through unrelated
  callers.

## Implementation discipline

Use vertical, deletable commits:

1. state the ownership change and exit criterion;
2. add or adapt a conformance test at the target Interface;
3. add the core behaviour and both real Adapter paths where applicable;
4. switch every caller in that slice;
5. delete the previous owner in the same series;
6. run the validation matrix before starting another slice.

Do not preserve old public Rust paths merely to make a migration appear less
disruptive. Do preserve wire compatibility when it is an explicit protocol
requirement; that is separate from Rust source compatibility.

## Validation snapshot (2026-07-14)

The completed ownership milestone passes:

- native `easytier-core` default, no-default, and all-feature checks;
- `wasm32-wasip1` no-default and all-feature checks, with the established
  default/no-default/all-feature guest test artifacts retained;
- 482 native `easytier-core` all-feature tests;
- all 31 `easytier-go-host` tests, including the real two-instance route and
  packet exchange, plus `go build` and `go vet`;
- four focused race-enabled Go bridge close, cancellation, and lifecycle
  tests;
- four focused native SOCKS gateway tests;
- core-trait WS/WSS, QUIC, WireGuard, Unix, and root FakeTCP tunnel tests;
- core UDP listener/session tests and native IPv4/IPv6 hole-punch forwarding
  tests after deletion of the native UDP Tunnel module;
- three root/netns Docker SOCKS portal scenarios;
- root/netns wrapped-TCP port-forward scenarios for the baseline, DHCP, and
  QUIC paths. A one-second DHCP/QUIC completion window timed out once in each
  variant and both passed unchanged on rerun, so no production or test
  semantics were altered.

The source audit finds no direct real-OS network, DNS, filesystem, process, or
platform syscall in `easytier-core`. Address-only uses of `std::net` and the
in-memory smoltcp stream are not OS operations.

An earlier full Go race suite passed 21 tests and exceeded fixed deadlines in
eight tests while initializing an instrumented WASM module or probe; it reported
no data races. Normal Go tests and focused lifecycle race tests pass, so this is
recorded as a quantitative race-instrumented initialization limit rather than an
ownership regression.

WireGuard portal Docker tests stop at their baseline ping before
`run_vpn_portal`, so they do not exercise the migrated client registry. The
legacy native ring/peer fixture and its TCP hole-punch wrappers are deleted;
portable policy is tested in core and real socket coverage remains native.

Quantitative latency/idle-resource baselines and hard-kill isolation remain
production-readiness work for the selected Go/WASI ABI. They do not change the
socket ownership or portable-logic boundary established by this refactor.

## Validation matrix

Every phase selects the relevant rows, and the final phase runs all rows:

| Dimension | Required checks |
| --- | --- |
| Rust host | unit tests, native integration tests, multi-node Docker tests |
| WASI core | default, no-default, and all-features compile and tests |
| Go host | Adapter conformance, multi-instance, multi-peer, shutdown tests |
| Scheduling | pending I/O, timers, backpressure, cancellation, idle CPU |
| State | no cross-instance leakage, restart and partial-start cleanup |
| Dependency | no new direct OS calls in core; wasm import allowlist |
| Configuration | host-OS policy explicit and consistent across hosts |
