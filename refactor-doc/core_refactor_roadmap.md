# EasyTier Core Refactor Roadmap

> Status: active and authoritative. Updated 2026-07-13.

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

The `refactor_core` line contains 200 commits after `f24735a8`; at `40fb39b5`
the accumulated diff changes 221 files with 46,055 insertions and 24,396
deletions. This is useful migration history, not evidence that the ownership
move is finished.

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

The current architecture is still intermediate:

- native listener planning and lifecycle still live in the runtime crate even
  though accepted TCP/UDP/byte-stream values already enter the core protocol
  upgrader; ring, Unix, and FakeTCP creation remain Host Adapter concerns;
- native `Instance`, `PeerManager`, `PeerContext`, and process-global state
  still overlap in lifecycle and state ownership;
- the wasm ABI and reusable Go bridge are now functional reference contracts;
  the bridge lives in the root `easytier-go-host` module, while repeated
  failure/isolation measurements and quantitative gates remain open;
- build features exist, but ownership has not yet settled into deep Modules
  suitable for deliberate feature slicing.

The remaining ownership work is specified in
[`core_remaining_ownership_refactor.md`](core_remaining_ownership_refactor.md).
That plan supersedes earlier statements that the native peer and gateway
Adapters are already at their final depth.

Current closure status on 2026-07-13:

- the Core instance, native and Go completion domains, runtime configuration,
  and per-instance ring registry now have single authoritative owners;
- the foreign-network ownership move is complete: core owns policy, state,
  lifecycle, snapshots, and manager assembly; native
  `foreign_network_manager.rs` contains only the GlobalCtx/direct-connector
  Host Adapter and RPC DTO conversion;
- native `PeerManager` is primarily a facade and still exposes a broad
  forwarding Interface, but it now receives the core-owned foreign manager
  instead of reconstructing its graph;
- `GlobalCtx` still implements the broad peer Interface in addition to narrow
  submitted-config support, so capability Locality is incomplete;
- core owns the TCP, UDP, ICMP, CIDR, wrapped-TCP, proxy ACL, smoltcp, and SOCKS
  state Modules, while native KCP/QUIC/SOCKS composition still requires a
  decision-by-decision gateway audit.

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
two-instance peer, route, and packet gates. Quantitative measurement and deeper
failure/isolation cases remain before declaring the ABI production-ready.

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
`AcceptedTransport` values to the shared protocol upgraders. Legacy standalone
connectors remain for non-peer consumers and tests; they are not part of the
Core instance admission path.

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

## Validation snapshot (2026-07-13)

The current implementation milestone passes:

- native `easytier-core` default, no-default, and all-feature checks;
- `wasm32-wasip1` default, no-default, and all-feature checks plus test-artifact
  linking;
- 392 native `easytier-core` library tests;
- all 29 `easytier-go-host` tests, including the real two-instance route and
  packet exchange;
- race-enabled Go bridge close, cancellation, and lifecycle tests;
- ten repeated runs of the real core lifecycle, two-instance network, socket
  factory, and listener paths;
- 15 native Core-instance ownership/isolation tests and nine native direct
  connector tests in the Docker environment.

The source audit finds no direct real-OS network, DNS, filesystem, process, or
platform syscall in `easytier-core`. Address-only uses of `std::net` and the
in-memory smoltcp stream are not OS operations.

Three native TCP hole-punch tests remain blocked before their hole-punch path:
the shared legacy ring-tunnel fixture in `easytier/src/peers/tests.rs` does not
provide `TunnelInfo`, so peer admission fails with `tunnel info is not set`.
This is recorded as a test-harness blocker rather than changing production
semantics during the connector refactor.

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
