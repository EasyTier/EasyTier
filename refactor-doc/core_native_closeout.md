# EasyTier Core/Native Ownership Closeout

> Status: active implementation checklist. Created 2026-07-16.

This is the only active ownership-closeout checklist after the first core
migration milestone. [`CONTEXT.md`](../CONTEXT.md) and the accepted ADRs remain
the architectural authority. Older documents that describe ownership as
complete are historical snapshots; completion now means every item and exit
gate in this document is closed.

## Goal

Finish reducing the native `easytier` crate to a native composition root,
Host Adapter implementations, concrete non-WASI protocol engines, native input
and persistence, and management presentation.

The closeout must preserve business and wire semantics. It must not introduce
feature slicing, replace third-party protocol engines, or repair unrelated
bugs. Each ownership slice moves portable decisions, lifecycle and tests
together, then deletes the previous native owner.

## Fixed ownership

### Core owns

- normalized runtime state and portable validation;
- peer, relay, ACL, foreign-network and connectivity policy;
- listener, route, proxy, DHCP and portable gateway lifecycle;
- portable packet classification and transformation;
- protocol-independent socket/session orchestration;
- portable protocol Modules and their tests.

### Native owns

- the process composition root and platform input/persistence;
- real TCP/UDP, DNS, TUN, netns, routes, raw sockets, WinDivert, UPnP and
  NAT-PMP operations;
- WS/WSS, WireGuard, QUIC and KCP concrete protocol engines;
- Unix and FakeTCP resource Adapters;
- Hickory DNS serving and OS DNS configuration;
- RPC/protobuf, CLI, web and GUI presentation;
- vertical tests that require concrete native engines or OS resources.

`WsTunnelListener` remains native because the web configuration server uses
it. `WgTunnelListener` remains native because the VPN portal uses it. Their
presence is not evidence of a second raw Tunnel owner.

## Slice 1: remove legacy shells and misplaced tests

### Tunnel shells

- [ ] Delete test-only `WsTunnelConnector`; retain the WS/WSS engine and
  `upgrade_connected`/`upgrade_accepted` implementation.
- [ ] Delete test-only `WgTunnelConnector`; retain the BoringTun engine and
  upgrade implementation.
- [ ] Add a WireGuard client/server roundtrip through the formal core
  stream/session and native protocol Adapter Seam before deleting its old
  connector tests.
- [ ] Remove helpers used only by those connectors, including
  `wait_for_connect_futures`, `_tunnel_pingpong` and `_tunnel_bench`.
- [ ] Delete the native short-framed-body test already covered by core.
- [ ] Remove unused `FromUrl for uuid::Uuid` and `IpScheme::protocol()` if the
  final caller audit remains empty.
- [ ] Consolidate default protocol-port metadata under core without moving the
  concrete native engines.

### Dead native state and facades

- [ ] Delete the unconstructed `IPCollector` cache/state machine; retain its
  OS interface-observation functions.
- [ ] Delete unused `CancellableTask` and localize `HedgeExt` to the native
  KCP/QUIC engine Module if that removes the generic utility Module.
- [ ] Remove the unused UDP session-control factory implementation after the
  protocol-packet Seam is switched.
- [ ] Remove unused DNS convenience helpers and replace the mutable global DNS
  test switch with per-test input.
- [ ] Replace mutable process-global peer defaults with constants or explicit
  per-instance runtime configuration.
- [ ] Remove default process-runtime constructors that can silently create an
  isolated Ring registry. Tests must pass a runtime explicitly.
- [ ] Remove production `Instance` methods and fields that only expose core
  internals to tests (`transport_proxy`, connector convenience, wait/close/id
  accessors) after callers move to the correct test Interface.
- [ ] Remove unused crate-root re-exports, empty public namespaces and shallow
  forwarding aliases. Keep real cross-crate presentation Interfaces.
- [ ] Remove or narrow crate-wide `#![allow(dead_code)]` only after the above
  facades are gone.

### Test ownership

- [ ] Move portable CoreInstance lifecycle, registry and proxy-policy tests
  out of native `instance/composition.rs`; retain one native wiring/real-TCP
  smoke test.
- [ ] Move peer feature and relay-policy derivation tests from native config
  tests into core.
- [ ] Move portable peer-admission helpers from `three_node.rs` into core;
  retain native netns/TUN/protocol-engine scenarios.
- [ ] Move generic core RPC client/server tests into core; retain real native
  TCP/UDP vertical RPC tests.
- [ ] Move Windows packet rewrite/classification tests with their Module;
  retain WinDivert/backend tests in native.

### Exit gate

- native production code has no test-only connector or process-runtime facade;
- protocol tests cross the same core transport/native-upgrader Seam as
  production;
- deletion does not move portable complexity into native callers.

## Slice 2: move self-contained portable Modules

### Web secure tunnel

- [ ] Move Noise handshake, framing, cipher session, timeout and fallback
  lifecycle from `easytier/src/web_client/security.rs` into one core Module.
- [ ] Use core runtime-time facilities and keep the Web client as presentation
  and composition only.
- [ ] Move the Ring/in-memory protocol tests with the Module.

### Standalone RPC lifecycle

- [ ] Move generic listener accept, task ownership, retry and client reconnect
  lifecycle from native `proto/rpc_impl/standalone.rs` into core.
- [ ] Keep generated aliases and native socket factories in native.
- [ ] Use core runtime-time rather than native `tokio::time` policy.

### Network identity and validation

- [ ] Make the core `NetworkIdentity` type authoritative for equality, hash,
  digest and default semantics.
- [ ] Keep native serde/input DTOs only where necessary and normalize them once
  at composition.
- [ ] Remove the divergent native default and duplicate conversion logic.
- [ ] Move mapped-listener validation and secure-mode key consistency/generation
  rules into core; keep TOML/CLI parsing, dump, permissions and persistence in
  native.

### Exit gate

- each Module has one implementation and one test surface in core;
- native callers use a deep core Interface rather than copying policy;
- `easytier-core` still builds for `wasm32-wasip1` with all features.

## Slice 3: establish a single runtime-config and lifecycle authority

### Peer-domain configuration

- [ ] Move `PeerFeatureFlag`, relay-whitelist preference, ACL group,
  foreign-network limit and related peer snapshot derivation into core.
- [ ] Native submits normalized product inputs plus explicit host capability
  and host-OS policy values; it does not construct derived peer-domain state.
- [ ] Ensure runtime updates use the same derivation path as initial creation.

### Proxy CIDR

- [ ] Make the core runtime store the sole source for manual routes and VPN
  portal CIDR.
- [ ] Remove `ProxyCidrMonitorHost::config_snapshot()` and split configuration
  input from the native presentation/route-application sink.
- [ ] Prevent a core -> `GlobalCtx` -> core-style state feedback loop.

### DHCP and VPN portal

- [ ] Remove the DHCP Host Adapter's weak back-reference to its owning
  `NativeCoreInstance` and full-snapshot refresh callback.
- [ ] Let core commit DHCP-selected address/runtime state after the Host
  Adapter successfully applies OS/TUN changes.
- [ ] Snapshot or explicitly pass the normalized WireGuard listener plan;
  `VpnPortalHost` must not read live `GlobalCtx` configuration as a hidden
  second source.

### Core lifecycle

- [ ] Replace the native-visible `start_network_services()` plus
  `start_gateway()` sequence with one core post-host-ready lifecycle Interface.
- [ ] Preserve the required pre-TUN/post-TUN ordering while hiding individual
  core Modules from the host.
- [ ] Ensure partial-start rollback and stop order remain core-owned.

### One-shot Web connector

- [ ] Add a narrow one-shot connector composition Interface for the Web client.
- [ ] Stop constructing and disassembling the full `CoreInstanceAdapters`
  bundle merely to obtain host, DNS and protocol capabilities.

### Exit gate

- core has one authoritative runtime store and one peer-policy derivation path;
- no Host Adapter calls back into its owning core instance;
- hosts signal readiness but do not know the core service start list;
- Web composition does not depend on the internal instance Adapter bundle.

## Slice 4: close portable dataplane and Host operation seams

### Windows UDP broadcast

- [ ] Move source selection, broadcast/multicast classification,
  malformed/fragment rejection, loop suppression, destination mapping,
  IPv4/UDP rewrite and checksum into a core packet Module.
- [ ] Keep WinDivert, capture sockets, interface observation, raw capture and
  injection in the native Adapter.
- [ ] Expose packet ingress/egress values rather than native platform handles at
  the Seam.

### UDP port mapping

- [ ] Move listener eligibility, backend ordering, IGD-to-NAT-PMP fallback,
  lease ownership, renew/cancel/remove rules and portable events into core.
- [ ] Keep gateway discovery, IGD/NAT-PMP protocol operations, netns execution
  and real resource handles in native.
- [ ] Replace the broad Adapter that captures `ArcGlobalCtx` with operation
  Interfaces and explicit request data.

### UDP control packets

- [ ] Make core the sole constructor of EasyTier UDP control packets and owner
  of preferred-source fallback policy.
- [ ] Reduce the native UDP Adapter to the syscall operation that sends bytes
  with source address/interface metadata.
- [ ] Delete duplicate packet construction and forwarding factory layers.

### Local-address probe

- [ ] Remove real UDP socket creation from `NativeInstanceEnvironment::is_local_ip`.
- [ ] Put the OS probe behind the process `NativeHostRuntime` with explicit
  `SocketContext`, or replace it with an authoritative observed host snapshot
  if that preserves current semantics.
- [ ] Keep the instance projection free of socket creation as required by
  ADR-0003.

### Exit gate

- all portable packet and port-mapping state machines live in core;
- native Adapters expose platform operations rather than EasyTier policy;
- every real socket operation goes through the process Host runtime with
  explicit request context;
- native and Go/in-memory Adapters exercise the same core Interface.

## Explicit non-goals and separately tracked debt

- Do not move WS/WSS, WireGuard, QUIC or KCP concrete engines into core during
  this closeout.
- Do not introduce a fork of Quinn, BoringTun or the WebSocket dependency.
- Do not implement feature slicing yet.
- Do not redesign QUIC Endpoint sharing without measurements.
- The accepted-QUIC-session retirement defect is a separate correctness bug:
  a failed handshake or a session with no remaining connection can retain its
  UDP session and admission permit. Record and fix it in a dedicated change
  that preserves multiple QUIC connections on one session; do not mix it with
  ownership-migration commits.

## Execution discipline

Use coherent ownership commits rather than one commit per tiny deletion. For
each code commit:

1. state the Module ownership change and Interface exit criterion;
2. switch all callers in that slice;
3. move or add tests at the production Seam;
4. delete the old owner in the same commit;
5. run formatting plus focused checks/tests only;
6. perform one incremental commit review restricted to the changed slice.

Do not wait for the complete matrix between slices. Run expensive WASI, Go,
Docker and full-workspace validation once after coherent milestones and at the
final gate. Review findings outside the current commit are recorded separately
and are not repaired opportunistically.

## Final verification

Completion requires:

1. every checkbox above is closed or explicitly removed by an accepted ADR;
2. focused native engine coverage for WS/WSS, WireGuard, QUIC and KCP;
3. all `easytier-core` tests with all features;
4. `easytier-core` all-feature compilation for `wasm32-wasip1`;
5. native all-feature test compilation and selected Docker TCP/UDP/protocol
   integration scenarios;
6. normal Go-host tests, focused race lifecycle tests and two-core WASM packet
   exchange;
7. static searches show no second portable owner or forbidden OS call in core;
8. final full-diff review finds no architecture regression, business-semantic
   change, concurrency/lifecycle leak, or accidental broad coupling.

## Progress log

- 2026-07-16: read-only closeout audit completed. The old connector/peers and
  raw TCP/UDP/Ring ownership are confirmed deleted, but the semantic ownership
  items above remain. No code was changed during the audit.
