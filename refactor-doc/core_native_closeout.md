# EasyTier Core/Native Ownership Closeout

> Status: complete. Created and closed 2026-07-16.

This is the authoritative ownership-closeout record after the first core
migration milestone. [`CONTEXT.md`](../CONTEXT.md) and the accepted ADRs remain
the architectural authority. Earlier completion claims are historical
snapshots; final completion means every item and exit gate in this document is
closed.

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

- [x] Delete test-only `WsTunnelConnector`; retain the WS/WSS engine and
  `upgrade_connected`/`upgrade_accepted` implementation.
- [x] Delete test-only `WgTunnelConnector`; retain the BoringTun engine and
  upgrade implementation.
- [x] Add a WireGuard client/server roundtrip through the formal core
  stream/session and native protocol Adapter Seam before deleting its old
  connector tests.
- [x] Remove helpers used only by those connectors, including
  `wait_for_connect_futures`, `_tunnel_pingpong` and `_tunnel_bench`.
- [x] Delete the native short-framed-body test already covered by core.
- [x] Remove unused `FromUrl for uuid::Uuid` and `IpScheme::protocol()` if the
  final caller audit remains empty.
- [x] Consolidate default protocol-port metadata under core without moving the
  concrete native engines.

### Dead native state and facades

- [x] Delete the unconstructed `IPCollector` cache/state machine; retain its
  OS interface-observation functions.
- [x] Delete unused `CancellableTask`.
- [x] Localize `HedgeExt` to the native KCP/QUIC engine Module if that removes
  the generic utility Module.
- [x] Delete the unused native `ErrorCollection` forwarding alias while
  retaining the generic collection used by `HedgeExt`.
- [x] Remove the unused UDP session-control factory implementation after the
  protocol-packet Seam is switched.
- [x] Remove unused DNS convenience helpers and replace the mutable global DNS
  test switch with per-test input.
- [x] Replace mutable process-global peer defaults with constants or explicit
  per-instance runtime configuration.
- [x] Remove default process-runtime constructors that can silently create an
  isolated Ring registry. Tests must pass a runtime explicitly.
- [x] Remove production `Instance` methods and fields that only expose core
  internals to tests (`transport_proxy`, connector convenience, wait/close/id
  accessors) after callers move to the correct test Interface.
- [x] Remove unused crate-root re-exports, empty public namespaces and shallow
  forwarding aliases. Keep real cross-crate presentation Interfaces.
- [x] Remove or narrow crate-wide `#![allow(dead_code)]` only after the above
  facades are gone.

### Test ownership

- [x] Move portable CoreInstance lifecycle, registry and proxy-policy tests
  out of native `instance/composition.rs`; retain one native wiring/real-TCP
  smoke test.
- [x] Move peer feature and relay-policy derivation tests from native config
  tests into core.
- [x] Move portable peer-admission helpers from `three_node.rs` into core;
  retain native netns/TUN/protocol-engine scenarios.
- [x] Move generic core RPC client/server tests into core; retain real native
  TCP/UDP vertical RPC tests.
- [x] Move Windows packet rewrite/classification tests with their Module;
  retain WinDivert/backend tests in native.

### Exit gate

- native production code has no test-only connector or process-runtime facade;
- protocol tests cross the same core transport/native-upgrader Seam as
  production;
- deletion does not move portable complexity into native callers.

## Slice 2: move self-contained portable Modules

### Web secure tunnel

- [x] Move Noise handshake, framing, cipher session, timeout and fallback
  lifecycle from `easytier/src/web_client/security.rs` into one core Module.
- [x] Use core runtime-time facilities and keep the Web client as presentation
  and composition only.
- [x] Move the Ring/in-memory protocol tests with the Module.

### Standalone RPC lifecycle

- [x] Move generic listener accept, task ownership, retry and client reconnect
  lifecycle from native `proto/rpc_impl/standalone.rs` into core.
- [x] Keep generated aliases and native socket factories in native.
- [x] Use core runtime-time rather than native `tokio::time` policy.

### Network identity and validation

- [x] Make the core `NetworkIdentity` type authoritative for equality, hash,
  digest and default semantics.
- [x] Keep native serde/input DTOs only where necessary and normalize them once
  at composition.
- [x] Remove the divergent native default and duplicate conversion logic.
- [x] Move mapped-listener validation and secure-mode key consistency/generation
  rules into core; keep TOML/CLI parsing, dump, permissions and persistence in
  native.

### Exit gate

- each Module has one implementation and one test surface in core;
- native callers use a deep core Interface rather than copying policy;
- `easytier-core` still builds for `wasm32-wasip1` with all features.

## Slice 3: establish a single runtime-config and lifecycle authority

### Peer-domain configuration

- [x] Move `PeerFeatureFlag`, relay-whitelist preference, ACL group,
  foreign-network limit and related peer snapshot derivation into core.
- [x] Native submits normalized product inputs plus explicit host capability
  and host-OS policy values; it does not construct derived peer-domain state.
- [x] Ensure runtime updates use the same derivation path as initial creation.

### Proxy CIDR

- [x] Make the core runtime store the sole source for manual routes and VPN
  portal CIDR.
- [x] Remove `ProxyCidrMonitorHost::config_snapshot()` and split configuration
  input from the native presentation/route-application sink.
- [x] Prevent a core -> `GlobalCtx` -> core-style state feedback loop.

### DHCP and VPN portal

- [x] Remove the DHCP Host Adapter's weak back-reference to its owning
  `NativeCoreInstance` and full-snapshot refresh callback.
- [x] Let core commit DHCP-selected address/runtime state after the Host
  Adapter successfully applies OS/TUN changes.
- [x] Snapshot or explicitly pass the normalized WireGuard listener plan;
  `VpnPortalHost` must not read live `GlobalCtx` configuration as a hidden
  second source.

### Core lifecycle

- [x] Replace the native-visible `start_network_services()` plus
  `start_gateway()` sequence with one core post-host-ready lifecycle Interface.
- [x] Preserve the required pre-TUN/post-TUN ordering while hiding individual
  core Modules from the host.
- [x] Ensure partial-start rollback and stop order remain core-owned.

The rollback gate above covers returned startup errors and explicit stop. A
caller dropping the startup waiter was already non-transactional before the
unified core entry and is tracked separately below rather than hidden behind
another asynchronous Drop guard.

### One-shot Web connector

- [x] Add a narrow one-shot connector composition Interface for the Web client.
- [x] Stop constructing and disassembling the full `CoreInstanceAdapters`
  bundle merely to obtain host, DNS and protocol capabilities.

### Exit gate

- core has one authoritative runtime store and one peer-policy derivation path;
- no Host Adapter calls back into its owning core instance;
- hosts signal readiness but do not know the core service start list;
- Web composition does not depend on the internal instance Adapter bundle.

## Slice 4: close portable dataplane and Host operation seams

### Windows UDP broadcast

- [x] Move source selection, broadcast/multicast classification,
  malformed/fragment rejection, loop suppression, destination mapping,
  IPv4/UDP rewrite and checksum into a core packet Module.
- [x] Keep WinDivert, capture sockets, interface observation, raw capture and
  injection in the native Adapter.
- [x] Expose packet ingress/egress values rather than native platform handles at
  the Seam.

### UDP port mapping

- [x] Move listener eligibility, backend ordering, IGD-to-NAT-PMP fallback,
  lease ownership, renew/cancel/remove rules and portable events into core.
- [x] Keep gateway discovery, IGD/NAT-PMP protocol operations, netns execution
  and real resource handles in native.
- [x] Replace the broad Adapter that captures `ArcGlobalCtx` with operation
  Interfaces and explicit request data.

### UDP control packets

- [x] Make core the sole constructor of EasyTier UDP control packets and owner
  of preferred-source fallback policy.
- [x] Reduce the native UDP Adapter to the syscall operation that sends bytes
  with source address/interface metadata.
- [x] Delete duplicate packet construction and forwarding factory layers.

### Local-address probe

- [x] Remove real UDP socket creation from `NativeInstanceEnvironment::is_local_ip`.
- [x] Put the OS probe behind the process `NativeHostRuntime` with explicit
  `SocketContext`, or replace it with an authoritative observed host snapshot
  if that preserves current semantics.
- [x] Keep the instance projection free of socket creation as required by
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
- Core post-host startup still lacks an explicit operation owner when its
  waiter is dropped or aborted. This predates the unified core entry: native
  and WASI callers previously owned the same cancellable future. A future
  lifecycle change should use an instance-scoped supervisor task, detach a
  dropped waiter rather than cancel the supervisor, await `stop()` on startup
  errors, and make explicit `CoreInstance::stop()` the cancellation API. It
  must use a dedicated post-host state instead of nesting the existing
  component operation lock or adding another Drop-time `tokio::spawn` guard.
- The native local-address probe has unit coverage for process-runtime routing
  and virtual-IP short-circuiting, but its final selected Docker matrix should
  also exercise an address that exists only inside an instance netns. This is
  a vertical Host Adapter coverage gap, not a second policy owner.
- Native Linux listener and virtual-NIC paths contain pre-existing netns guards
  that cross asynchronous suspension points. Linux `setns` is thread-local, so
  restoration after a Tokio worker migration can target the wrong thread. Fix
  this in a dedicated native Host Adapter correctness change by keeping the
  namespace switch and affected operations on one non-migrating execution
  context; do not mix it into core/native ownership migration.

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

All completion gates are closed:

1. [x] Every ownership checkbox above is closed.
2. [x] Focused native engine coverage exists for WS/WSS, WireGuard, QUIC and
   KCP. The KCP case uses the real native engine across two portable core
   instances and verifies bidirectional bytes through the core peer dataplane.
3. [x] `easytier-core --all-features`: 618 tests passed.
4. [x] `easytier-core` compiles for `wasm32-wasip1 --all-features`.
5. [x] Native all-feature test targets compile without warnings. Selected
   Docker TCP, UDP, WS, WSS and WireGuard three-node paths passed, together
   with real-TCP composition, raw-UDP runtime and QUIC UDP-session upgrade
   cases.
6. [x] The normal Go-host suite passed against a release WASM build, including
   two-core raw-TCP formation and IPv4 packet exchange. Four focused
   race-enabled bridge cancellation and lifecycle tests passed.
7. [x] Static searches find no legacy native connector/peer/raw-Tunnel owner,
   no crate-wide dead-code exemption, no full core-instance dependency in the
   migrated packet-plane adapters, and no direct real-OS call in core.
8. [x] Incremental reviews and the final full-range review found no remaining
   in-scope architecture, behaviour, concurrency, state or coupling defect.

The selected KCP-only and QUIC-only mapped-subnet Docker cases stop at their
mapped-CIDR ICMP prerequisite before either protocol engine runs. The KCP
failure was reproduced with a pre-closeout binary, so it is not used as an
ownership-regression signal. Deterministic concrete-engine coverage now closes
the KCP verification gap without depending on that environment.

## Progress log

- 2026-07-16: read-only closeout audit completed. The old connector/peers and
  raw TCP/UDP/Ring ownership are confirmed deleted, but the semantic ownership
  items above remain. No code was changed during the audit.
- 2026-07-16: removed the test-only WS/WG connector shells, preserved WS/WSS
  mismatch and WireGuard peer cleanup coverage on the production Adapter Seam,
  and deleted the unused native IP collector cache and cancellable-task shell.
- 2026-07-16: moved the Web Noise tunnel and standalone RPC lifecycle into
  core, made core authoritative for network-identity semantics, and retained
  only native socket factories and serde input at the native Seam.
- 2026-07-16: made the core runtime store authoritative for manual proxy routes
  and VPN portal CIDR; the native Proxy CIDR Adapter now emits presentation
  events only and no longer serves configuration back to core.
- 2026-07-16: moved peer feature, relay, ACL and foreign-network derivation to
  the core host-input path; moved DHCP commit authority and its host-side
  serialization permit into core; and made post-host service startup one core
  operation with returned-error rollback.
- 2026-07-16: moved Windows UDP packet policy and UDP port-mapping lifecycle to
  core, moved local-IP probing behind the process host runtime, and removed the
  native UDP session-control policy/factory layers. Core now constructs the
  32-byte control packet and owns preferred-source fallback through socket
  metadata.
- 2026-07-16: removed mutable DNS/peer test globals and the implicit
  `Instance::new` process runtime, retained only vertical native composition
  coverage, and moved generic standalone RPC lifecycle coverage into core.
- 2026-07-16: preserved the native `socks5` feature boundary through an
  immutable core startup plan; portable and WASI composition retain their
  previous default gateway capability.
- 2026-07-16: removed the production `Instance` transport attachment, cached
  identity and test-only core forwarding methods. Native tests now use a
  test-only extension and discover the actual Ring listener URL.
- 2026-07-16: audited peer admission ownership. The reusable address policy is
  covered at its core owner for external, non-IP, unavailable, loopback and
  virtual-network inputs. The remaining `three_node` helper was retained
  because it is a real native netns/TUN/TCP/UDP/protocol-upgrade scenario, not
  a portable helper.
- 2026-07-16: removed the native crate-wide dead-code exemption, narrowed
  listener namespaces and feature/platform `cfg`s, deleted unconnected DNS,
  UDP, FakeTCP and Windows helper paths, and removed their direct dependencies.
  Native default, no-default and Windows cross-target library checks and the
  core test build are warning-free.
- 2026-07-16: moved one-shot manual endpoint-resolver construction into
  `CoreProcessRuntime`. Native Web composition now supplies only Host/DNS,
  protocol and normalized discovery inputs; a TXT-to-Ring test covers the deep
  core factory path and process namespace.
- 2026-07-16: split UDP port-mapping operations from presentation events,
  made public-IPv6 reconciliation start its core lifecycle owner, and removed
  the duplicate native VPN-portal start path.
- 2026-07-16: introduced `CorePacketPlane` as the concrete packet/route
  projection used by DHCP, NIC, Magic DNS, Windows relay and mobile setup.
  Native dataplane tasks no longer retain or depend on the full core lifecycle
  root; shutdown joins static-IP handoff before tearing down NIC and core.
- 2026-07-16: added a deterministic two-core native KCP round trip using the
  real `KcpProxyService`, `KcpEndpoint`, core peer datagrams and native TCP
  destination ingress. Final Rust, WASI, native, Go-host, static and review
  gates passed, closing this checklist.
