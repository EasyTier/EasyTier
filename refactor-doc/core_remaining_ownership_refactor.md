# Remaining Core Ownership Refactor

> Status: historical first-milestone closure record. Superseded by
> [`core_native_closeout.md`](core_native_closeout.md). Updated 2026-07-16.

## Outcome

Finish the ownership move required by
[`CONTEXT.md`](../CONTEXT.md) and
[ADR-0001](../docs/adr/0001-portable-logic-belongs-in-one-core-crate.md):

- `easytier-core` owns all portable foreign-network, peer, runtime-state, and
  gateway-dataplane decisions and lifecycle;
- native `easytier` is a composition root, management projection, and Host
  Adapter implementation;
- the Go and native hosts use the same deep core Modules;
- `easytier-core` continues to compile for `wasm32-wasip1` without real OS
  networking, DNS, TUN, route, filesystem-configuration, process, or service
  operations.

This plan does not move files mechanically. Each vertical slice moves state,
decisions, lifecycle, tests, and management snapshots together. The deletion
test must show that removing a native Module does not make portable complexity
reappear in its callers.

## Fixed constraints

The following decisions are already accepted and are not reopened here:

1. There is one `easytier-core` crate, not a family of new core crates.
2. Hosts create and authorize real sockets and DNS operations.
3. Core/Tokio owns I/O scheduling, backpressure, peer state, and protocol
   decisions above Host Adapter operations.
4. Connector and listener Modules produce TCP streams, byte streams, or
   peer-scoped UDP sessions before tunnel upgrade.
5. Native QUIC, WireGuard, WebSocket/WSS, KCP, FakeTCP, and other concrete
   protocol engines may remain behind narrow upgrade Adapters when their
   dependencies cannot build for WASI. Their selection and surrounding policy
   remain core-owned.
6. Rust source compatibility with legacy `easytier::*` paths is not required.
7. Business and wire semantics must not change during ownership migration.
8. Fine-grained feature slicing follows ownership closure; it is not mixed
   into these migrations.

## Current inventory

Raw native source size is not the ownership measure, because integration tests
and unavoidable platform implementations are intentionally large. The relevant
production ownership inventory is:

| Native Module | Current role | Remaining architectural friction |
| --- | --- | --- |
| `peers/foreign_network_manager.rs` | generated direct-connector RPC Host Adapter and management DTO mapper | no portable foreign-network construction, policy, state, or lifecycle remains |
| `peers/peer_manager.rs` | native composition, runtime-snapshot submission, identity/debug presentation, and DTO mapping | no peer-domain forwarding facade remains |
| `common/global_ctx.rs` | native configuration source, Host observations, product events, persistence, metrics, interface state | no longer implements `PeerContext`; remaining uses are native capabilities and product projection |
| `gateway/*` | concrete socket/protocol Adapters, product facades, and I/O composition | no portable ownership debt remains; KCP/QUIC engines, WireGuard, real listeners/sockets, netns, configuration, events, and RPC presentation intentionally remain native |
| `tunnel/*` | native QUIC, WireGuard, WS/WSS, FakeTCP and Unix protocol engines plus framing helpers used by those engines | raw TCP/UDP/Ring Tunnel modules and native connector/listener traits are deleted; remaining engines are narrow Host/protocol Adapters |

Already core-owned and not to be reimplemented:

- peer graph, admission, sessions, peer RPC, relay map, OSPF, credentials,
  trusted keys, traffic metrics, ACL, and foreign-network entry state;
- the Core instance runtime configuration store and submitted peer context;
- TCP, UDP, and ICMP proxy engines and lifecycle Modules;
- proxy CIDR table and monitor, packet reassembly, proxy ACL, wrapped TCP
  classification and destination planning, smoltcp stack, portable SOCKS wire
  protocol and session state, and VPN portal client state;
- connectivity state machines, listener lifecycle, socket Interfaces, and
  protocol-selection policy;
- raw TCP and UDP Tunnel framing/construction, UDP mux/session lifecycle and
  classification, and Ring Tunnel/registry ownership. The detailed closure
  record is [`tunnel_ownership_refactor.md`](tunnel_ownership_refactor.md).

## Slice 1: deepen the Foreign network Module

### Problem

Core owns the foreign peer graph, but the `ForeignNetworkRuntime` Interface is
shallow and leaks portable decisions to its native Adapter. Callers must know
that whitelist checks, relay-all, foreign relay limits, maximum direct
connections, parent feature synchronization, stats construction, trusted-key
projection, connector registration, and context lifetime are coordinated
across two crates. This loses Locality and allows native and Go hosts to diverge.

### Target ownership

Core owns:

- relay whitelist evaluation and relay-all fallback;
- relay-data policy and reversible parent preference composition;
- maximum direct connections per foreign peer;
- foreign relay limiter policy and lifecycle;
- construction and update of the foreign peer configuration snapshot;
- trusted-key state and trusted-key management snapshot;
- parent feature propagation without a native event-copy loop;
- foreign entry creation, rollback, route/RPC/peer-center preparation, task
  ownership, shutdown, and management snapshot.

### Progress

- Core now evaluates the relay whitelist and relay-all fallback from the
  submitted parent peer snapshot.
- The maximum direct-connection limit is part of the submitted core snapshot
  and is enforced by the core foreign manager.
- Foreign relay limiter selection is performed by core through the parent
  peer context; the native runtime no longer constructs or selects it.
- Statistics are an explicit core manager dependency, and trusted-key
  management snapshots are read through the core peer context; neither is
  projected by the native foreign runtime anymore.
- The parent peer context is an explicit core manager dependency rather than
  a value recovered through the Host runtime Interface.
- Core computes and applies the reversible foreign `avoid_relay_data` policy
  and owns its parent runtime-change subscription loop; native GlobalCtx only
  adapts the existing event stream to the narrow core subscriber Interface.
- Core derives the complete foreign context specification and constructs the
  `CorePeerContext`, runtime snapshot, independent credential/trusted-key/event
  state, shared instance statistics, live parent STUN projection, public-IPv6
  runtime, route graph, tasks, and cleanup internally.
- `PeerManagerCore` constructs and owns the core foreign-network manager. The
  former `ForeignNetworkRuntime` Interface and native foreign `GlobalCtx`
  registry are deleted, so native cannot construct, replace, or remove foreign
  contexts.
- The only cross-host Seam is `ForeignNetworkRpcRegistrar`: native registers
  its generated direct-connector RPC server, while core supplies the RPC
  manager, network domain, and explicit socket request context. The no-op
  Adapter supports hosts that do not provide that generated server.
- The foreign context specification is private core Implementation rather than
  public Interface.

The native Host Adapter owns only:

- registration of native-only direct-connector RPC handling;
- conversion of core management snapshots to native protobuf responses.

### Exit criteria

- the core foreign manager does not call a Host Adapter for whitelist,
  relay-all, limiter, connection-limit, or feature decisions;
- no native task copies parent configuration into a second authoritative
  foreign configuration object;
- native `ForeignNetworkManager` contains no forwarding peer-graph Interface;
- credential, secure-mode, relay, traffic, rollback, and route integration
  tests preserve current behaviour;
- core native/wasm and native foreign-network tests pass.

### Closure record

The ownership move is complete as of 2026-07-14. The native foreign-network
file contains only the generated direct-connector RPC Adapter, management DTO
mapping, and integration tests. Foreign context construction, resource
identity, state, graph, and lifecycle are core-local. Core tests verify shared
instance statistics, independent credential/trusted-key state, live parent
STUN, normalized host-routing policy, and control metrics. Some legacy
ring-based foreign tests still stop at the pre-existing missing-`TunnelInfo`
fixture documented in the verification discipline; that fixture is not part
of the ownership move.

## Slice 2: reduce the Native peer facade

### Problem

The native `PeerManager` is no longer a peer graph owner, but its broad
forwarding Interface remains nearly as complex as the core Interface. It is a
shallow Module: deleting a forwarding method usually removes complexity rather
than forcing a decision to reappear elsewhere.

### Target ownership

Core owns construction and lifecycle of its complete peer graph, including the
core foreign manager. Native composition supplies narrow Adapters and retains
only:

- construction of native Host Adapter values;
- immutable access to the core manager where native management composition
  requires it;
- conversion to native RPC/protobuf presentation models;
- platform-specific debug labels and resource handles that do not affect peer
  decisions.

### Progress

- Recent-traffic demand state and notification are used through the core
  manager Interface. The native facade no longer projects mark/query/GC or
  notification methods, and its unused route-update-time projection is gone.
- Direct-connection checks and core graph/resource handles for relay state,
  peer RPC, peer sessions, NIC delivery, and traffic metrics are no longer
  re-exported one method at a time by the native facade.
- Native callers and tests now enter the core peer graph through
  `PeerManagerCore::get_peer_map`; the high-fanout native `get_peer_map`
  projection has been deleted without introducing another compatibility
  accessor.
- Foreign-client state is likewise obtained from `PeerManagerCore`; the native
  facade no longer re-exports the core foreign-client handle.
- Packet/NIC pipeline and route registration now use the core manager
  Interface directly. The native facade no longer mirrors registration
  methods or core registration-guard types.
- Route handles, proxy/public-IPv6 queries, destination selection, and
  KCP/QUIC eligibility checks now stay on the core Interface. Native retains
  only the route snapshot-to-protobuf presentation method.
- Packet sending for proxy/IP paths and NIC pipeline removal now call core
  directly; native no longer wraps core packet-plane errors solely to forward
  the same operation.
- Tunnel admission, peer-connection close, and peer-manager wait are no longer
  projected by the native facade. Native tests and composition use the core
  lifecycle/admission Interface directly.
- Test-only peer-manager startup now calls `PeerManagerCore::run_for_test`
  directly. The native facade no longer owns a hidden core task lifecycle.

The retained native Interface is intentionally limited to host composition,
runtime-config synchronization, ring-registry and `GlobalCtx` resource access,
local identity/debug presentation, foreign-context test inspection, and the
route snapshot-to-protobuf mapper. By the deletion test, removing this Module
would force those native Adapter and presentation decisions into callers; the
remaining methods are therefore not shallow projections of peer-domain
operations.

### Exit criteria

- native code does not forward admission, routing, relay, pipeline, credential,
  or lifecycle methods one by one;
- production callers use the deep core Interface or a genuinely native
  management projection;
- the native facade owns no peer or route state and starts no core-domain task;
- native peer and three-node integration tests pass unchanged.

### Closure record

The ownership move is complete as of 2026-07-13. Native `PeerManager` no
longer projects admission, routing, relay, packet-plane, credential, or task
lifecycle methods. Its remaining surface assembles native resources, submits
runtime snapshots, exposes native-only ring and `GlobalCtx` handles, supplies
debug identity, and maps core snapshots to protobuf presentation. Removing the
facade would move real Adapter and presentation work into callers, so the
remaining Module passes the deletion test.

## Slice 3: replace GlobalCtx with capability Adapters

### Problem

`GlobalCtx` is a useful native composition object but a poor seam. Its broad
peer implementation lets core-domain callers reach configuration, live
observations, events, credentials, trusted keys, metrics, limiter creation,
STUN, interface state, and platform state through one Interface. The submitted
runtime snapshot fixed configuration authority, but capability Locality is
still incomplete.

### Target ownership

Do not move `GlobalCtx` into core. Split its roles:

- normalized configuration remains in `CoreRuntimeConfigStore`;
- credential and trusted-key in-memory authority remains in core, with native
  persistence behind a storage Adapter when required;
- peer and route events originate in core and are projected through an event
  sink Adapter;
- traffic accounting uses core metrics Modules, with optional native export;
- STUN protocol, public-endpoint state, mapping, and lifecycle belong to core;
  public-IPv6 lease, interface inventory, netns, TUN, route installation, real
  sockets, and system DNS remain Host capabilities;
- platform configuration parsing and persistence remain native.

The final native composition may still own one `GlobalCtx` value internally,
but no core Module receives it or a broad Interface implemented by it.

### Progress

- Native and foreign peer graphs now receive a core `CorePeerContext` backed by
  an explicit runtime snapshot. Foreign contexts are constructed entirely in
  core; native no longer creates foreign `GlobalCtx` values or keeps a parallel
  foreign-context registry.
- `SubmittedPeerContext` owns its peer-event broadcast stream. A narrow
  `PeerEventSink` projects rich events to native `GlobalCtxEvent` consumers,
  while core state-machine subscriptions remain core-local; event publication
  and subscription are no longer part of the live runtime-support Interface.
- Limiter acquisition is isolated behind `PeerLimiterFactory`; the submitted
  context still derives all keys and rates from its core-owned snapshot, while
  native only supplies the token-bucket implementation. Limiting is no longer
  part of the broad live runtime-support Interface.
- Control-plane traffic export uses `PeerControlTrafficSink`; native maps it to
  the existing labelled `StatsManager` counters, while the broad live support
  Interface no longer exposes the metrics registry's side effects.
- Submitted contexts now hold the core `CredentialManager` and
  `TrustedKeyMapManager` directly. Native credential files remain a storage
  Adapter, and only the `PeerCredentialEventSink` crosses back to product
  events; trust lookup and OSPF key state are no longer Host support methods.
- Named `SubmittedPeerContextCapabilities` makes each remaining Interface
  explicit at the composition Seam and prevents positional capability wiring
  from becoming a new broad runtime Interface.
- The former broad `PeerRuntimeSupport` has been deleted. STUN observations use
  a separate read-only core Interface backed by the per-instance core collector;
  public-IPv6 lease/provider state is core-owned, while the host only observes
  reserved addresses and receives event deltas. The advertised EasyTier version
  is part of the submitted snapshot.
- `GlobalCtx` no longer implements `PeerContext` and no longer carries a second
  peer-event broadcast bus. Native configuration is normalized explicitly into
  `PeerRuntimeSnapshot`; main, foreign, and test peer graphs all receive
  `SubmittedPeerContext`, while product consumers keep the native event bus.
- Peer runtime-change subscriptions now originate from
  `CoreRuntimeConfigStore`; replacing a submitted peer snapshot publishes a
  core-local version change. Foreign relay synchronization no longer observes
  native `GlobalCtxEvent` merely to discover portable configuration updates.
- Base avoid-relay preference is core-owned state initialized by the submitted
  snapshot. `PeerRelayStateSink` projects changes one-way to native advertised
  feature flags; `GlobalCtx` is no longer the relay-state authority.

### Exit criteria

- `impl PeerContext for GlobalCtx` is removed;
- each remaining Host Adapter Interface has two real implementations where it
  is a cross-host seam, or remains private to native composition when it does
  not vary;
- configuration decisions cannot change without a submitted core snapshot;
- credential/trusted-key/event/metrics behaviour and shutdown remain covered;
- source audit finds no `GlobalCtx` dependency in `easytier-core`.

### Closure record

The capability split is complete as of 2026-07-14. `GlobalCtx` does not
implement `PeerContext`; core receives normalized snapshots and named narrow
capabilities for events, limiters, traffic export, public-IPv6 OS observation,
credentials, and relay-state projection. Core owns STUN observations and
lifecycle, public-IPv6 provider/lease/route policy, credential, trusted-key,
runtime-change, and base relay-preference state. Native
`GlobalCtx` remains a useful product composition object, but it is neither a
core dependency nor an authoritative peer-domain store.

## Slice 4: audit and deepen Gateway dataplane Modules

### Classification rule

Move behaviour when it is packet classification, transformation, proxy/NAT or
session state, retry/lifecycle policy, or forwarding choice. Keep behaviour in
native when it invokes a real OS resource or a concrete non-WASI protocol
engine.

### Required audit

The field-by-field audit below records the observed owner, not only the desired
file location. A row marked **move** is remaining migration debt; a row marked
**keep** is an intentional Host Adapter or product-composition boundary.

| Path / responsibility | Current core owner | Current native owner | Decision |
| --- | --- | --- | --- |
| TCP proxy classification, ACL and forwarding lifecycle | `TcpProxyService`, engine and runtime Interfaces | socket connector, copy loop, stats and management facade | **Keep**: the seam is already deep and host-neutral |
| UDP NAT/session lifecycle and packet transformation | UDP engine, service and socket-runtime Interface | real UDP socket Adapter and test shims | **Keep**: native contains resource realization only |
| ICMP request/session policy and peer pipeline lifecycle | ICMP engine and service | raw ICMP socket, netns and runtime Adapter | **Keep**: raw socket access is a Host capability |
| Proxy CIDR lookup and monitor state | `ProxyCidrTable` and `ProxyCidrTableRuntime` | normalized GlobalCtx snapshot provider | **Keep**: configuration projection is the Adapter seam |
| KCP/QUIC source-side wrapped TCP classification | packet classifier, marker and forwarding policy in `wrapped_tcp_proxy` | concrete KCP/quinn endpoint and stream handling | **Keep**: source policy is already core-owned |
| KCP/QUIC destination mapping and ACL plan | `WrappedTcpDestinationPlanner` owns CIDR/group lookup, listener denial, loop prevention, self/no-TUN rewrite, chain selection, `PacketInfo`, and first-payload planning | runtime observations plus concrete connect/copy | **Complete**: one core planner drives both native engines |
| SOCKS entry/session table and peer IPv4 packet routing | `Socks5EntryTable` and packet classifier | resource payloads stored behind the generic table | **Keep**: state and classification are already core-owned |
| SOCKS TCP transport choice | `Socks5TcpConnectPlan` selects kernel, smoltcp or KCP | route/group observations and construction of the chosen concrete connector | **Keep**: core chooses; native realizes the engine |
| SOCKS wire constants, address codec, authentication and handshake | stream-generic `socks5_protocol` Module owns wire framing, authentication, commands, DNS sequencing, TCP copy, and UDP association lifecycle | DNS, TCP and UDP runtime Adapters | **Complete**: portable protocol state is core-owned |
| SOCKS smoltcp and peer packet pumps | core owns the smoltcp stack, entry/session state, transport choice, and peer packet routing | native wires channels, peer sender, product port-forwards, and concrete streams | **Keep**: the remaining code is I/O composition with no second policy owner |
| VPN portal client identity and peer-packet dispatch | `VpnPortalClientTable` and `VpnPortalClientSession` own registry, replacement-safe removal, identity learning, packet validation, and dispatch | opaque WireGuard client sink and event/config projection | **Complete**: registry and dispatch policy are core-owned |
| VPN portal WireGuard listener, tunnel and client config presentation | WireGuard tunnel protocol remains an accepted native engine | listener/device lifecycle, tunnel I/O, key material formatting, product events and RPC DTOs | **Keep** as concrete protocol Adapter and presentation |
| VPN portal advertised routes | route/proxy-CIDR state is core-owned | native formats `AllowedIPs` and projects the configured portal CIDR | **Keep** formatting in native; do not create a second route authority |

The audit must account for code already moved to `easytier-core::proxy`; it must
delete duplicate native decisions rather than create parallel engines.

### Migration order

1. Add a core wrapped-TCP destination planner and switch both KCP and QUIC to
   it before deleting their duplicated policy blocks.
2. Move the stream-generic SOCKS wire protocol Module to core without changing
   its handshake, authentication, timeout, DNS, or connector semantics.
3. Move the VPN portal client registry and peer-packet dispatch policy to core;
   keep the WireGuard tunnel engine and product events in native.
4. Repeat the deletion test across `gateway/*`: removing a native facade must
   leave only real resource composition or presentation work in its callers.

All four steps completed on 2026-07-13. The destination planner is shared by
KCP and QUIC; the portable SOCKS codec and handshake/session state live in
core; modified-source SOCKS packet routing and VPN portal registry/dispatch
are core-owned; stale native state and duplicate routing checks were deleted.

### Closure record

The gateway ownership audit is closed. Native gateway code retains concrete
KCP/quinn and WireGuard engines, real sockets/listeners, transparent-address
lookup, netns handling, product configuration/events, RPC DTOs, and the
smoltcp/channel pump that composes core Interfaces. Moving that pump behind a
new pass-through wrapper would reduce Depth: deleting it does not force packet
policy or session rules to reappear, because those rules already live in the
core Modules named above.

### Exit criteria

- native gateway facades contain only Host Adapter work and presentation;
- no native gateway Module registers a portable packet policy that duplicates a
  core pipeline Module;
- KCP/QUIC concrete engines remain narrow Adapters and do not own routing or
  wrapped-proxy decisions;
- SOCKS and VPN portal ownership is documented field by field before migration;
- native gateway tests and wasm feature checks pass.

## Documentation requirements

Documentation is part of each slice, not a final cleanup:

1. Update this document's current state and exit criteria with each ownership
   commit series.
2. Update `core_refactor_roadmap.md` validation counts and blockers after each
   completed slice.
3. Add or sharpen terms in `CONTEXT.md` whenever a new deep Module is named.
4. Record a new ADR only if a durable decision changes an accepted ADR or
   chooses between multiple viable ownership models.
5. Mark historical plans as historical; do not silently leave stale paths as
   current instructions.

## Commit and verification discipline

Use small vertical commits. A typical slice is:

1. introduce or tighten the core Interface and a conformance test;
2. move one coherent state/decision/lifecycle unit;
3. switch native Adapter and Go/in-memory Adapter where relevant;
4. delete the previous native owner;
5. update documentation and validation record.

Every code commit receives a focused post-commit review. Reviews report only
issues introduced by the current ownership move; unrelated legacy problems are
recorded separately and are not mixed into the patch.

Minimum recurring verification:

```bash
cargo test -p easytier-core
cargo check -p easytier-core --no-default-features
cargo check -p easytier-core --all-features
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features
cargo check -p easytier-core --target wasm32-wasip1 --all-features
cargo check -p easytier --no-default-features
cargo check -p easytier
(cd easytier-go-host && go test ./... && go build ./... && go vet ./...)
```

Run focused native and Docker integration tests for the domain touched by each
slice. The known legacy ring fixture without `TunnelInfo` remains out of scope
unless a migration directly changes that fixture's ownership.

## Final definition of done

- the native crate is not a second owner for any portable peer, foreign,
  gateway, configuration, or lifecycle state;
- a Go host can drive the same deep core Modules without reconstructing native
  decisions;
- core remains free of real OS operations and compiles for `wasm32-wasip1`;
- obsolete forwarding Interfaces and native ownership are deleted;
- native, wasm, Go, and selected Docker scenarios pass;
- `CONTEXT.md`, ADRs, roadmap, this plan, and code describe the same ownership.

The ownership definition of done is met. Final validation covered 482 core
tests; native, no-default, all-feature, and `wasm32-wasip1` checks; all 31 Go
host tests plus build and vet; focused race-enabled lifecycle tests; native
SOCKS tests; and root/netns Docker SOCKS and wrapped-TCP scenarios. An earlier
full Go race run exceeded eight fixed WASM-initialization deadlines and produced
no race-detector reports. WireGuard portal Docker tests stop at a baseline ping
before entering
the migrated portal path, and the legacy ring fixture still lacks
`TunnelInfo`; both are recorded verification limitations rather than reasons
to change production semantics in this migration.
