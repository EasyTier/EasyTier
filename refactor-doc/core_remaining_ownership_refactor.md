# Remaining Core Ownership Refactor

> Status: active and authoritative for the remaining ownership migration.
> Updated 2026-07-13.

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
| `peers/foreign_network_manager.rs` | about 650 production lines plus extensive integration tests; wraps the core manager and implements its runtime Interface | runtime Interface still decides relay whitelist, relay-all, limiter, max connections, and feature synchronization; native facade forwards most core operations |
| `peers/peer_manager.rs` | about 425 production lines plus tests; constructs `PeerManagerCore` and forwards management calls | broad facade exposes core internals one method at a time and still owns foreign-runtime composition |
| `common/global_ctx.rs` | native configuration, observations, events, persistence, metrics, interface state | implements a broad `PeerContext` as well as submitted-config support, mixing core state access with host capabilities |
| `gateway/*` | concrete socket/protocol Adapters and product facades | TCP/UDP/ICMP/CIDR/wrapped/proxy-ACL engines are core-owned, but KCP/QUIC/SOCKS paths still mix portable policy with concrete engines |

Already core-owned and not to be reimplemented:

- peer graph, admission, sessions, peer RPC, relay map, OSPF, credentials,
  trusted keys, traffic metrics, ACL, and foreign-network entry state;
- the Core instance runtime configuration store and submitted peer context;
- TCP, UDP, and ICMP proxy engines and lifecycle Modules;
- proxy CIDR table and monitor, packet reassembly, proxy ACL, wrapped TCP
  policy, smoltcp stack, and SOCKS entry state;
- connectivity state machines, listener lifecycle, socket Interfaces, and
  protocol-selection policy.

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
- Core derives the complete foreign context specification: network identity,
  hostname, secure mode, relay protocol/socket-mark flags, and initial
  advertised features. Native only realizes that specification as a GlobalCtx
  and attaches host STUN, listener, and connector resources.
- `PeerManagerCore` now constructs and owns the core foreign-network manager
  from a `ForeignNetworkRuntime` Host Adapter. The shallow native manager
  facade has been deleted; native callers and tests use the core manager
  Interface directly, while RPC presentation keeps a standalone DTO mapper.
- The remaining runtime surface is context construction/removal and native
  direct-connector RPC registration.

The native Host Adapter owns only:

- platform-backed connector and protocol-upgrade resources required by the
  foreign network;
- registration of native-only direct-connector RPC handling;
- credential persistence or event projection that actually crosses the host
  seam;
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

The ownership move is complete as of 2026-07-13. The native foreign-network
file contains the GlobalCtx/direct-connector Host Adapter and the management DTO
mapper, but no peer-graph facade or portable policy projection. Core tests,
native/WASI checks, native test compilation, and focused context/feature tests
pass. Some legacy ring-based foreign tests still stop at the pre-existing
missing-`TunnelInfo` fixture documented in the verification discipline; that
fixture is not part of the ownership move.

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
- STUN/public-endpoint, public-IPv6 lease, interface inventory, netns, TUN,
  route installation, and system DNS remain Host capabilities;
- platform configuration parsing and persistence remain native.

The final native composition may still own one `GlobalCtx` value internally,
but no core Module receives it or a broad Interface implemented by it.

### Progress

- Native and foreign peer graphs now receive a core `SubmittedPeerContext`
  backed by an explicit runtime snapshot. Foreign `GlobalCtx` values remain
  only as live Host support and public-IPv6 Adapters; production composition no
  longer coerces them directly into the broad peer-domain Interface.

### Exit criteria

- `impl PeerContext for GlobalCtx` is removed;
- each remaining Host Adapter Interface has two real implementations where it
  is a cross-host seam, or remains private to native composition when it does
  not vary;
- configuration decisions cannot change without a submitted core snapshot;
- credential/trusted-key/event/metrics behaviour and shutdown remain covered;
- source audit finds no `GlobalCtx` dependency in `easytier-core`.

## Slice 4: audit and deepen Gateway dataplane Modules

### Classification rule

Move behaviour when it is packet classification, transformation, proxy/NAT or
session state, retry/lifecycle policy, or forwarding choice. Keep behaviour in
native when it invokes a real OS resource or a concrete non-WASI protocol
engine.

### Required audit

| Path | Expected core ownership | Expected native ownership |
| --- | --- | --- |
| TCP/UDP/ICMP proxy | engine, NAT/session state, pipeline lifecycle, packet transformation | real socket/listener/connect/copy, raw ICMP, netns, stats export |
| KCP/QUIC wrapped proxy | eligibility, connection-state lookup, packet marking and forwarding policy | concrete endpoint and stream engine |
| SOCKS5 | entry/session policy, routing choice, portable protocol state where dependency-safe | real listeners/sockets, CLI/product exposure, platform bind policy |
| VPN portal | portable peer/session/policy state | TUN/WireGuard device and OS route operations |

The audit must account for code already moved to `easytier-core::proxy`; it must
delete duplicate native decisions rather than create parallel engines.

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
