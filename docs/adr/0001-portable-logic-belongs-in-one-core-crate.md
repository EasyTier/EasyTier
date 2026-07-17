# ADR-0001: Portable Logic Belongs in One Core Crate

- Status: Accepted
- Date: 2026-07-10

## Context

EasyTier historically combines peer state, routing, connection orchestration,
protocol logic, product configuration, and OS operations in the `easytier`
crate. The refactor has already moved peer, route, proxy, UDP hole-punch, socket,
and listener logic into `easytier-core`, but `easytier` still owns important
portable state machines and remains a second orchestration center.

The target is native reuse and a Go-hosted `wasm32-wasip1` artifact without
cgo. Splitting every domain into a separate crate would add Cargo and public
Interface complexity before the Module seams are stable.

## Decision

1. Keep one `easytier-core` crate.
2. Move almost all portable EasyTier logic into deep Modules inside that crate.
3. Make a core instance the authoritative owner of peer, route, connectivity,
   listener, proxy, configuration, and task-lifecycle state.
4. Keep real OS operations in Host Adapters supplied by native `easytier` or a
   Go host.
5. Keep `easytier-proto` as the generated wire/model crate; it is not a second
   runtime owner.
6. Do not preserve old `easytier::*` public paths solely for compatibility.
7. Delay fine-grained Cargo feature slicing until Module ownership and
   dependency direction are stable.

## Consequences

- `easytier` becomes a native composition root and Adapter implementation.
- Core can contain multiple internal Modules without exposing each as a
  separately versioned crate.
- Shallow re-export and compatibility Modules may be deleted when their callers
  migrate.
- Feature work is guided by real product profiles later instead of forcing
  premature seams now.
- Reviews must reject new authoritative routing or connectivity state in the
  host layer.

## Implementation update (2026-07-13)

The TCP/UDP/Ring ownership seam is closed:

- core owns raw TCP and UDP Tunnel construction, framing, UDP mux/session
  classification and lifecycle, and Ring Tunnel/registry state;
- network manual, direct and hole-punch connectivity returns core
  `ConnectedTransport` values before protocol upgrade and peer admission;
- inbound network Host Adapters return core `AcceptedTransport` values;
- Ring stays entirely inside core and produces a core Ring Tunnel without
  crossing a Host Adapter;
- native `easytier` retains real socket factories and concrete protocol engines
  only where their dependencies are not yet WASI-capable;
- the native `TunnelConnector`, `TunnelListener`, and `TunnelConnCounter`
  traits, raw TCP/UDP/Ring modules, and compatibility adapters are deleted.

The detailed ownership and deletion checks are recorded in
[`tunnel_ownership_refactor.md`](../../refactor-doc/tunnel_ownership_refactor.md).
Fine-grained feature slicing can now proceed without reopening this boundary.

## Implementation update (2026-07-15)

The second native orchestration center has been removed:

- `easytier/src/connector`, `easytier/src/peers`, and the test-only native
  `peer_center` facade are deleted;
- native composition lives under `instance`, management projection under
  `instance::management`, and concrete QUIC/WireGuard/WebSocket engines under
  `tunnel`;
- `Instance` delegates connector mutations directly to its core instance;
  native no longer constructs a parallel manual/direct/hole-punch manager;
- `ForeignNetworkManager`, credential, ACL, stats, STUN, listener registry,
  UDP hole-punch runtime, portable proxy, and Ring state are constructed and
  owned inside `easytier-core`;
- portable tests no longer require native peer or connector facades. Native
  tests are limited to configuration projection, Host Adapters, concrete
  protocol engines, and vertical OS integration.
- portable `CoreInstance` lifecycle, runtime-update, listener-registry and
  wrapped-transport session tests are owned by `easytier-core`; the nextest
  archive includes both crates, and native configuration mapping is tested
  directly beside its normalization boundary.

Core now owns the only running-listener registry. Transport and external
listeners publish into the same event sink; native may mirror events for UI
presentation but never submits listener state back into core.

Listener ownership is complete: `CoreInstance` accepts normalized URLs and
socket context, derives Ring identity from the final peer instance, classifies
supported schemes from protocol and host capabilities, and owns one manager for
Ring, TCP, UDP-session, Unix, and FakeTCP listeners. Native advertises and
creates only the concrete Unix/FakeTCP `SocketListener`; it never receives the
plan, accepted-socket handler, event sink, or lifecycle. The Go/WASI create
schema version 13 likewise submits URL-level listener input rather than an
internal transport plan and cannot inject an EasyTier-managed IPv6 set.

The public-IPv6 provider state machine is also core-owned. Core reads the
submitted runtime snapshot, resolves provider state, retries stale config,
derives desired NDP state and owns reconcile/cleanup lifecycle. Native exposes
only Linux route/interface observations and concrete sysctl/netlink/NDP
operations, plus lease/route delta events for native consumers. It stores no
provider, lease, or route mirror and does not construct a second provider
manager. Connector policy queries the core peer graph directly.

`GlobalCtx` no longer maintains a parallel peer-feature or ACL/secret-policy
model. Native derives one normalized peer snapshot from product configuration;
core owns subsequent policy state, while the host exposes only dynamic OS facts
through narrow Adapters.

The current ownership map and deletion gates are recorded in
[`core_native_closeout.md`](../../refactor-doc/core_native_closeout.md).

## Implementation update (2026-07-16)

Core instance construction now has one public Interface:

```rust
CoreInstance::new(
    CoreInstanceConfig,
    CoreHostAdapters<H>,
) -> anyhow::Result<Arc<CoreInstance<H>>>
```

Native, WASI, and core tests all provide the same complete normalized
configuration and Host Adapter bundle. Core validates those inputs and
constructs its runtime store, STUN collector, peer graph, listener runtime,
connectivity, packet plane, proxy state, and lifecycle Modules.

The old `new_portable*`, prebuilt-peer-manager, public `HostCoreInstance`, and
wrapped-transport factory/attachment paths are deleted. WASI retains a private
ownership bundle only to keep one completion runtime shared by socket, DNS,
environment, and packet Adapters; schema version 13, the C ABI, and lifecycle
ordering remain unchanged.

The final Interface, ownership map, deletion checks, and verification evidence
are recorded in
[`core_instance_construction.md`](../../refactor-doc/core_instance_construction.md).

## Rejected alternatives

### Multiple core crates now

Rejected because it would stabilize package seams before the runtime and socket
Interfaces have been proven by both native and Go Adapters.

### Keep the native runtime as the main orchestrator

Rejected because the Go host would then need to reconstruct EasyTier decisions,
creating parallel state and losing Locality.

### Preserve all existing public paths

Rejected because compatibility wrappers would keep shallow Modules alive and
constrain the target architecture without a stated compatibility requirement.

### Resume `refactor_core_bak` wholesale

Rejected as a migration strategy. That branch is design archaeology, not an
implementation source of truth. Individual findings may be reconsidered, but
the branch's mixed transport handoff direction is not the current target.
