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
