# Core Instance Construction Closure

> Status: complete. Updated 2026-07-17.

## Outcome

`easytier-core` now exposes one construction Interface for a complete network
instance:

```rust
CoreInstance::new(
    CoreInstanceConfig,
    CoreHostAdapters<H>,
) -> anyhow::Result<Arc<CoreInstance<H>>>
```

Native EasyTier, the Go/WASI Adapter, and complete-instance core tests use this
entry. The caller supplies normalized configuration and platform capabilities;
core validates the configuration and constructs every portable runtime Module
it owns. The returned `Arc` is the lifecycle owner required by `start`,
post-host-ready startup, and `stop`.

This closes a migration seam that previously exposed six `CoreInstance`
constructors, three layers of host/WASI construction, prebuilt peer-manager
paths, and a wrapped-transport factory whose attachment was only passed back to
the caller.

## Construction Interface

### Configuration

`CoreInstanceConfig` is the complete normalized instance input. It contains:

- `peer`: the peer identity, policy, and initial peer-runtime configuration;
- `connectivity`: `CoreConnectivityConfig`, containing listener URLs, initial
  peers, runtime configuration, startup plan, STUN servers, endpoint discovery,
  and manual/direct connectivity options.

The split is data organization inside one authoritative input, not two
construction stages. Core checks peer/connectivity identity and P2P-policy
consistency before assembling any runtime state.

### Host Adapters

`CoreHostAdapters<H>` is the single capability bundle for one construction
request. Its required inputs are:

- the socket/connectivity Host Adapter;
- one DNS Adapter implementing both address and record resolution;
- the packet egress sink;
- the shared `CoreProcessRuntime`.

The bundle may additionally provide peer presentation and persistence
Adapters, native protocol upgraders and wrapped-transport engines, external
listener resources, listener/connectivity event sinks, port mapping,
public-IPv6 operations, proxy operations, VPN portal support, and gateway event
projection. Absence of an optional capability is explicit and is handled by
the owning core Module.

`CoreProcessRuntime` remains supplied rather than created per instance. Native
shares one process runtime; one instantiated WASI module shares one runtime
across its instance handles. Its Ring registry therefore has the intended
process/module scope without becoming host-visible mutable instance state.

### Core-owned assembly

`CoreInstance::new` constructs and connects:

- the authoritative runtime configuration store;
- one per-instance STUN provider, selected from a test-only construction
  override or a core-constructed production collector;
- `PeerManagerCore`, including foreign-network and peer-graph state;
- listener planning, the running-listener registry, accept handling, and
  manual/direct/hole-punch connectivity;
- packet ingress/egress, peer-center routing, proxy/gateway state, and optional
  VPN/public-IPv6 lifecycle Modules.

Callers cannot inject a prebuilt `PeerManagerCore` or runtime store. Tests that
need deterministic STUN use the hidden test-only
`CoreHostAdapters::replace_stun_provider` seam and still construct the instance
through the production entry.

`PeerManagerCore` has one production constructor, the crate-private `new`, and
`CoreInstance` is its only production caller. Standalone peer-manager unit
tests use a builder local to their test Module rather than widening the
production Interface.

## Composition roots

### Native

The native `easytier` crate normalizes product configuration, builds concrete
Host Adapters and protocol engines, and calls `CoreInstance::new`. It retains
only native lifecycle ordering and presentation:

1. construct the core instance in `Created` state;
2. call core `start`;
3. create and attach host resources such as TUN;
4. signal core `start_after_host_ready`.

Native does not construct a peer graph, listener manager, STUN manager, or
parallel network instance.

### Go/WASI

The external ABI remains the version-13 create payload and the existing
`easytier_instance_*` exports. The Rust-side `WasiCoreRuntime` is private and
only retains:

- one shared `HostSocketRuntime` used by socket, DNS, environment, and packet
  Adapters;
- the `Arc<CoreInstance<_>>` returned by the common construction Interface.

Creation still runs inside the Tokio runtime and WASI instance domain. Each
drive notifies host completions before polling core work, and drop preserves
the stop, registry removal, and domain-clear ordering. The private ownership
wrapper is an executor/ABI implementation detail, not a second kind of EasyTier
instance.

## Removed migration paths

The following are intentionally deleted rather than retained as compatibility
wrappers:

- production `new_portable*` and prebuilt-peer
  `new_with_runtime_config_store*` constructors;
- the single-field `PeerManagerCoreBuildResult` wrapper;
- public `HostCoreInstance` construction helpers;
- `WrappedTransportEngineFactory`, attachment return values, and the no-op
  factory;
- the partial/full configuration names that made one input look like two
  construction models;
- native helpers that assembled and disassembled a complete instance bundle
  for one-shot operations.

The similarly named `new_portable_for_test` remains only inside the
peer-manager unit-test Module. It is a local test builder, not a production
Interface.

Rust source compatibility with these migration APIs is not required by
ADR-0001. The WASI JSON shape, schema version 13, exported ABI, wire protocols,
and lifecycle semantics are unchanged.

## Deletion and verification gates

The construction boundary is closed when all of the following remain true:

- `CoreInstance` has exactly one public constructor;
- native, WASI, and complete-instance tests call that constructor;
- no caller supplies `PeerManagerCore`, a core runtime store, or another
  portable manager;
- the WASI runtime wrapper is private and owns one shared completion runtime;
- wrapped protocol engines are capabilities, not factories used to return
  opaque attachments;
- old constructor and Adapter names do not appear in Rust source.

The closure was verified with formatting and diff checks, native and core
all-feature compilation, `wasm32-wasip1` all-feature compilation, native and
core all-feature test compilation, and the focused core-instance configuration,
lifecycle, wrapped-transport, and proxy-CIDR tests.

## Deferred work

This construction closure does not redesign QUIC endpoint pooling, alter
protocol ownership, repair unrelated netns behavior, or add quantitative Go
host production hardening. Those items remain separate work so this refactor
does not change existing networking semantics.
