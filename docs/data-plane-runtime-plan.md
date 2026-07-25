# Data Plane Runtime and Event-Driven Host Plan

## Status

Accepted.

This document is the implementation plan for restructuring the EasyTier data
plane and exposing it through native FFI and the standalone
`easytier-go-host` project. It describes a target architecture, not the current
implementation.

The implementation scope is:

- `easytier-core`;
- the native `easytier` composition that injects the existing optional KCP
  backend;
- `easytier-contrib/easytier-ffi`;
- the WASI guest ABI implemented by `easytier-core`;
- `/data/project/easytier-go-host`;
- TCP, UDP, and smoltcp data-plane paths;
- moving KCP route selection and source-connection ownership below the
  `DataPlaneRuntime` Interface without making KCP portable.

The implementation explicitly excludes Mihomo integration. Consumers such as
Mihomo must be able to use the resulting standard Go network interfaces
without requiring consumer-specific code in either repository.

It also excludes:

- porting `kcp-sys` to `wasm32-wasip1`;
- changing KCP timers or cancellation behavior;
- installing KCP in the WASI composition;
- exposing KCP through the FFI v2 or Go data-plane session;
- compatibility with the existing native data-plane FFI.

## Motivation

The current gateway data plane works, but its locality is poor:

- `gateway/dataplane/mod.rs` owns smoltcp lifecycle, packet demultiplexing,
  flow state, SOCKS5 listener tasks, port forwarding, public data-plane
  sockets, and route selection;
- public data-plane TCP connections use a connector named and designed for
  SOCKS5;
- route and packet-flow types that are shared data-plane concepts live under
  the SOCKS5 Module;
- the public data-plane connect path can silently select a Host direct socket
  for a non-overlay destination;
- native FFI presents asynchronous work as per-operation
  `start/status-or-wait/finish` calls rather than one instance completion
  stream;
- the WASI runtime is cooperatively driven, but the data-plane result direction
  is not exposed to a Host;
- the current Go artifact is not built with the smoltcp data plane.

The objective is a deep `DataPlaneRuntime` Module. Callers select an explicit
route policy and receive TCP or UDP behavior without understanding PeerManager
lookups, smoltcp flows, optional KCP backend readiness, Host port reservations,
or cleanup rules. SOCKS5 and port forwarding become Adapters over that Module.
Native FFI and WASI use an instance-scoped operation broker and completion
queue. Go exposes only standard `net` interfaces.

## Architectural decisions

The following decisions are part of this plan.

| Caller | Route policy |
| --- | --- |
| Go data plane | `OverlayOnly`, smoltcp only |
| Native FFI v2 data plane | `OverlayOnly`, smoltcp only |
| SOCKS5 TCP | `OverlayOrDirect`, existing optional KCP backend |
| Port forwarding | Preserve current behavior |

Additional decisions:

- Public FFI v2, WASI, and Go TCP use smoltcp.
- Native gateway Adapters may request the existing optional KCP backend.
- KCP selection and source-connection ownership live behind
  `DataPlaneRuntime`; SOCKS5 no longer implements that policy.
- This refactor does not change the existing KCP backend implementation,
  destination proxy, timers, or cancellation semantics.
- A selected KCP connection keeps the existing no-fallback behavior.
- An existing overlay route that is temporarily unusable never falls back to
  a Host direct connection.
- The first version supports IPv4 only and rejects IPv6 explicitly.
- The first Go interface accepts IP literals only. Name resolution must
  eventually be owned by core rather than being silently delegated to an
  unrelated Host resolver.
- Public Go and FFI data-plane callers cannot opt into direct fallback.
- The cooperative WASI drive contract remains. It is hidden by the Go engine
  and triggered only by real commands, completions, packets, runnable work, or
  protocol deadlines.
- Go does not implement routing or smoltcp.

The local virtual address is an overlay destination. An exact local
data-plane listener wins. Otherwise, a connection to the local virtual address
may use a `LocalHost` path to the Host loopback. This is not equivalent to
falling back to an unrelated direct destination.

## Target architecture

```text
CoreInstance
  |
  +-- DataPlaneRuntime
  |     - route planning
  |     - flow ownership
  |     - smoltcp stack generations
  |     - local endpoints
  |     - optional native KCP backend selection
  |            |
  |            v
  |     PeerManager / ACL / packet forwarding / Host socket seams
  |
  +-- SOCKS5 Adapter ----------- calls DataPlaneRuntime
  |
  +-- PortForward Adapter ------ calls DataPlaneRuntime

Go Instance: Dial / Listen / ListenPacket
        |
        v
Go engine: one driver and completion dispatcher
        |
        v
coreabi Adapter: WASM exports, memory, canonical wire encoding
        |
        v
WASI DataPlane Adapter
        |
        v
DataPlaneSession
  - ResourceTable
  - data-plane operation metadata and quotas
        |
        +-- foundation::OperationBroker
              - operation lifecycle
              - CompletionQueue
        |
        +----------------------- calls DataPlaneRuntime
```

`DataPlaneRuntime`, `Socks5GatewayAdapter`, and `PortForwardAdapter` are sibling
components owned by `CoreInstance`. The dependency is one-way: both gateway
Adapters call the runtime's crate-private Interface. The runtime never owns,
starts, stops, imports, or names either Adapter.

There are two opposite-direction seams and they must remain separate:

1. `hostabi` and the Go reactor implement guest-to-Host underlay operations.
2. The data-plane ABI implements caller-to-guest overlay operations.

Guest data-plane resources must not be stored in the Go Host reactor, and
underlay Host resources must not be exposed as public data-plane handles.

## EasyTier core design

### Module layout

The target layout is:

```text
easytier-core/src/gateway/
  dataplane/
    mod.rs
    runtime.rs
    route.rs
    flow.rs
    packet.rs
    stack.rs
    tcp.rs
    udp.rs
    session.rs
    operation.rs
    resource.rs
  socks5/
    adapter.rs
    codec.rs
    server.rs
    host.rs
  port_forward.rs
```

The exact file split may change during implementation, but ownership must
follow these Modules rather than the current physical layout.

### `DataPlaneRuntime`

`CoreInstance` owns one `DataPlaneRuntime`. The Module owns:

- smoltcp stack-generation lifecycle;
- PeerManager route queries used by the data plane;
- optional native KCP backend capability queries and selection;
- TCP flow and listener registration;
- UDP flow registration;
- peer-packet classification and delivery;
- local data-plane endpoint registration;
- stack, pipeline, and task shutdown;
- data-plane route and I/O errors.

Its public Interface remains narrow:

- connect an overlay TCP stream;
- bind an overlay TCP listener;
- bind an overlay UDP socket;
- start and stop with the owning core instance.

Crate-private Adapter entry points additionally accept route policy, transport
preference, socket purpose, source hints, and an absolute deadline. The public
data-plane entry points always use `OverlayOnly` and `SmoltcpOnly`.

The runtime must not return SOCKS5 errors or depend on SOCKS5 request types.
SOCKS5 error mapping belongs to the SOCKS5 Adapter.

### TCP route planner

`Socks5TcpConnectPlan` becomes a data-plane route planner. It is one pure
implementation, not a trait with a single Adapter.

The planner returns one of:

- `LocalEndpoint`;
- `LocalHost`;
- `Smoltcp`;
- `KcpBackend`;
- `Direct`.

The route matrix is:

1. An exact local data-plane listener selects `LocalEndpoint`.
2. The local virtual address selects `LocalHost` when no data-plane listener
   owns the destination port.
3. An overlay route selects the optional KCP backend only when a native
   gateway Adapter requests `PreferKcp`, the source engine is ready, and the
   peer chain allows KCP; otherwise it selects smoltcp.
4. A destination without an overlay route returns `NoOverlayRoute` under
   `OverlayOnly`.
5. A destination without an overlay route selects `Direct` only under
   `OverlayOrDirect`.
6. A known overlay destination whose data-plane path is temporarily
   unavailable returns `NotReady`; it never becomes `Direct`.

One connection uses one route snapshot. A route update does not change a
stream's selected path after establishment.

KCP backend connection failure is returned to the gateway Adapter. Adding a
fallback policy or exposing KCP to public data-plane sessions requires a
separate explicit design.

### Deadlines and errors

Readiness, route lookup, port reservation, and connection establishment use
one absolute deadline. The current combination of an outer duration and an
inner timeout rounded to seconds is removed.

Core defines stable data-plane error kinds:

- `Cancelled`;
- `DeadlineExceeded`;
- `InstanceStopped`;
- `HandleClosed`;
- `NoOverlayRoute`;
- `PathNotReady`;
- `AddressFamilyUnsupported`;
- `AddressInUse`;
- `ConnectionRefused`;
- `NetworkChanged`;
- `ResourceLimit`;
- `BufferTooSmall`;
- `Io`.

Adapters may attach detailed messages, but consumers must not infer behavior
from strings.

### Flow ownership

The following SOCKS5-named types move into the data plane:

| Current type | Target type |
| --- | --- |
| `Socks5Entry` | `FlowKey` |
| `Socks5EntryKind` | `FlowKind` |
| `Socks5EntryTable` | `FlowTable` |
| `Socks5EntryGuard` | `FlowLease` |
| `Socks5PeerPacketRoute` | `PeerPacketRoute` |

Each resource owns explicit leases:

- an outbound smoltcp stream owns its exact flow lease and Host port
  reservation;
- a stream returned by the optional KCP backend owns its logical source-port
  lease through the backend connection wrapper;
- a listener owns its wildcard listener lease;
- an accepted stream owns an independent exact flow lease;
- a UDP socket owns the destination flow leases it created;
- a direct or local stream reports its actual address and does not fabricate a
  smoltcp address.

Dropping a listener stops new accepts but does not invalidate already accepted
streams. Cancelling a connect future releases both its flow and port
reservation.

UDP cleanup must release owned leases directly. It must not scan the complete
flow table using pointer equality.

### Packet delivery

Packet classification behavior must remain compatible:

- malformed or unmatched packets pass to the next pipeline;
- exact TCP flows win over wildcard listeners;
- only supported EasyTier data packet kinds are consumed;
- modified-source packets that are not local loopback traffic pass through;
- fragmented UDP response routing remains supported;
- a packet is consumed only when the owning flow exists.

`DataPlaneRuntime`, not the SOCKS5 Adapter, registers and owns the peer-packet
pipeline.

### smoltcp stack generations

The smoltcp packet bridge moves out of `Socks5ServerNet` into a
`SmoltcpPlane` implementation.

A stack generation owns:

- the virtual IPv4 address and prefix;
- the smoltcp `Net`;
- its flow table;
- peer-to-smoltcp and smoltcp-to-peer tasks;
- a cancellation token and closed state.

When the virtual address or prefix changes, the old generation closes
deterministically. Existing sockets return `NetworkChanged` or `Closed` on
subsequent I/O. Old flows cannot survive into the new generation.

The runtime starts as a lightweight idle Module with the core instance. A
runtime lease creates or retains the smoltcp generation. Data-plane sockets,
an enabled SOCKS5 Adapter, and active port forwards hold leases.

Dropping the final lease immediately wakes the runtime supervisor. The current
possibility of waiting for a 120-second timer before releasing an unused
stack is removed. Protocol timers such as UDP expiry remain real deadlines,
not polling substitutes.

### SOCKS5 Adapter

The following SOCKS5 implementation remains:

- codec and target-address parsing;
- handshake and authentication;
- command parsing;
- reply encoding;
- server framing and request lifecycle.

`Socks5GatewayAdapter` owns:

- the Host listener;
- accepted SOCKS5 sessions;
- a connector Adapter that calls `DataPlaneRuntime` with
  `OverlayOrDirect`;
- mapping `DataPlaneError` to SOCKS5 replies;
- the SOCKS5 task group.

The current SOCKS5 UDP behavior is preserved during this implementation.
Adding overlay-aware SOCKS5 UDP is a separate behavior change and must not be
hidden inside the mechanical refactor.

### Port-forward Adapter

Port-forward ownership moves out of the core data-plane implementation into a
gateway Adapter. Its current TCP and UDP route behavior remains compatible.
It uses crate-private data-plane entry points rather than reading runtime
fields directly.

### Core instance lifecycle

The start order is:

```text
PeerManager
-> WrappedTransport
-> DataPlaneRuntime
-> SOCKS5 and PortForward Adapters
```

Stop uses the reverse order.

The data-plane runtime is available whenever its feature is compiled. It is
not gated by whether configuration enables a SOCKS5 listener or a port-forward
rule. Gateway configuration controls the Adapters, not whether public Go or
FFI data-plane sockets are possible.

The runtime must:

- clean up partial start;
- reject new work after stopping begins;
- wake pending connect, bind, accept, read, write, and receive operations;
- avoid awaiting Host, PeerManager, optional KCP backend, or smoltcp work
  while holding its main state lock;
- make repeated stop and resource close safe.

## KCP backend boundary

The existing concrete `KcpProxyService` remains in the native `easytier`
composition and continues to use `kcp-sys`. It is injected through the
existing wrapped-transport Interface.

`DataPlaneRuntime` owns the decision to use that backend and wraps the returned
stream with the flow and source-port leases required by the gateway caller.
SOCKS5 and port forwarding do not query KCP readiness or peer policy directly.

The FFI v2 and WASI session request `SmoltcpOnly`, so their TCP listeners
accept smoltcp streams only. The WASI composition installs no KCP backend and
the data-plane capability set contains no KCP bit. Consequently this plan does
not require:

- moving the concrete engine into `easytier-core`;
- compiling `kcp-sys` for WASI;
- tracking KCP timers in the externally driven runtime;
- delivering KCP streams to FFI or Go listeners;
- changing current KCP hedge or cancellation behavior.

These omissions are an explicit scope boundary, not a Go-side KCP fallback.

## Data-plane session and operation broker

### Instance scope

Each core instance owns a `DataPlaneSession`:

```text
DataPlaneSession
  ResourceTable
  data-plane operation metadata and quotas
  foundation::OperationBroker
  CompletionNotifier
```

The native C ABI may still require process-global opaque session handles, but
the actual resource and operation namespaces are instance scoped.

The crate-private foundation broker is a concrete Module rather than an
Adapter trait. It owns ID allocation, terminal-operation arbitration, retained
outcomes, and completion queue transitions without depending on data-plane
types. `DataPlaneSession` composes it under the session's existing lock so
resource creation, quota settlement, and completion publication remain one
atomic transition.

Resource handles identify:

- TCP streams;
- TCP listeners;
- UDP sockets.

Operation handles identify:

- TCP connect;
- TCP bind;
- TCP accept;
- TCP read;
- TCP write;
- UDP bind;
- UDP receive;
- UDP send.

Handle zero is invalid. IDs are monotonically allocated within the session and
are not reused while a stale reference may remain.

### Operation state

An operation slot progresses through:

```text
Pending
-> Queued(result or error)
-> Drained(result or error)
-> Consumed

Pending -> Discarding -> Discarded
Queued  -> Discarded
```

Completion and cancellation are linearized in one state transition:

- the first transition from `Pending` wins;
- an operation is queued at most once;
- cancelling a queued or drained operation preserves its result;
- cancelling an absent or consumed operation is idempotent for cleanup paths;
- closing a resource turns its pending operations into `HandleClosed`;
- stopping a session turns its pending operations into `InstanceStopped`.

Free and the completion queue are linearized under the same broker lock:

- freeing `Pending` moves it to an invisible `Discarding` tombstone until its
  task acknowledges cancellation;
- freeing `Queued` atomically marks its descriptor discarded so a batch drain
  skips it;
- freeing `Drained` drops the retained result;
- a discarded successful result that owns a new resource closes that resource;
- discarded operations never produce an unexplained completion.

The completion queue contains fixed descriptors, not potentially large
payloads. A descriptor contains:

- operation ID;
- operation kind;
- stable status code.

The typed result remains in the operation slot. Draining a descriptor does not
consume the result. Result take is exactly once and consumes only after a
successful copy into a sufficiently large destination.

The implementation enforces per-instance limits for:

- open resources;
- outstanding operations;
- total retained result bytes;
- a single read allocation.

Admission reserves one completion credit for every accepted operation.
Therefore an operation that was accepted can always enter `Queued`; completion
cannot fail because the queue became full. Once operation or result-byte
limits are reached, new submissions fail with `ResourceLimit`.

### Completion notification

The completion notifier sends one edge when the queue changes from empty to
non-empty. It does not run user code and does not enter a guest.

Native FFI uses a condition variable initially. WASI uses queue-ready state
observed by the driver after a guest turn. Optional Unix `eventfd` and Windows
event handles may be added later without changing operation semantics.

## Native FFI

### New session Interface

The new native Interface provides:

- open and close an instance data-plane session;
- submit typed TCP or UDP operations;
- cancel or free an operation;
- close a resource;
- wait until any completion exists;
- batch-drain completion descriptors;
- query result size;
- take a typed result.

`completion_wait` blocks on the complete session queue. A caller needs one
dispatcher wait rather than one loop per operation. Timeout means only that no
completion arrived during the requested wait.

No completion callback is added initially. Calling arbitrary C or Go code from
a Tokio runtime thread would create avoidable reentrancy, lock-order, and
lifetime hazards.

### Replacement policy

The existing synchronous and
`start/status/wait/finish/free` data-plane functions are removed rather than
adapted. FFI v2 is the only native data-plane Interface after this change.

This also removes the runtime-readiness loop that currently calls a manager
method in 50-millisecond chunks even though that method does not actually
wait. Compatibility for those unused symbols and their previous direct
fallback behavior is explicitly outside this plan.

## WASI guest ABI

### Direction

Existing `easytier_host` imports remain guest-to-Host underlay operations.
They are not reversed or reused for public data-plane sockets.

New guest exports provide:

- typed TCP and UDP operation submission;
- operation cancellation and free;
- resource close;
- batch completion-descriptor take;
- result length;
- typed result take;
- data-plane ABI version and capabilities.

`CORE_INSTANCE_CONFIG_VERSION` remains the create-envelope schema version. It
is not reused as a general WASI ABI version.

Capabilities include at least:

- data plane;
- TCP;
- UDP.

The Go `coreabi` Adapter checks required exports, version, and capabilities
before creating an instance.

### Wire and memory ownership

The data-plane wire format has an explicit byte order and field encoding. It
does not expose Rust `repr(C)` layout or padding.

ABI v2 uses big-endian integers and the existing 27-byte WASI socket-address
record. Its fixed records are:

| Record | Bytes | Fields |
| --- | ---: | --- |
| Operation ID | 8 | `u64` |
| Completion | 12 | operation `u64`, kind `u16`, status `u16` |
| TCP connect/accept | 62 | resource `u64`, local address, peer address |
| TCP/UDP bind | 35 | resource `u64`, local address |
| TCP read metadata | 1 | EOF flag |
| UDP receive metadata | 28 | peer address, truncated flag |

The v2 address decoder accepts IPv4 only even though the shared address record
reserves an IPv6 representation for a future capability revision.

Every submit export writes its operation ID into a caller-allocated eight-byte
guest buffer and returns a stable status. `UINT64_MAX` is the no-deadline
sentinel; zero is an immediate deadline. Completion drain writes a dense array
of 12-byte descriptors. Payload result size is queried before typed result
take.

Memory rules:

- submission copies and validates all request and write bytes before the
  export returns;
- the guest never retains a Host memory pointer;
- read payloads and typed results remain guest-owned until result take;
- result take writes only to a currently valid guest buffer;
- insufficient capacity reports `BufferTooSmall` without consuming;
- the Host copies result bytes before freeing the guest buffer;
- no guest-memory slice escapes a serialized `coreabi` call.

### Event-driven drive contract

WASM cannot execute while the Host is not inside the guest. The externally
driven current-thread Tokio runtime therefore remains, but the public Go
caller never drives or polls it.

The Go driver enters the guest after:

- a caller command;
- a real Host reactor completion;
- a tracked Tokio deadline;
- raw packet ingress;
- immediately runnable guest work, represented by a zero next deadline.

After each bounded drive turn, the driver batch-drains data-plane completion
descriptors and dispatches them to Go waiters.

A guest data-plane completion is created only while the guest is executing a
turn. It does not need to call back into Go from a background thread.

The current unconditional Host-completion notification inside
`WasiInstance::drive` is removed. Only a real reactor completion causes:

```text
NotifyCompletions
-> Drive
-> drain data-plane completions
-> NextDeadline
```

Host import callbacks and reactor workers may signal a Go channel but must
never re-enter the guest.

### Shutdown

Graceful stop:

1. takes the session lock and linearizes `Running -> Stopping`;
2. rejects new submissions and turns every operation still pending at that
   point into an `InstanceStopped` completion;
3. detaches and closes underlying resources without reclassifying those
   operations as `HandleClosed`;
4. lets the Host drain terminal completions;
5. stops the data-plane runtime.

If explicit resource close linearizes first, its pending operations complete
as `HandleClosed`. If stop linearizes first, they complete as
`InstanceStopped`.

Forced guest drop additionally requires the Go Adapter to complete any local
waiters with `net.ErrClosed`, because guest results cannot be queried after
the module is dropped.

An unclaimed successful completion that owns a newly created resource closes
that resource when cancelled, freed, or dropped.

## Go host design

### Public Interface

The root `Instance` gains:

```go
Dial(ctx context.Context, network, address string) (net.Conn, error)
Listen(network, address string) (net.Listener, error)
ListenPacket(network, address string) (net.PacketConn, error)
```

The first version supports:

- `tcp`;
- `tcp4`;
- `udp`;
- `udp4`;
- IPv4 literals.

It explicitly rejects:

- `tcp6` and `udp6`;
- hostnames;
- non-overlay destinations;
- Host direct fallback.

Existing raw packet `SendPacket` and `ReceivePacket` calls remain independent
of the socket data plane.

No public type exposes:

- wazero;
- guest memory;
- resource handles;
- operation IDs;
- `start`, `take`, `drive`, or completion polling.

### Package ownership

Suggested additions:

```text
dataplane.go
internal/coreabi/dataplane.go
internal/coreabi/dataplane_wire.go
internal/coreabi/errors.go
internal/engine/dataplane.go
internal/engine/conn.go
internal/engine/listener.go
internal/engine/packet_conn.go
internal/engine/deadline.go
```

The exact internal files may be consolidated where that improves locality.

Responsibilities:

- the root package validates the small public Interface and delegates;
- `internal/coreabi` owns guest export lookup, memory copies, wire encoding,
  status conversion, and ABI validation;
- `internal/engine` owns serialized guest execution, pending-operation
  dispatch, standard Go network behavior, cancellation, deadlines, and
  resource lifecycle;
- `platform`, `internal/hostabi`, and `internal/reactor` continue to own only
  underlay Host capabilities.

The data plane does not add another public bridge or expose raw guest handles.

### Single driver

After module creation, every guest export and guest-memory access runs on the
instance's single driver goroutine.

Public socket calls submit one of three internal command classes:

- submit a data-plane operation;
- cancel an operation;
- close a resource.

The driver owns the pending-operation map. Reactor workers, public goroutines,
and timer callbacks communicate only through channels.

The event loop is:

```text
command, Host completion, or deadline
-> optional NotifyCompletions
-> bounded Drive turns
-> batch-drain data-plane completions
-> dispatch result channels
-> query NextDeadline
-> wait
```

The driver records a pending waiter before a completion can be drained. An
unknown operation completion, wrong kind, or wrong resource is an ABI protocol
error rather than something silently ignored.

Completion draining has a fairness budget. If a batch limit is reached while
more work remains, the driver schedules an immediate self-turn rather than
waiting for an unrelated event.

### Cancellation races

Context or deadline cancellation sends a guest cancel command and waits for
the terminal arbitration. It does not return while leaving an unowned
operation active.

If completion wins, its result is delivered. If cancellation wins, the
operation completes as cancelled. If a resource-creating operation completes
after its Go caller can no longer receive the result, the driver closes the
orphan resource immediately.

Pending map entries remain until one terminal completion is processed. This
prevents late completions from becoming unexplained protocol errors.

### TCP connection Adapter

The guest session owns the actual stream. Go owns an opaque resource ID,
address snapshots, deadline state, and its instance reference.

Concurrency:

- one read and one write may proceed concurrently;
- multiple reads serialize through a read mutex;
- multiple writes serialize through a write mutex;
- close and deadline changes may run concurrently with either direction;
- close does not wait for a read or write mutex.

Read behavior:

- zero-length reads return immediately;
- explicit EOF maps to `io.EOF`;
- cancellation cannot leave a hidden operation consuming future bytes;
- closing the connection wakes a blocked read.

Write behavior:

- zero-length writes return immediately;
- the guest tracks bytes written before an error;
- Go returns `n, err` for partial progress;
- successful completion returns the full source length.

`LocalAddr` and `RemoteAddr` use immutable snapshots returned when the stream
is established or accepted.

### Listener Adapter

Accept calls are serialized. Close is idempotent and wakes a blocked Accept
with `net.ErrClosed`.

If an Accept/Close race creates a child stream after the caller can no longer
receive it, the driver closes the child immediately.

The public session listener accepts smoltcp streams through the core listener
Interface.

### Packet connection Adapter

Read and write directions serialize independently.

- UDP writes are atomic.
- A short datagram write becomes `io.ErrShortWrite`.
- `ReadFrom` returns `*net.UDPAddr`.
- A zero-length datagram is a valid datagram and is not EOF.
- Completion results identify truncation explicitly.
- closing the socket wakes blocked receive operations.

`Dial` for UDP creates an ephemeral UDP resource with a fixed peer. Its read
side accepts only that peer; `ListenPacket` exposes the full datagram Interface.

### Deadline Adapter

Read and write directions each own:

- an absolute deadline;
- a generation or changed channel;
- the current guest operation.

Changing a deadline wakes the current waiter so it can recompute:

- shortening affects an existing operation;
- extending does not cause the old timer to cancel the operation;
- clearing removes the timer;
- close remains independent of direction locks.

When a deadline expires, Go submits cancellation and waits for the
cancel-versus-completion arbitration before returning
`os.ErrDeadlineExceeded`.

### Error mapping

Stable guest error codes map to:

- `*net.OpError`;
- `context.Canceled`;
- `context.DeadlineExceeded`;
- `os.ErrDeadlineExceeded`;
- `net.ErrClosed`.

Go must not classify errors by string matching.

### Instance shutdown

Instance close order is:

1. reject new public operations;
2. ask the guest session to close resources and cancel operations;
3. dispatch or locally complete all pending waiters;
4. stop and drop the guest instance;
5. close the Host reactor and wazero module/runtime.

The existing distinction between graceful `Stop` and resource-reclaiming
`Close` remains.

## Implementation sequence

### Phase 0: freeze semantics and define the ABI

Repository: EasyTier.

- Add golden tests for current route selection, Host direct calls, flow
  cleanup, listener/accepted-stream lifetime, stack lease release, stop, IP
  update, local addresses, SOCKS5 UDP, and port-forward behavior.
- Define the data-plane ABI version, capabilities, wire format, errors, and
  resource limits.

### Phase 1: move shared data-plane ownership

Repository: EasyTier.

- Move and rename the flow table and peer-packet classifier.
- Move the smoltcp packet bridge out of `Socks5ServerNet`.
- Split TCP and UDP resource implementations.
- Preserve all behavior and existing tests.

### Phase 2: introduce `DataPlaneRuntime`

Repository: EasyTier.

- Add stack generations and runtime leases.
- Make shutdown and final-lease release event driven.
- Add typed errors and one absolute deadline.
- Make `CoreInstance` own and start the runtime independently of configured
  gateway Adapters.

### Phase 3: route policy and gateway Adapters

Repository: EasyTier.

- Add `OverlayOnly` and `OverlayOrDirect`.
- Move route selection into the data plane.
- Make public data-plane calls overlay-only.
- Adapt SOCKS5 TCP and port forwarding without changing their behavior.
- Add guard tests proving overlay-only never connects an unrelated Host
  destination.

### Phase 4: optional native KCP backend integration

Repository: EasyTier.

- Move KCP selection and source-connection ownership into
  `DataPlaneRuntime`.
- Keep the existing concrete backend injected by native `easytier`.
- Make public FFI/WASI sessions explicitly request `SmoltcpOnly`.
- Add selected-path diagnostics and route-selection tests without changing
  `kcp-sys` or the wrapped-transport destination.

### Phase 5: session and operation broker

Repository: EasyTier.

- Add the resource table, operation slots, completion queue, and notifier.
- Implement operation limits, cancellation, close, stop, result ownership, and
  batch completion drain.
- Add deterministic race and lost-wakeup tests.

### Phase 6: native FFI

Repository: EasyTier.

- Add the new session Interface.
- Remove the existing synchronous and per-operation asynchronous data-plane
  Interfaces.
- Remove runtime-readiness polling.
- Update examples and conformance tests.

### Phase 7: WASI ABI

Repository: EasyTier.

- Add guest data-plane exports and canonical wire encoding.
- Add ABI version and capabilities.
- Remove unconditional duplicate Host completion notification.
- Enable smoltcp in the artifact build profile.
- Add WASI target and memory-ownership tests.

### Phase 8: Go `coreabi` and engine

Repository: `easytier-go-host`.

- Add typed data-plane guest calls and wire codecs.
- Extend the single driver with submit, cancel, close, and completion drain.
- Add pending-operation, orphan-resource, shutdown, and ABI-protocol handling.
- Test with a deterministic fake guest before adding public sockets.

### Phase 9: Go standard network Adapters and artifact

Repository: `easytier-go-host`.

- Add `Dial`, `Listen`, and `ListenPacket`.
- Implement TCP, UDP, deadlines, cancellation, close, and error mapping.
- Build the final WASM from the exact final EasyTier commit on
  `codex/cfg-refactor-pr`.
- Update embedded artifact provenance.
- Run real two-instance TCP and UDP integration tests.

Each phase ends in a reviewable commit. Commit messages use a 72-column text
width. The complete task receives one final review across both repositories.
The operation-broker commit may receive an additional high-risk incremental
review because it contains concurrency logic.

## Validation plan

### EasyTier core

Required focused tests:

- complete route-policy truth table;
- no Host direct call under `OverlayOnly`;
- optional native KCP backend selection remains below `DataPlaneRuntime`;
- public session calls remain smoltcp-only even when KCP is available;
- port and flow release on cancel and drop;
- listener and accepted-stream independent lifetime;
- UDP multi-destination flow cleanup;
- deterministic close on stack-generation change;
- stop while connecting, accepting, reading, writing, or receiving;
- SOCKS5 TCP wire compatibility;
- broker completion/cancel and completion/close races;
- exactly-once completion and result take;
- buffer-too-small without consumption;
- session isolation and resource limits;
- blocking completion wait without lost wakeups.

Feature and target profiles include:

```text
cargo check -p easytier-core --no-default-features
cargo check -p easytier-core --no-default-features \
  --features proxy-smoltcp-stack
cargo test -p easytier-core --no-default-features \
  --features proxy-smoltcp-stack,test-utils
cargo test -p easytier-core \
  --features proxy-smoltcp-stack,test-utils
cargo build -p easytier-core --release --target wasm32-wasip1 \
  --features proxy-smoltcp-stack
```

Exact commands may change with the final feature names.

Docker integration in the shared `rust` container covers:

- two-node TCP and UDP data-plane traffic;
- three-node relay TCP;
- SOCKS5 virtual and direct targets;
- stop during connection and accept;
- runtime virtual IPv4 change.

### Native FFI

- one wait receives completions from multiple operation kinds;
- timeout does not spin;
- cross-thread wait and take;
- instance deletion wakes waiters;
- stress with many outstanding operations;
- no leaked result buffers, operations, or resources.

### Go

Deterministic engine tests cover:

- all guest calls remain serialized;
- Host completion ordering is notify before drive;
- synchronous and batch completion delivery;
- fairness self-wake;
- complete/cancel race;
- orphan resource close;
- instance shutdown with pending work;
- unknown or mismatched completion as an ABI error.

Standard network tests cover:

- TCP full duplex and EOF;
- partial write with progress;
- one concurrent read and write;
- listener port zero and Accept/Close races;
- UDP address and truncation semantics;
- connected UDP peer filtering;
- deadline shortening, extension, clearing, and expiry;
- Close unblocking Read, Accept, and Receive;
- `errors.Is` mappings;
- race-detector execution.

Real embedded-WASM tests cover:

- overlay TCP dial and listen;
- overlay UDP packet connection;
- context cancellation and deadlines;
- repeated close;
- a non-overlay dial failure with a recording Host socket factory proving no
  data-plane direct connection occurred;
- idle operation with no drive turns other than genuine protocol deadlines.

Final Go validation includes:

```text
go test -count=1 ./...
go test -race ./...
go vet ./...
```

## Definition of done

The implementation is complete when:

- EasyTier owns all data-plane route, smoltcp, flow, and resource policy;
- optional native KCP selection and source-stream ownership are behind
  `DataPlaneRuntime`;
- SOCKS5 and port forwarding use Data Plane through explicit Adapters;
- public Go and new FFI data-plane calls are overlay-only;
- a Go data-plane TCP listener accepts smoltcp connections;
- native FFI can wait for any instance completion without per-operation
  polling;
- the Go caller sees only standard `net` interfaces;
- the Go driver is event driven and never re-entered from a Host callback;
- cancellation, deadline, close, and instance stop produce exactly one terminal
  operation outcome;
- the WASM artifact includes the smoltcp data plane and does not advertise
  KCP;
- the unused legacy data-plane FFI has been removed;
- all focused, Docker, race, ABI, and embedded-WASM tests pass;
- artifact provenance identifies the exact final EasyTier commit;
- no Mihomo-specific code exists in either repository.
