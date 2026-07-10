# Mihomo WASI Core Constraints

> Status: accepted constraint input. See the
> [authoritative refactor index](../../../refactor-doc/README.md) for current
> decisions, migration order, and Implementation status.

## Source And Scope

This document records the constraints implied by the mihomo EasyTier outbound
discussion:

- Issue: <https://github.com/MetaCubeX/mihomo/issues/2875>
- Comment: <https://github.com/MetaCubeX/mihomo/issues/2875#issuecomment-4818588541>

The document is only about constraints on EasyTier core. It does not define an
Implementation route, migration order, or release plan.

The target integration is a mihomo outbound that can run EasyTier inside a Go
host without cgo and without loading arbitrary native libraries. The host must
control socket creation and name resolution so that mihomo can preserve its own
routing, DNS, loop-prevention, platform policy, and security model. It retains
resource ownership and observability without taking over EasyTier I/O
scheduling.

## Hard Constraints

EasyTier core must not require the embedding host to use cgo.

EasyTier core must not require runtime loading of a custom `.so`, `.dylib`, or
`.dll` as the target mihomo integration mechanism. Native FFI can remain as a
compatibility surface for existing users, but it cannot be the target core
architecture for mihomo.

EasyTier core must be able to compile for `wasm32-wasip1` and run in a WASI
hosted environment. The wasm target is the portability constraint for this
integration; native platform behavior must sit outside core.

EasyTier core must not create real OS sockets by itself. TCP dial, TCP listen,
TCP accept, UDP bind, and every other platform network resource creation must be
authorized and implemented by the host. Core may drive asynchronous read/write
through a host-backed Socket Interface, but the resulting OS operations still
execute through the host or WASI.

EasyTier core must not perform DNS resolution by itself. This includes
`ToSocketAddrs`, `tokio::net::lookup_host`, hickory resolver usage, SRV lookup,
system resolver access, and any helper that hides these operations.

EasyTier core must not depend on TUN devices, netns, socket mark, platform
service managers, platform DNS settings, CLI, TOML loading, or host file-system
configuration as part of its control-plane or data-plane Implementation.

EasyTier core must not assume that it owns the process network namespace or the
device routing table. In an embedded proxy host, those decisions belong to the
host.

## Interface Constraints

DNS-dependent decisions may live in core, but DNS Implementation must be
provided by the host. Core may ask for address resolution through an explicit
Resolver Interface and then apply EasyTier safety rules to the returned
addresses.

Socket-dependent behavior may live in core, but real socket resources must be
provided by the host. Core owns peer state, handshake state, routing state,
proxy state, packet transformation rules, read/write scheduling, and
backpressure. Creation and actual OS operations cross the Socket seam through a
host-provided Adapter; crossing that seam does not transfer scheduling or
protocol ownership to the host.

The socket creation Interface must be expressive enough for the host to enforce
routing and loop-prevention policy when a real resource is created. Core must
not bypass the Host Adapter through convenience helpers.

The socket Interface must be host-authorized and host-backed, but it need not be
host-scheduled. TCP, UDP, and packet-oriented I/O should be expressed as
asynchronous sockets that core and Tokio can poll while the WASI host retains
resource ownership, observability, cancellation, and mapping to Go
abstractions.

A Go `net.Conn` or `net.PacketConn` may be a logical wrapper rather than a raw
OS descriptor. The wasm socket seam must preserve such wrapper behavior instead
of requiring descriptor extraction that would bypass Mihomo policy.

Core Interfaces must distinguish these cases explicitly:

- IP literals resolved without DNS.
- Hostnames resolved by the host.
- Non-IP transports that should not undergo IP-network checks.
- Resolution unavailable because the host disabled or cannot provide DNS.

For unavailable resolution, core should preserve existing tolerant behavior
where the decision does not require a resolved address. Resolution failure must
not accidentally become a hidden connection failure unless the specific rule
requires an address.

## State Ownership Constraints

Peer graph ownership belongs in EasyTier core. Runtime or host code must not
maintain a second authoritative `PeerMap`, `PeerManager`, next-hop table, or
peer connection registry.

PeerSession, peer RPC dispatch, request/response matching, route state,
credential trust state in memory, foreign-network state, relay state, traffic
classification state, and proxy NAT/routing state belong in core when they are
not intrinsically tied to OS resources.

Runtime and host code own platform resources and policy: socket creation, DNS
strategy, TUN integration, netns, socket mark, service lifecycle, config file
loading, credential persistence, management Interface presentation,
library/module distribution, and security policy around loading code.

Runtime adapters may cache or present core state, but they must not become a
parallel source of truth for EasyTier routing or peer connectivity.

If state is needed for packet routing correctness across multiple call sites, it
belongs behind a core Interface rather than being reconstructed in host or
runtime glue.

## Security Constraints

The target integration must not ask mihomo users to configure an arbitrary
native library path. A configurable native library path has the same practical
security problem as allowing arbitrary code loading inside the proxy process.

The target integration should treat the EasyTier executable payload as a fixed
or host-controlled module, not a user-selected native extension. Versioning,
hashing, signing, or bundling policy belongs to the host/runtime distribution
layer, not to core.

Core must not hide host-observable network behavior behind native side effects.
The host must be able to audit and control when outbound sockets are created,
which names are resolved, and which destination addresses are contacted.

## Acceptance Constraints

The core crates must keep passing wasm checks:

```bash
cargo check -p easytier-proto --target wasm32-wasip1
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features
```

When proxy packet or smoltcp-backed data-plane code is involved, the relevant
feature checks must also pass:

```bash
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features --features proxy-packet
cargo check -p easytier-core --target wasm32-wasip1 --no-default-features --features proxy-smoltcp-stack
```

Core source must remain free of DNS Implementation calls:

```bash
rg 'Url::socket_addrs|ToSocketAddrs|lookup_host|lookup_ip|hickory_resolver' easytier-core/src
```

Core source must remain free of real OS socket implementations. Socket-like
traits, a WASI Socket Adapter over host-provided resources, and in-memory or
smoltcp-internal virtual sockets are acceptable. None may create a host OS
socket while bypassing the Host Adapter.

The target mihomo-facing architecture is not satisfied merely because native
FFI data-plane APIs exist. Those APIs can remain as compatibility support, but
the mihomo target requires a host-controlled WASI/wasm-compatible core surface.
