# Mihomo WASI Core Constraints

## Source And Boundary

This document records the constraints implied by the mihomo EasyTier outbound
discussion:

- Issue: <https://github.com/MetaCubeX/mihomo/issues/2875>
- Comment: <https://github.com/MetaCubeX/mihomo/issues/2875#issuecomment-4818588541>

The document is only about constraints on EasyTier core. It does not define an
implementation route, migration order, or release plan.

The target integration is a mihomo outbound that can run EasyTier inside a Go
host without cgo and without loading arbitrary native libraries. The host must
be able to control network I/O and name resolution so that mihomo can preserve
its own routing, DNS, loop-prevention, platform policy, and security model.

## Hard Constraints

EasyTier core must not require the embedding host to use cgo.

EasyTier core must not require runtime loading of a custom `.so`, `.dylib`, or
`.dll` as the target mihomo integration mechanism. Native FFI can remain as a
compatibility surface for existing users, but it cannot be the target core
architecture for mihomo.

EasyTier core must be able to compile for `wasm32-wasip1` and run in a WASI
hosted environment. The wasm target is the portability constraint for this
integration; native platform behavior must sit outside core.

EasyTier core must not create real OS sockets by itself. This includes TCP
dial, TCP listen, TCP accept, UDP bind, UDP send/recv, and any other platform
network handle creation.

EasyTier core must not perform DNS resolution by itself. This includes
`ToSocketAddrs`, `tokio::net::lookup_host`, hickory resolver usage, SRV lookup,
system resolver access, and any helper that hides these operations.

EasyTier core must not depend on TUN devices, netns, socket mark, platform
service managers, platform DNS settings, CLI, TOML loading, or host file-system
configuration as part of its control-plane or data-plane implementation.

EasyTier core must not assume that it owns the process network namespace or the
device routing table. In an embedded proxy host, those decisions belong to the
host.

## Interface Constraints

DNS-dependent decisions may live in core, but DNS implementation must be
provided by the host. Core may ask for address resolution through an explicit
resolver interface and then apply EasyTier safety rules to the returned
addresses.

Socket-dependent behavior may live in core, but socket implementation must be
provided by the host. Core may own peer state, handshake state, routing state,
proxy state, and packet transformation rules, but actual dial/listen/bind/read
and write operations must cross a host-provided adapter interface.

The host network adapter interface must be expressive enough for the host to
enforce routing and loop-prevention policy before real I/O occurs. Core must not
bypass the host adapter through convenience helpers.

The data-plane interface exposed to the host must be host-driven. TCP, UDP, and
packet-oriented operations should be expressed as stable calls or streams that a
WASI host can poll, drive, cancel, and map into Go-side abstractions.

Core interfaces must distinguish these cases explicitly:

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
loading, credential persistence, management API presentation, library/module
distribution, and security policy around loading code.

Runtime adapters may cache or present core state, but they must not become a
parallel source of truth for EasyTier routing or peer connectivity.

If state is needed for packet routing correctness across multiple call sites, it
belongs behind a core interface rather than being reconstructed in host or
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

Core source must remain free of DNS implementation calls:

```bash
rg 'Url::socket_addrs|ToSocketAddrs|lookup_host|lookup_ip|hickory_resolver' easytier-core/src
```

Core source must remain free of real OS socket implementations. Socket-like
traits and in-memory or smoltcp-internal virtual sockets are acceptable only
when they do not create host OS sockets.

The target mihomo-facing architecture is not satisfied merely because native
FFI data-plane APIs exist. Those APIs can remain as compatibility support, but
the mihomo target requires a host-controlled WASI/wasm-compatible core surface.
