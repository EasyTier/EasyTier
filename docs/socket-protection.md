# Host socket protection

VPN bypass is a socket-creation requirement, not an operation on a socket that
core has already connected. Core and WASI guests never need an OS file descriptor.

## Portable requests

`BindConfig::need_protect` travels through the
existing connect/bind operations. A host requiring VPN bypass must acknowledge
successful protection before connect, bind/listen, or publishing the socket.
Failure or cancellation fails creation and discards the owned socket; emitting
an event alone is not acknowledgement. Platforms without VPN bypass can treat
the requirement as a no-op.

- TCP connect constructors request protection, including egress for proxies.
- TCP transport/hole-punch listeners request protection. Hosts retain this flag
  on the listener and protect accepted children before handing them to core.
- Local ProxyNat/SOCKS/port-forward/port-lease listeners do not request it.
- UDP transport, candidates, listeners, NAT egress and STUN request protection.
  Loopback control packets and inbound SOCKS associations explicitly opt out;
  UDP port-forward and port-lease sockets also opt out.
- `BindConfig` defaults to protection, including deserialization without
  `need_protect`. Local/TUN-facing endpoints set `false` explicitly.
- `with_bind()` replaces the **entire** bind object. A local listener's replacement
  must retain its opt-out rather than inherit the protected default. A native
  adapter must honor explicit `false`, not silently change it based on `purpose`.
- DNS and source-route queries are already host-owned operations. A bypass-enabled
  host must protect their underlying sockets before querying/probing, including
  DNS TCP fallback, rather than letting system DNS silently bypass this contract.

## TUN-facing ingress and port forwarding

The extra `force_smoltcp` wildcard port-forward ingress listener has been removed.
Normal TUN-backed ingress is delivered to the existing unprotected native listener;
its accepted sockets remain unprotected so overlay replies can return through TUN.
The physical/underlay egress socket is protected independently. A separate
DataPlane listener must not mask broken host/TUN routing in this path.

This does not remove the existing public DataPlane listener APIs, the generic
no-TUN smoltcp TCP proxy, or `force_smoltcp` itself. Those have other uses. Whether
Android subnet proxy works without forced smoltcp needs actual platform regression
testing; socket-creation unit tests alone do not establish that result.

## Native integration and HarmonyOS

The native `easytier` adapter implements the creation requirement using an async
`NativeSocketProtector` callback. This is a native implementation detail, not a
new portable or WASI ABI. It takes only the native handle; the creation options
select policy, without a second purpose enum. Namespace switching is confined to synchronous socket
creation and never held across the callback's await.

Core defines one portable `BindConfig` for TCP and UDP, passed to native hosts
or WASI encoding. Native hosts create sockets through
`easytier::socket::bind::<B>(BindConfig)`, an async function that creates,
protects, configures and binds the requested socket type. `BindConfig` is a
plain struct with public fields; callers build it with struct update syntax
over `Default`. There is no separate native builder.
Supplying `local_addr` binds TCP to that address; otherwise `context.ip_version`
selects its family and source selection is deferred to connect. TCP connect
requests set that family from their remote address before binding. UDP always
binds a source address, using the requested family when none is specified.
Native DNS and route probes use the same builder. Legacy WebSocket listeners
explicitly keep their unprotected policy.

`reuse_addr` is tri-state for both protocols: `None` selects the host default,
while `Some(false)` and `Some(true)` are authoritative. Native bound sockets
default to reuse on non-Windows hosts; unbound TCP sockets default to no reuse.
Callers select device/reuse policy by setting the fields when constructing the
configuration. The native host does not override those settings by inspecting an endpoint purpose
tag. Multi-address connection attempts clone the configuration and override
`local_addr` for each attempt.

The HarmonyOS broker wakes the already-pending request consumer with `Notify`
(no polling timer). It keeps a duplicate FD alive until ArkTS completes
`VpnConnection.protect(fd)` and returns its ACK. The waiting creation future is
woken immediately by the oneshot acknowledgement. Failure stays fail-closed;
shutdown retains dispatched FDs for late ACKs to prevent FD reuse races.
The ArkTS request shape is unchanged; its diagnostic `purpose` string is now
the generic `"socket"`. Neither ACK routing nor protection policy uses that label.

This guarantees ordering, not a wall-clock real-time bound: OS/ArkTS scheduling
can still delay protection. Such a delay keeps the socket unconnected; it must
never allow the first SYN/query to race ahead of protection.

## WASI option format

The `easytier_host` import names and function signatures are unchanged. TCP
connect/listen retain their version 3 bytes. UDP bind uses **version 4**:
`reuse_addr` uses the same 0=default, 1=disabled, 2=enabled encoding as TCP, and
the UDP purpose byte is removed. `need_protect` follows `only_v6`, before the
optional bind-device field. A minimal UDP document is 48 bytes. Other option
fields and DNS/environment/instance-config/data-plane layouts are unchanged.

The bundled Go host accepts UDP versions 3 and 4, translating the legacy purpose
defaults into the shared configuration at the version 3 boundary. Version 4
keeps explicit false distinct from a host default. Older hosts reject the new
UDP version instead of silently changing that request.

An embedding host must update its versioned option decoder and honor the flag
inside its existing creation implementation. The external host implementation
is not in this repository: building the guest proves propagation/compatibility
of imports, not that every external host has implemented platform protection.
