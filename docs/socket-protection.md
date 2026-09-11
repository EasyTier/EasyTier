# Host socket protection

VPN bypass is a socket-creation requirement, not an operation on a socket that
core has already connected. Core and WASI guests never need an OS file descriptor.

## Portable requests

`TcpBindOptions::need_protect` and `UdpBindOptions::need_protect` travel through the
existing connect/bind operations. A host requiring VPN bypass must acknowledge
successful protection before connect, bind/listen, or publishing the socket.
Failure or cancellation fails creation and discards the owned socket; emitting
an event alone is not acknowledgement. Platforms without VPN bypass can treat
the requirement as a no-op.

- TCP connect constructors request protection, including egress for proxies.
- TCP transport/hole-punch listeners request protection. Hosts retain this flag
  on the listener and protect accepted children before handing them to core.
- Local ProxyNat/SOCKS/port-forward/port-lease listeners do not request it.
- UDP transport, candidates, listeners, NAT egress and STUN request protection;
  HolePunchControl, local SOCKS/port-forward and port-lease sockets do not.
- Low-level TCP/UDP bind options default to protection, including deserialization
  of options without `need_protect`. The named local/TUN-facing constructors set
  `false` explicitly. The UDP default keeps its historical purpose label for
  socket setup; only the named `hole_punch_control()` constructor opts out.
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

The existing native `bind` builder is async and shared by TCP/UDP creation. Its
legacy direct-call default remains unprotected; portable factories explicitly
pass their core bind options (default protected). Callers must await `.call()`.
TCP listeners reuse TCP socket creation then listen, instead of duplicating the
setup. Existing legacy WebSocket direct-call policy is unchanged.

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
connect, TCP listen and UDP bind use option document **version 3** (previously 2):
one `u8` boolean `need_protect` is inserted immediately after the existing purpose
byte and before the optional bind-device field. All other field encodings and
purpose values are unchanged. The document version lets older hosts reject
unsupported options instead of silently ignoring protection. DNS, environment,
instance-config and data-plane layouts/versions are unchanged.

An embedding host must update its versioned option decoder and honor the flag
inside its existing creation implementation. The external host implementation
is not in this repository: building the guest proves propagation/compatibility
of imports, not that every external host has implemented platform protection.
