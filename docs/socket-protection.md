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
- The low-level `TcpBindOptions::default()` is unprotected. `with_bind()` replaces
  the **entire** bind object; callers constructing an outbound replacement must
  preserve/set `need_protect`. `with_need_protect(false)` is an explicit override,
  not something a native adapter should silently replace based on `purpose`.
- DNS and source-route queries are already host-owned operations. A bypass-enabled
  host must protect their underlying sockets before querying/probing, including
  DNS TCP fallback, rather than letting system DNS silently bypass this contract.

## Native integration and HarmonyOS

The native `easytier` adapter implements the creation requirement using an async
`NativeSocketProtector` callback. This is a native implementation detail, not a
new portable or WASI ABI. The callback's purpose is diagnostic; the creation
options select policy. Namespace switching is confined to synchronous socket
creation and never held across the callback's await.

The HarmonyOS broker wakes the already-pending request consumer with `Notify`
(no polling timer). It keeps a duplicate FD alive until ArkTS completes
`VpnConnection.protect(fd)` and returns its ACK. The waiting creation future is
woken immediately by the oneshot acknowledgement. Failure stays fail-closed;
shutdown retains dispatched FDs for late ACKs to prevent FD reuse races.

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
