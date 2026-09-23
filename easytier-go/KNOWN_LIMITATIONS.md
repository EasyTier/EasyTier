# Known limitations

These edge cases are intentionally kept separate from feature changes so they
can be addressed without expanding unrelated patches.

## Port-forward bind conflicts

`InstanceConfigBuilder.Build` rejects exact duplicate port-forward rules, but
two rules with the same protocol and bind address and different destinations
are rejected later by `Instance.Start` when Core binds the second socket.
Callers should keep each `(protocol, bind address)` pair unique.

## Maximum UDP datagram reassembly

Core buffers can carry the maximum IPv4 UDP payload of 65,507 bytes. At the
current data-plane MTU this requires about 52 IPv4 fragments, while smoltcp can
track 16 disjoint reassembly segments. Extremely out-of-order delivery that
creates more than 16 holes can therefore drop an otherwise valid maximum-size
datagram. Ordered delivery is covered by the current tests.

## First inbound `ListenPacket` flow

An `Instance.ListenPacket` socket currently installs an exact UDP data-plane
flow after sending to a peer. A newly bound socket may not receive the first
datagram from a previously unseen peer until a reciprocal flow has been
established. This does not affect the TUN packet plane or Core port-forward
destinations reached through it.
