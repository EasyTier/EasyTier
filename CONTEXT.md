# EasyTier Domain Context

## Module layers

`easytier-core` layers dependencies from `foundation` upward through the
portable networking domains. `foundation` contains infrastructure Modules
that have no dependency on a networking domain and may be used by any higher
layer.

## Operation broker

An operation broker owns the lifecycle of asynchronous work submitted by an
external caller to core. It allocates opaque operation IDs, arbitrates
completion, cancellation, and disposal, retains terminal outcomes, and
publishes a batch-drainable completion queue.

The broker does not interpret operation kinds, outcomes, resources, wire
formats, or domain errors. Each domain Module owns those semantics and composes
the broker under the same lock as any state that must change atomically with an
operation transition.

Host capability operations use a separate seam. They turn Host readiness into
Rust task wakeups and do not share the caller-to-core broker state machine.

## Credential grant

A credential grant contains the authorization constraints shared by generated,
imported, managed, and attached-peer credentials: ACL groups, relay permission,
allowed proxy CIDRs, and whether concurrent reuse is allowed. It does not own
credential identity, key material, lifetime, persistence, or runtime ownership.
Each credential intake path normalizes the grant before installing it.

## Peer Relay advertisement

A platform peer may prefer an eligible directly connected credential relay by
omitting covered credential-leaf edges from only its own advertised OSPF
connection row. Its local route calculation still uses the complete physical
adjacency so direct-destination fallback remains available. Other peers'
source-owned rows and versions are never rewritten, cached for promotion, or
otherwise changed by this projection.

Before a graceful Instance stop, the owner publishes a new-version empty
connection row while keeping its physical adjacencies available for route
synchronization. It waits for the current direct route Sessions to acknowledge
that withdrawal up to a bounded deadline, then continues shutdown. Abrupt
process loss cannot publish this withdrawal and retains the normal route
expiry behavior.

Relay eligibility comes from the transport-authenticated credential identity
and grant, not self-reported route metadata. The advertisement Module does not
support changing a credential's relay permission in place; such a permission
change is a credential revocation and new authenticated Session.

## Attached peer

An attached peer is an ordinary `PeerManagerCore` connected to another
`PeerManagerCore` through an authenticated in-process transport. Each
authenticated portal client owns one complete peer manager. The managers are
protocol peers; `attached` describes only the local transport and its trusted
ingress provenance, not a parent/child peer role.

An attached peer owns one complete IPv4 CIDR (for example `10.144.0.5/16`).
Its address and advertised network are independent of the network manager's
own static or DHCP address. A VPN portal derives the attached peer route and
the external client's allowed network from that single CIDR; it does not infer
either value from the portal-hosting instance.

An external portal client uses that same IPv4 address on its native tunnel
interface. The portal validates the source address and forwards IPv4 packets
unchanged between the native tunnel and the attached peer; it does not assign
a second tunnel-only address or perform address translation.

Each manager owns its ACL execution state, route service, RPC endpoint, secure
sessions, packet processing, and lifecycle. Portal code supplies raw packets
and peer configuration but does not build, reload, or coordinate ACL filters.

When the network manager uses Secure Mode, an attached peer authenticates as a
credential peer. Its portal-owned, in-memory credential grant carries ACL
groups and is revoked with the attached runtime; the peer never receives the
network secret or ACL group secrets. A non-Secure-Mode network retains the
legacy admin-attached identity for compatibility. A credential peer cannot host
a portal because it cannot issue credential grants. Each live portal Session
owns a fresh attached-peer identity, while the external client key remains
stable across Sessions; a replacement Session must never reuse the previous
non-reusable credential identity.

## Compact compatibility Host

A compact compatibility Host retains accepted values in the authoritative TOML
model for management readback, while the shared host-aware normalization path
omits capabilities that the compact runtime cannot execute. Omitted settings
are silent no-ops and must not be advertised as live network capabilities.

## Web compatibility Host

The Web compatibility Host runs the portable EasyTier guest in JavaScript
runtimes that provide WebAssembly JSPI. Its shared runtime Module owns guest
lifecycle, Host capability operations, data-plane resources, and WebSocket
message handling. Browser and Cloudflare Adapters own only the platform-specific
way that WebSockets are dialed or accepted and the matching guest artifact.

The Browser Adapter is an outbound-only EasyTier instance with a smoltcp TCP
data plane. The Cloudflare Adapter is an inbound-only relay hosted by one named
Durable Object. Their public configuration exposes only capabilities each Host
can execute; guest ABI details and serialized TOML remain internal.
