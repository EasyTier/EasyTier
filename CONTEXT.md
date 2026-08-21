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

## Attached peer

An attached peer is an ordinary `PeerManagerCore` connected to another
`PeerManagerCore` through an authenticated in-process transport. Each
authenticated portal client owns one complete peer manager. The managers are
protocol peers; `attached` describes only the local transport and its trusted
ingress provenance, not a parent/child peer role.

Each manager owns its ACL execution state, route service, RPC endpoint, secure
sessions, packet processing, and lifecycle. Portal code supplies raw packets
and peer configuration but does not build, reload, or coordinate ACL filters.

When the network manager uses Secure Mode, an attached peer authenticates as a
credential peer. Its portal-owned, in-memory credential grant carries ACL
groups and is revoked with the attached runtime; the peer never receives the
network secret or ACL group secrets. A non-Secure-Mode network retains the
legacy admin-attached identity for compatibility. A credential peer cannot host
a portal because it cannot issue credential grants.

## Compact compatibility Host

A compact compatibility Host retains accepted values in the authoritative TOML
model for management readback, while the shared host-aware normalization path
omits capabilities that the compact runtime cannot execute. Omitted settings
are silent no-ops and must not be advertised as live network capabilities.
