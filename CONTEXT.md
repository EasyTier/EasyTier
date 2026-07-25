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
