# ADR-0002: Go Host Drives WASI Core with Tokio Retained Internally

- Status: Accepted for Phase 0 validation
- Date: 2026-07-10

## Context

The target integration loads EasyTier into a Go process without cgo. The host
passes configuration and supplies DNS, TCP, UDP, and packet-plane capabilities.
Core owns the peer graph, protocols, routing, and connection orchestration.

Tokio 1.52 supports the `rt`, `time`, `sync`, `macros`, and `io-util` features on
WASM. The current `easytier-core` uses exactly this subset. Local verification
ran the existing wasm test artifacts with Go and wazero v1.12.0:

- 220 default/no-default tests passed;
- 239 all-feature tests passed;
- timer tests exercised WASI `clock_time_get` and `poll_oneoff`.

This proves that Tokio's current-thread scheduler, synchronization, and timers
run under a Go host. It does not prove that arbitrary Go socket and DNS
implementations can wake and drive a long-lived EasyTier instance efficiently.

wazero calls into a guest synchronously. Calls to the same exported function
must not overlap. A blocking host import pauses the only guest executor. Tokio's
current-thread runtime also stops making progress after the active drive
returns.

## Decision

1. Retain Tokio as an internal core Implementation.
2. Limit wasm builds to Tokio's supported current-thread feature subset.
3. Do not expose Tokio runtime handles or Rust futures across the Go/wasm seam.
4. Give each wasm core instance one serialized Go drive owner.
5. Express DNS and socket work as non-blocking operations completed during a
   later drive; do not call blocking Go network methods inside host imports.
6. Forbid host-to-guest re-entry from inside an import.
7. Use cooperative stop and operation cancellation. Context-triggered Module
   closure is only a hard watchdog.
8. Validate the exact drive/timer strategy in Phase 0 before more connectivity
   migration depends on it.

## Consequences

- Tokio-based core code does not need a wholesale executor rewrite before the
  PoC.
- Go owns real asynchronous I/O and completion queues.
- The wasm Adapter copies request data out of guest memory before an operation
  outlives a call and reacquires memory before copying a completion in.
- A fixed periodic drive may be used only as a measured PoC mechanism. It is not
  accepted as the final design without idle-CPU and latency evidence.
- `rt-multi-thread`, `spawn_blocking`, `block_in_place`, `tokio::net`, and
  blocking individual host imports are outside the supported wasm model.

## Phase 0 unresolved decision

Phase 0 must compare bounded cooperative drive with a centralized multiplexed
wait. The accepted design will be the one that preserves timer progress,
avoids head-of-line blocking, provides clean cancellation, and meets measured
idle-CPU and latency budgets without busy polling.

## Rejected alternatives

### Remove Tokio before validating the host seam

Rejected because current tests prove the supported Tokio subset works, and a
rewrite would touch widespread task and timer code without first proving it is
necessary.

### Block in each socket or DNS import

Rejected because one pending read or accept would freeze all peer, timer,
reconnect, and shutdown tasks in that wasm instance.

### Concurrent or re-entrant calls into one wasm instance

Rejected because wazero function calls are not safe to overlap and core state is
designed for one serialized owner.

## References

- <https://docs.rs/tokio/1.52.1/src/tokio/lib.rs.html#424-455>
- <https://tokio.rs/tokio/topics/bridging>
- <https://wazero.io/languages/>
- <https://pkg.go.dev/github.com/tetratelabs/wazero/api#Function>
- <https://doc.rust-lang.org/nightly/rustc/platform-support/wasm32-wasip1.html>
