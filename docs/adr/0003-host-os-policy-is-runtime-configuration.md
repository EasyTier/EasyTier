# ADR-0003: Host-OS Policy Is Runtime Configuration

- Status: Accepted
- Date: 2026-07-10

## Context

OS-independent core means that core does not perform concrete system calls. It
does not mean all conditional compilation is forbidden. Core may need different
Implementation code for guest-target capabilities.

However, a wasm artifact always observes the WASI compilation target. It cannot
discover whether the Go host runs on Windows, Linux, macOS, Android, or OHOS
through Rust `cfg(target_os)` or `cfg(target_env)`.

Current examples include a Windows-dependent TCP reuse default in core and an
OHOS-specific packet-routing branch. These compile, but their behaviour is
incorrectly tied to the guest target when embedded.

## Decision

1. Permit `cfg` in core for guest-target capabilities and Implementation
   availability.
2. Represent host-OS policy as normalized runtime configuration consumed by
   core.
3. Let native Adapters derive that configuration with native `cfg` checks.
4. Let Go Adapters derive the same configuration from the actual Go host.
5. Allow core socket requests to describe policy such as netns tokens, socket
   marks, bind devices, or interface indices, but only the host may interpret
   those descriptions and perform the operation.

## Consequences

- One wasm artifact behaves correctly on different host operating systems.
- Core keeps policy decisions and tests while Host Adapters keep system calls.
- Existing target-specific product behaviour in core must migrate to explicit
  configuration as the surrounding Module is touched.
- Source checks should distinguish forbidden OS operations from allowed policy
  data; a blanket ban on all `cfg(target_*)` is not appropriate.

## Implementation update (2026-07-14)

The native host now has one process-level `NativeHostRuntime` for TCP, UDP,
listeners, DNS, Unix/FakeTCP resources, route probes, and interface discovery.
It does not retain `GlobalCtx` or instance netns/mark state. Callers clone one
shared `Arc`; they do not construct per-instance socket or DNS factories.

`SocketContext` is the request contract for IP family, exact optional socket
mark, and opaque netns token. Route probes and preferred-source discovery carry
the same context as the subsequent socket request. Linux namespace guards cover
only synchronous resource creation and never cross `await`; Tokio continues
asynchronous I/O after the guard is released.

Core's `ConnectorHostAdapter` composes that process runtime with a narrow native
`NativeInstanceEnvironment`. The environment projects only the immutable
`SocketContext` plus instance-owned mapped-listener, protected-port and managed
IPv6 facts. Byte-stream creation, route probes, interface observation and
preferred-source discovery all go through `NativeHostRuntime`; portable core
applies the preferred-source eligibility policy. Running listeners are absent
from this seam because the core listener registry is authoritative.

Interface observations are cached by the per-instance `ConnectorHostAdapter`,
not by `NativeHostRuntime`. Core keys entries by the complete `SocketContext`,
expires them after the existing 60-second observation window, and coalesces
concurrent misses per context without serializing unrelated contexts. This
keeps the process runtime stateless and prevents one
instance, socket mark, IP-family policy, or namespace lifecycle from reusing
another instance's observation.

## Rejected alternatives

### Ban all target conditionals from core

Rejected because guest-target capability differences are real and may require
conditional Implementation code.

### Keep host policy in target conditionals

Rejected because `wasm32-wasip1` conditionals describe the guest, not the OS
that embeds it.
