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

## Rejected alternatives

### Ban all target conditionals from core

Rejected because guest-target capability differences are real and may require
conditional Implementation code.

### Keep host policy in target conditionals

Rejected because `wasm32-wasip1` conditionals describe the guest, not the OS
that embeds it.
