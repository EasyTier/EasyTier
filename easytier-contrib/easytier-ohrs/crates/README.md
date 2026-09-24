# HarmonyOS Rust package boundaries

`easytier-ohrs` keeps the single `.so`/HAR and N-API compatibility surface consumed by ArkTS, but its Rust implementation is split by responsibility:

- **`easytier-ohos-core`** owns the process Tokio runtime, `NativeInstanceManager`, runtime-state projections, kernel socket protocol DTOs, TUN route aggregation, and the platform handshake used to protect individual transport sockets. Code that starts, stops, observes, or translates EasyTier runtime state belongs here.
- **`easytier-ohos-features`** owns configuration persistence and migration, SQLite metadata/field storage, schema reflection, validation, import/export, and share links. Code that remains meaningful without a running EasyTier instance belongs here.
- **`easytier-ohrs`** is the platform facade. It owns N-API exports, HarmonyOS platform logging and nearby-management adapters, and the small amount of orchestration that passes a validated feature configuration into the kernel package.

## Dependency direction

```text
ArkTS/HAR
   |
easytier-ohrs (N-API facade)
   |                    |
   v                    v
easytier-ohos-core     easytier-ohos-features
```

The facade passes owned EasyTier configuration values into the kernel package when runtime state must be projected. The kernel and feature packages do not depend on each other, so another HarmonyOS application can reuse the kernel integration without pulling in this client's SQLite repository, migrations, schema UI metadata, or share-link services.

## Boundary rules

1. SQLite, schema reflection, import/export, and share-link code must not enter `easytier-ohos-core`.
2. Tokio runtime ownership, instance lifecycle, TUN attachment, kernel protocol, and runtime-state conversion must not enter `easytier-ohos-features`.
3. New ArkTS exports remain in the outer `easytier-ohrs` facade so the HAR continues to expose one stable native module.
4. Cross-package values should be owned DTOs/snapshots; feature code must not receive runtime-manager handles.
5. Kernel code must not read the feature package's repository or global storage state; the facade supplies the validated runtime values it needs.
6. The split is semantic and architectural. It is not presented as a configuration-page frame-time optimization.
