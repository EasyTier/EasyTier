# Android application management foundation

This is the first stage of [#2538](https://github.com/EasyTier/EasyTier/issues/2538),
not the headless lifecycle controller itself.

## Ownership

- `easytier-core::management::application_client` owns the application-level
  configuration/source rules and the existing pre/post hooks. It accepts an
  already-connected RPC tunnel; it does not create a runtime or instance manager.
- `ManagementHost` supplies event delivery, the single-TUN platform policy, and
  instance-event observation. The GUI adapter remains responsible for Tauri and
  subscribing to the existing `NativeInstanceManager`.
- `ConfigRepository` supplies durable configuration/desired-enabled storage.
  Desktop keeps its existing event/localStorage adapter. Android uses the shared
  versioned `SnapshotRepository` and an encrypted native storage adapter.
- The existing GUI commands and web-client hooks both use `ApplicationClient`.
  There is no new JNI start/stop path, independent instance manager, or runtime.

The extracted rules retain user/web/legacy provenance (including old `webhook`
values), conservative ownership merging, one Android TUN, coexistence with
multiple `no_tun` networks, and user/legacy TUN precedence over managed TUNs.

## Persistence and migration

The version-1 snapshot contains backend profile options, configurations and their
sources, desired-enabled IDs, and the selected network. Desired-enabled IDs are
intent, **not** evidence of a running instance or an attached Android TUN. This
change does not automatically replay that intent after process death.

Android stores the whole snapshot in `noBackupFilesDir/management-v1.enc` using
AES-256-GCM with a non-exportable Android Keystore key. A versioned envelope is
authenticated as associated data; each write uses a fresh IV. AndroidX `AtomicFile`
provides `.new` replacement/recovery on all supported Android versions, and the
committed payload is read back before acknowledging
success. The service-side helper takes only a `Context`, not an Activity/WebView.
The current Rust transport adapter uses Tauri; a later thin JNI adapter can supply
the same `SnapshotBackend` without changing the schema or application rules.

At startup the UI asks for existing native state **before parsing localStorage**.
Only an absent native snapshot permits importing the legacy configuration list,
backend profile and selection. All records are validated before commit. The UI
deletes its legacy plaintext entries only after successful native persistence and
keeps subsequent preferences in memory; configuration events no longer recreate a
plaintext Android localStorage copy. Logical removal does not promise secure
erasure of old WebView/database or external backup remnants.

Unreadable ciphertext, unavailable keys, invalid snapshots and newer schema
versions are errors, not permission to overwrite with defaults. Failed initial
migrations leave the legacy data available for retry. Failures before commit roll
back only the pending write. After entering commit, verification failure never
calls `failWrite`: the new file may already be the only valid copy. The repository
marks its cached snapshot uncertain and must reload and validate native state
before another read or mutation; failed refresh blocks stale-cache writes.
Do not clear app data as an automatic
recovery action: it deletes the only native configuration copy. Downgrading to an
older build that only reads localStorage will not see migrated configurations.

Backend mode and its options are preserved verbatim. Loading an Android profile
no longer rewrites its mode to `normal`. Existing UI mode validation/connection
paths remain; no headless adapter is authorized to interpret remote, service, or
unknown modes as a local network. The future controller must check mode explicitly.

## Runtime results and persistence warnings

UI start/stop/remove commands use a narrow transport around the **same** connected
RPC manager. Required configuration is saved before start preparation or replacing
an existing VPN. Disconnect does not require a successful disk write. Once a
runtime operation succeeds, observed running state and the existing post hooks are
updated before best-effort persistence. Web post-start/remove hooks follow the same
ordering. Editing a saved profile does not mark an instance running.

`OperationOutcome` separates confirmed runtime application from persistence and
reconciliation warnings. `get_management_status` exposes observed IDs, desired
enabled IDs, whether runtime state is known, and the last outcome. The UI receives
warnings by event and queries them on its existing status timer, so a missed event
does not lose the warning. A persistence failure cannot undo a completed stop;
the latest in-memory intent is retried on a later operation, not an old captured
snapshot. Until persistence succeeds, process death can still lose those changes.

RPC reconnection is not an application restart: it replaces only the mutation/query
transport, retaining configurations, desired intent and persistence warnings in the
existing application client. It does not reload an older durable snapshot or replay
desired starts. Runtime observations become unconfirmed until reconciliation with
the new connection. A later configuration reload still must flush pending intent
successfully before reading durable state; if storage remains unavailable, it fails
without discarding the in-memory changes.

An RPC error is not proof that the operation had no effect. Query actual instance
IDs and trigger the existing VPN reconciliation path before returning the error.
If querying also fails, expose unknown runtime state and block further starts
until it can be confirmed; stopping remains available. The published instance
state is **not** proof that Android has attached a TUN. Native VPN reconciliation
still belongs to the existing UI path. The generic `RemoteClientManager` mutation
defaults are not used by these application commands; other consumers are unchanged.

## Follow-up boundaries

Still required by #2538:

1. One serialized command/state owner for UI, tile, revoke and recovery.
2. A service-owned foreground entry point and a thin JNI transport into that owner.
3. Native TUN reconciliation, cancellation, authoritative published state, and
   reuse of the same Rust runtime when an Activity attaches later.
4. Explicit recovery policy (including permission, locked-device and unsupported
   backend handling); never treat Android force-stop as self-recoverable.

This PR deliberately leaves the UI-backed VPN reconciliation, tile cold-start
behavior and foreground-service lifecycle unchanged. The snapshot repository
serializes persistence updates; it is not a lifecycle serializer.

## Validation

- Rust application-client tests cover source compatibility, managed/user priority,
  TUN candidate selection, `no_tun` coexistence and VPN-stop event selection, plus
  disk/event failures, lost RPC replies, unknown runtime state, and latest-intent retry.
  The GUI's shared connect/reconnect entry point is tested with a real snapshot
  repository after runtime deletion and failed persistence, including repeated
  reconnects, unavailable storage and eventual successful persistence.
- Rust snapshot tests cover one-time migration, corrupt/future data, failed writes,
  backend preservation, invalid IDs, deletion of desired/selected state, and
  refresh/blocking after an uncertain commit.
- Kotlin JVM tests exercise the actual AndroidX atomic-file algorithm, including
  first-write interruption, legacy backup recovery, sync failure and post-commit
  verification failure. These do not replace API-level/device validation.
- `node --test tauri-plugin-vpnservice/tests/command-contract.test.mjs` checks every
  direct Rust mobile command against Kotlin `@Command` names. JavaScript invoke
  identifiers remain unchanged. This is a contract test, not a native bridge smoke test.
- Frontend tests cover native-first loading, migration/deletion ordering, retries,
  corrupt data, preference write ordering, and the existing mobile VPN/tile tests.
- Before release, device-test upgrading a configured installation, process restart,
  managed configuration updates, selection persistence, remote-mode UI operation,
  and storage failure handling. Check that the legacy Android localStorage keys
  are absent after successful migration, without printing decrypted credentials.
- Device validation must also exercise the native command bridge, first-write
  interruption on API 24/28 and a recent API level, and successful VPN stop while
  snapshot writes fail. JVM tests and Android-target compilation cannot prove these.
