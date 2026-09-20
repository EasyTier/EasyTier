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
authenticated as associated data; each write uses a fresh IV. `AtomicFile` provides
replacement/recovery, and the committed payload is read back before acknowledging
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
migrations leave the legacy data available for retry. Failed updates do not replace
the repository's last committed snapshot. Do not clear app data as an automatic
recovery action: it deletes the only native configuration copy. Downgrading to an
older build that only reads localStorage will not see migrated configurations.

Backend mode and its options are preserved verbatim. Loading an Android profile
no longer rewrites its mode to `normal`. Existing UI mode validation/connection
paths remain; no headless adapter is authorized to interpret remote, service, or
unknown modes as a local network. The future controller must check mode explicitly.

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
  TUN candidate selection, `no_tun` coexistence and VPN-stop event selection.
- Rust snapshot tests cover one-time migration, corrupt/future data, failed writes,
  backend preservation, invalid IDs and deletion of desired/selected state.
- Frontend tests cover native-first loading, migration/deletion ordering, retries,
  corrupt data, preference write ordering, and the existing mobile VPN/tile tests.
- Before release, device-test upgrading a configured installation, process restart,
  managed configuration updates, selection persistence, remote-mode UI operation,
  and storage failure handling. Check that the legacy Android localStorage keys
  are absent after successful migration, without printing decrypted credentials.
