# CI

[中文](CI.zh-CN.md)

| Trigger | Core | GUI | Mobile |
| --- | --- | --- | --- |
| PR targeting `main`/`develop`, or push to either branch | Core/Web `cargo check`: Linux x64, Windows x64, macOS ARM64 | Linux frontend build and Rust check | Android ARM64 frontend build and Rust check |
| Push to `releases/**`, or manual dispatch | 16 targets and Magisk artifacts | Installers for 7 targets | APKs for 4 architectures |

Test runs CI script tests, fmt, clippy, WASI, Cargo.lock validation, and
Linux tests for `easytier`/`easytier-core`, including `three_node`. Full mode
also checks each `easytier` feature except `macos-ne`.

Linux tests run on one runner with 32 concurrent nextest processes. Network
integration tests use separate namespaces and bridges for each test. Subnet
proxy cases run at most eight at a time. Tests that use host-wide network state,
measure bandwidth, or make time-sensitive connectivity assertions run first,
exclusively, before the parallel tests.

These four workflows skip build/test jobs for draft PRs. Path and duplicate
content checks can skip ordinary builds and Rust jobs. The result jobs are
`core-result`, `gui-result`, `mobile-result`, and `test`.

PR dashboard builds run only for frontend, Core configuration, schema, or
build configuration changes. Ordinary branch pushes build the dashboard.
Core checks run independently; Web embedding is compiled only in full mode.
Test skips the frontend build in ordinary mode; its test archive builds
only Rust packages.

PR runs can upload the test archive for reuse within CI. The dashboard is
uploaded only in full mode.
Core binaries, GUI installers, APKs, and Magisk artifacts require full mode.
Compilation outputs are cached. Ordinary pushes do not cancel full builds.

## Nightly

Scheduled at 03:17 Asia/Shanghai. Check Core, GUI, Mobile, and Test separately
on each existing `main`/`develop` branch. Compare HEAD with that workflow's
latest successful `workflow_dispatch` run: skip matching commits; dispatch
otherwise. Commits without a successful run are retried on the next check.

Nightly only dispatches jobs; results appear in the corresponding workflows.
Core's `sign_windows` is set to `false` for nightly builds.

## Manual builds and releases

Repository Write access is required. In Actions, run Core, GUI, and Mobile
separately on the PR branch to obtain full artifacts. The branch must contain
these workflow definitions. Fork PRs need a temporary branch in this repository.

Manual Core builds default to SignPath test signing (`sign_windows: true`).
Full macOS GUI builds are signed and notarized.

Release is a separate manual workflow. Its Core/GUI/Mobile run IDs must refer
to successful full builds from their respective workflows at the same commit.
It downloads their artifacts and creates a draft release.

## Other workflows

- OHOS runs independently; relevant PRs can still upload HAR artifacts.
- Go, JavaScript Hosts, and Nix use their own path filters.
- Docker is manual; it downloads a specified Core run's artifacts and pushes images.
