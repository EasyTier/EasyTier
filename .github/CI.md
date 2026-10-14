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

Scheduled at 03:17 Asia/Shanghai, or started manually on `main`. Check Core,
GUI, Mobile, and Test separately. Compare main HEAD with that workflow's latest
successful `workflow_dispatch` run: skip matching commits; dispatch otherwise.
Core's `sign_windows` is set to `false` for nightly builds.

Nightly waits for the dispatched runs, retrying failed jobs once. A second
failure or a cancelled run fails Nightly and prevents publication. The build
and wait job has a three-hour timeout. Once all four components succeed at the
same commit, Nightly updates the rolling `nightly` prerelease using that commit,
even if main advances while builds are running. If main changes between the
dispatch requests and the builds target different commits, Nightly fails and
must be started again.

Builds dispatched with `GITHUB_TOKEN` do not trigger downstream `workflow_run`
jobs, so scheduled publication and retries run directly in Nightly. Completion
events still handle full main builds dispatched manually by a maintainer.
Nightly Release can also be started manually to publish existing main HEAD
builds without rebuilding them.

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

- OHOS runs independently. Relevant PRs run bridge tests and check the bindings
  for the host and ARM64 OHOS. Non-PR runs build and upload HAR artifacts;
  publishing and downstream builds retain their existing main/manual conditions.
- Go, JavaScript Hosts, and Nix use their own path filters.
- Docker is manual; it downloads a specified Core run's artifacts and pushes images.
