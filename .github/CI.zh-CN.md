# CI

[English](CI.md)

| 触发方式 | Core | GUI | Mobile |
| --- | --- | --- | --- |
| 目标为 `main`/`develop` 的 PR，或 push 到这两个分支 | Linux x64、Windows x64、macOS ARM64 的 Core/Web `cargo check` | Linux 前端构建和 Rust 检查 | Android ARM64 前端构建和 Rust 检查 |
| Push 到 `releases/**`，或手动触发 | 16 个目标和 Magisk 产物 | 7 个目标的安装包 | 4 个架构的 APK |

Test 运行 CI 脚本测试、fmt、clippy、WASI、Cargo.lock 检查，以及
`easytier`/`easytier-core` 的 Linux 测试（含 `three_node`）。全量模式还逐个
检查 `easytier` 的 feature，排除 `macos-ne`。

这四个 workflow 的构建和测试任务跳过 draft PR。普通构建和 Rust 任务可因
无关路径或重复内容而跳过。汇总检查为 `core-result`、`gui-result`、
`mobile-result` 和 `test`。

PR 可上传供 CI 内部复用的 Web 前端和测试归档。Core 二进制、GUI 安装包、
APK 和 Magisk 产物仅在全量模式上传。编译产物启用缓存。普通 push 不会取消
全量构建。

## 每日构建

定时为北京时间 03:17。对实际存在的 `main`/`develop` 分支，分别检查 Core、
GUI、Mobile、Test：比较分支 HEAD 与该 workflow 最近一次成功的
`workflow_dispatch` 提交，相同则跳过，不同或无成功记录则触发该 workflow。
尚未成功构建的提交在下一轮继续触发。

Nightly 只负责触发，结果见对应 workflow。每日 Core 构建设置
`sign_windows: false`。

## 手动构建与发布

需要仓库 Write 权限。在 Actions 分别运行 Core、GUI、Mobile，选择 PR 分支
即可生成全量产物。该分支必须包含这些 workflow 定义。Fork PR 需要先在本
仓库建立临时分支。

手动 Core 构建默认开启 SignPath 测试签名（`sign_windows: true`）。
全量 macOS GUI 构建会签名和公证。

Release 是独立的手动 workflow。输入的 Core/GUI/Mobile run ID 必须分别来自
正确的 workflow、全量构建成功，且提交相同。它下载这些产物并创建 draft
release。

## 其他 workflow

- OHOS 独立运行，相关 PR 仍可上传 HAR。
- Go、JavaScript Hosts、Nix 使用各自的路径过滤。
- Docker 手动触发，下载指定 Core 构建的产物并推送镜像。
