# CI

[English](CI.md)

| 触发方式 | Core | GUI | Mobile |
| --- | --- | --- | --- |
| 目标为 `main`/`develop` 的 PR，或 push 到这两个分支 | Linux x64、Windows x64、macOS ARM64 的 Core/Web `cargo check` | Linux 前端构建和 Rust 检查 | Android ARM64 前端构建和 Rust 检查 |
| Push 到 `releases/**`，或手动触发 | 16 个目标和 Magisk 产物 | 7 个目标的安装包 | 4 个架构的 APK |

Test 运行 CI 脚本测试、fmt、clippy、WASI、Cargo.lock 检查，以及
`easytier`/`easytier-core` 的 Linux 测试（含 `three_node`）。全量模式还逐个
检查 `easytier` 的 feature，排除 `macos-ne`。

Linux 测试使用一个 runner，nextest 总并发度为 32。网络集成测试为每个测试
创建独立的 namespace 和网桥。子网代理用例最多同时运行八个；带宽测试、
使用宿主机全局网络状态的测试和时间敏感的连通性测试优先独占
执行，完成后再运行并发测试。

这四个 workflow 的构建和测试任务跳过 draft PR。普通构建和 Rust 任务可因
无关路径或重复内容而跳过。汇总检查为 `core-result`、`gui-result`、
`mobile-result` 和 `test`。

PR 仅在前端、Core 配置源码、schema 或构建配置变化时构建 Web 前端。
普通分支 push 仍构建 Web 前端。Core 检查独立运行；Web 的嵌入模式仅在
全量构建中编译。
Test 在普通模式下跳过前端构建，测试归档仅构建 Rust 包。

PR 可上传供 CI 内部复用的测试归档。Web 前端仅在全量模式上传。
Core 二进制、GUI 安装包、APK 和 Magisk 产物仅在全量模式上传。编译产物
启用缓存。普通 push 不会取消全量构建。

## 每日构建

定时为北京时间 03:17，也可以在 `main` 上手动运行。分别检查 Core、GUI、
Mobile、Test：比较 main HEAD 与该 workflow 最近一次成功的
`workflow_dispatch` 提交，相同则跳过，不同或无成功记录则触发该 workflow。
每日 Core 构建设置 `sign_windows: false`。

Nightly 等待已触发的构建结束，失败任务自动重试一次。再次失败或取消会使
Nightly 失败并阻止发布，构建和等待任务的超时为三小时。四个组件在同一提交
上全部成功后，Nightly 使用该提交更新固定的 `nightly` 预发布版本，即使等待
期间 main 已有新提交。如果 main 在各次触发请求之间变化，导致构建提交不
一致，Nightly 会失败，需要重新运行。

`GITHUB_TOKEN` 触发的构建不会触发下游 `workflow_run` 任务，因此定时构建的
发布和重试直接由 Nightly 执行。维护者手动触发的 main 全量构建仍由完成事件
处理。也可手动运行 Nightly Release，使用 main HEAD 的现有成功构建直接发布。

Nightly 的产物名称和压缩包目录结构与版本发布保持一致。Core、Web 和 Magisk
ZIP 文件名包含构建提交中的版本号，例如 `easytier-linux-x86_64-v2.7.0.zip`。
GUI 安装包和 Android APK 保留原始文件名，不再套一层 ZIP。`SHA256SUMS`
包含所有下载文件的校验值。项目版本变化时产物下载地址也会变化，可通过固定的
`nightly` 发布页面查找当前文件。

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

- OHOS 独立运行。相关 PR 运行桥接单测，并检查宿主平台和 ARM64 OHOS 的绑定。
  非 PR 构建生成并上传 HAR；发布和下游构建仍按原有主线/手动触发条件执行。
- Go、JavaScript Hosts、Nix 使用各自的路径过滤。
- Docker 手动触发，下载指定 Core 构建的产物并推送镜像。
