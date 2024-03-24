# EasyTier

[![GitHub](https://img.shields.io/github/license/KKRainbow/EasyTier)](https://github.com/KKRainbow/EasyTier/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/KKRainbow/EasyTier)](https://github.com/KKRainbow/EasyTier/commits/main)

一个简单的即插即用的 ZeroTier 和 TailScale 替代方案，使用 Rust 语言和 Tokio 框架实现。

## 特点

- **去中心化**：无需依赖中心化服务，节点平等且独立。
- **易部署**：简单的安装步骤，支持多种安装方式。
- **智能路由**：根据流量智能选择链路，减少延迟，提高吞吐量。
- **突破限制**：在 UDP 受限环境下尝试使用 TCP 以获得更好的性能。
- **高可用性**：支持多路径和在检测到高丢包率或网络错误时切换到健康路径。

## 安装

EasyTier 支持 MacOS/Linux/Windows，后续将支持 IOS 和 Android。

1. **通过 crates.io 安装**：
   ```sh
   cargo install eastier
   ```
2. **通过源码安装：**:

git clone https://github.com/KKRainbow/EasyTier.git
cd EasyTier
cargo build
下载预编译的二进制文件：
访问 GitHub Release 页面 下载适用于您操作系统的二进制文件。

快速开始
第一个节点（假设公网 IP 为 100.1.1.1，虚拟 IP 为 10.144.144.1）：

sudo easytier-core -i 10.144.144.1
第二个节点：

sudo easytier-core --peers udp://100.1.1.1:1101
贡献
我们欢迎并鼓励社区贡献！如果你想参与进来，请提交 GitHub PR。只要 PR 通过 CI 检查，就可以被合并。

许可证
EasyTier 根据 Apache License 2.0 许可证发布。

联系方式
提问或报告问题：GitHub Issues
讨论和交流：GitHub Discussions
