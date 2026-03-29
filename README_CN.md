# EasyTier

[![Github release](https://img.shields.io/github/v/tag/EasyTier/EasyTier)](https://github.com/EasyTier/EasyTier/releases)
[![GitHub](https://img.shields.io/github/license/EasyTier/EasyTier)](https://github.com/EasyTier/EasyTier/blob/main/LICENSE)
[![GitHub last commit](https://img.shields.io/github/last-commit/EasyTier/EasyTier)](https://github.com/EasyTier/EasyTier/commits/main)
[![GitHub issues](https://img.shields.io/github/issues/EasyTier/EasyTier)](https://github.com/EasyTier/EasyTier/issues)
[![GitHub Core Actions](https://github.com/EasyTier/EasyTier/actions/workflows/core.yml/badge.svg)](https://github.com/EasyTier/EasyTier/actions/workflows/core.yml)
[![GitHub GUI Actions](https://github.com/EasyTier/EasyTier/actions/workflows/gui.yml/badge.svg)](https://github.com/EasyTier/EasyTier/actions/workflows/gui.yml)
[![GitHub Test Actions](https://github.com/EasyTier/EasyTier/actions/workflows/test.yml/badge.svg)](https://github.com/EasyTier/EasyTier/actions/workflows/test.yml)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/EasyTier/EasyTier)

[简体中文](/README_CN.md) | [English](/README.md)

> ✨ 一个由 Rust 和 Tokio 驱动的简单、安全、去中心化 SD-WAN 组网方案

🌐 **[官网文档](https://easytier.cn)** | 🚀 **[快速开始](https://easytier.cn/guide/introduction.html)** | 📝 **[下载发布版本](https://github.com/EasyTier/EasyTier/releases)** | 🌍 **[国际站](https://easytier.rs)** | ❤️ **[赞助](#赞助)**

## 快速开始

### 安装

Linux：

```bash
curl -fsSL "https://github.com/EasyTier/EasyTier/blob/main/script/install.sh?raw=true" | sudo bash -s install
```

Windows（请使用管理员权限运行）：

```powershell
irm "https://github.com/EasyTier/EasyTier/blob/main/script/install.ps1?raw=true" | iex
```

Homebrew（macOS/Linux）：

```bash
brew tap brewforge/chinese
brew install --cask easytier-gui
```

通过 cargo 安装（最新开发版本）：

```bash
cargo install --git https://github.com/EasyTier/EasyTier.git easytier
```

更多安装方式：

- [CLI 安装文档](https://easytier.cn/guide/installation.html)
- [GUI 安装文档](https://easytier.cn/guide/installation_gui.html)
- [下载预编译文件](https://github.com/EasyTier/EasyTier/releases)
- [OpenWrt 插件](https://github.com/EasyTier/luci-app-easytier)
- [一键注册系统服务](https://easytier.cn/guide/network/oneclick-install-as-service.html)

### 最小示例

使用共享公共节点，让多台设备加入同一个网络：

```bash
# 节点 A
sudo easytier-core -d --network-name demo --network-secret demo -p tcp://<共享节点IP>:11010

# 节点 B
sudo easytier-core -d --network-name demo --network-secret demo -p tcp://<共享节点IP>:11010
```

所有节点使用相同的 `--network-name` 和 `--network-secret` 即可加入同一个网络。启动后可通过 `easytier-cli peer`、`easytier-cli route` 或 `easytier-cli node` 查看状态。

## 为什么选择 EasyTier

- 🔒 **去中心化**：节点平等独立，无需中心化控制器。
- 🚀 **易于使用**：支持 Web 控制台、图形界面和命令行多种使用方式。
- 🌍 **跨平台**：支持 Windows、macOS、Linux、FreeBSD、Android 和多种 CPU 架构。
- 🔐 **安全**：支持 AES-GCM 或 WireGuard 加密，保护网络通信。
- 🔌 **高效 NAT 穿透**：支持 UDP、IPv6 穿透，可打通 NAT4-NAT4 场景。
- 🌐 **子网代理**：可将私有子网共享给虚拟网络中的其他节点访问。
- 🔄 **智能路由**：自动选择更优链路，降低延迟并提升体验。
- ⚡ **高性能**：全链路零拷贝，支持 TCP、UDP、WS、WSS、WG、QUIC 等协议。

## 深入了解

- [简介](https://easytier.cn/guide/introduction.html)
- [命令行组网](https://easytier.cn/guide/networking.html)
- [去中心化组网](https://easytier.cn/guide/network/decentralized-networking.html)
- [通过 Web 控制台组网](https://easytier.cn/guide/network/web-console.html)
- [使用 WireGuard 客户端接入](https://easytier.cn/guide/network/use-easytier-with-wireguard-client.html)
- [子网代理](https://easytier.cn/guide/network/point-to-networking.html)
- [带宽与延迟优化](https://easytier.cn/guide/network/kcp-proxy.html)
- [自建公共共享节点](https://easytier.cn/guide/network/host-public-server.html)
- [第三方图形界面](https://easytier.cn/guide/installation_gui.html#%E7%AC%AC%E4%B8%89%E6%96%B9%E5%9B%BE%E5%BD%A2%E7%95%8C%E9%9D%A2)

## 社区

- 💬 **[Telegram 群组](https://t.me/easytier)**
- 👥 **QQ 群**：[一群 949700262](https://qm.qq.com/q/wFoTUChqZW)、[二群 837676408](https://qm.qq.com/q/4V33DrfgHe)、[三群 957189589](https://qm.qq.com/q/YNyTQjwlai)

## 许可证

EasyTier 在 [LGPL-3.0](https://github.com/EasyTier/EasyTier/blob/main/LICENSE) 许可下发布。

## 赞助

本项目的 CDN 加速和安全防护由腾讯云 EdgeOne 赞助。

<p align="center">
  <a href="https://edgeone.ai/?from=github" target="_blank">
    <img src="assets/edgeone.png" width="200" alt="EdgeOne Logo">
  </a>
</p>

特别感谢 [浪浪云](https://langlangy.cn/?i26c5a5) 和 [雨云](https://www.rainyun.com/NjM0NzQ1_) 赞助我们的公共服务器。

<p align="center">
  <a href="https://langlangy.cn/?i26c5a5" target="_blank">
    <img src="assets/langlang.png" width="200" alt="浪浪云 Logo">
  </a>
  <a href="https://www.rainyun.com/NjM0NzQ1_" target="_blank">
    <img src="assets/raincloud.png" width="200" alt="雨云 Logo">
  </a>
</p>

如果您觉得 EasyTier 有帮助，欢迎赞助我们。软件开发和维护需要持续投入，您的支持将帮助我们更好地维护和改进 EasyTier。

<p align="center">
  <img src="assets/wechat.png" width="200" alt="微信赞助二维码">
  <img src="assets/alipay.png" width="200" alt="支付宝赞助二维码">
</p>
