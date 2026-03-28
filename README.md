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

> ✨ A simple, secure, decentralized SD-WAN solution powered by Rust and Tokio

<p align="center">
  <img src="assets/config-page.png" width="300" alt="EasyTier configuration page">
  <img src="assets/running-page.png" width="300" alt="EasyTier running page">
</p>

🌐 **[Official Website](https://easytier.rs)** | 📚 **[Documentation](https://easytier.rs/en/)** | 🚀 **[Get Started](https://easytier.rs/en/guide/introduction.html)** | 📝 **[Download Releases](https://github.com/EasyTier/EasyTier/releases)** | 🇨🇳 **[China Site](https://easytier.cn)** | ❤️ **[Sponsor](#sponsor)**

## Get Started

### Install

Linux:

```bash
curl -fsSL "https://github.com/EasyTier/EasyTier/blob/main/script/install.sh?raw=true" | sudo bash -s install
```

Windows (run with administrator privileges):

```powershell
irm "https://github.com/EasyTier/EasyTier/blob/main/script/install.ps1?raw=true" | iex
```

Homebrew (macOS/Linux):

```bash
brew tap brewforge/chinese
brew install --cask easytier-gui
```

Install from source (latest development version):

```bash
cargo install --git https://github.com/EasyTier/EasyTier.git easytier
```

More installation options:

- [CLI installation guide](https://easytier.rs/en/guide/installation.html)
- [GUI installation guide](https://easytier.rs/en/guide/installation_gui.html)
- [Pre-built binaries](https://github.com/EasyTier/EasyTier/releases)
- [OpenWrt package](https://github.com/EasyTier/luci-app-easytier)
- [One-click register service](https://easytier.rs/en/guide/network/oneclick-install-as-service.html)

### Quick Example

Join the same network from multiple nodes with a shared public node:

```bash
# Node A
sudo easytier-core -d --network-name demo --network-secret demo -p tcp://<SharedNodeIP>:11010

# Node B
sudo easytier-core -d --network-name demo --network-secret demo -p tcp://<SharedNodeIP>:11010
```

Use the same `--network-name` and `--network-secret` on every node to join the same network. After startup, check peers with `easytier-cli peer`, `easytier-cli route`, or `easytier-cli node`.

## Why EasyTier

- 🔒 **Decentralized**: Nodes are equal and independent, with no centralized controller required.
- 🚀 **Easy to Use**: Use EasyTier from the web console, GUI clients, or the command line.
- 🌍 **Cross-Platform**: Supports Windows, macOS, Linux, FreeBSD, Android, and multiple CPU architectures.
- 🔐 **Secure**: Protects traffic with AES-GCM or WireGuard encryption.
- 🔌 **Efficient NAT Traversal**: Supports UDP and IPv6 traversal, including NAT4-to-NAT4 scenarios.
- 🌐 **Subnet Proxy**: Share private subnets with other nodes in the virtual network.
- 🔄 **Intelligent Routing**: Chooses lower-latency paths automatically for a better network experience.
- ⚡ **High Performance**: Uses zero-copy data paths and supports TCP, UDP, WS, WSS, WG, QUIC, and more.

## Learn More

- [Introduction](https://easytier.rs/en/guide/introduction.html)
- [Command line networking](https://easytier.rs/en/guide/networking.html)
- [Decentralized networking](https://easytier.rs/en/guide/network/decentralized-networking.html)
- [Networking with web console](https://easytier.rs/en/guide/network/web-console.html)
- [WireGuard client access](https://easytier.rs/en/guide/network/use-easytier-with-wireguard-client.html)
- [Subnet proxy (point-to-network)](https://easytier.rs/en/guide/network/point-to-networking.html)
- [Bandwidth and latency optimization](https://easytier.rs/en/guide/network/kcp-proxy.html)
- [Hosting public shared nodes](https://easytier.rs/en/guide/network/host-public-server.html)
- [Third-party graphical interfaces](https://easytier.rs/en/guide/installation_gui.html#third-party-graphical-interfaces)

## Community

- 💬 **[Telegram Group](https://t.me/easytier)**
- 👥 **QQ Groups**: [No.1 949700262](https://qm.qq.com/q/wFoTUChqZW), [No.2 837676408](https://qm.qq.com/q/4V33DrfgHe), [No.3 957189589](https://qm.qq.com/q/YNyTQjwlai)

## License

EasyTier is released under the [LGPL-3.0](https://github.com/EasyTier/EasyTier/blob/main/LICENSE).

## Sponsor

CDN acceleration and security protection for this project are sponsored by Tencent EdgeOne.

<p align="center">
  <a href="https://edgeone.ai/?from=github" target="_blank">
    <img src="assets/edgeone.png" width="200" alt="EdgeOne Logo">
  </a>
</p>

Special thanks to [Langlang Cloud](https://langlangy.cn/?i26c5a5) and [RainCloud](https://www.rainyun.com/NjM0NzQ1_) for sponsoring our public servers.

<p align="center">
  <a href="https://langlangy.cn/?i26c5a5" target="_blank">
    <img src="assets/langlang.png" width="200" alt="Langlang Cloud Logo">
  </a>
  <a href="https://www.rainyun.com/NjM0NzQ1_" target="_blank">
    <img src="assets/raincloud.png" width="200" alt="RainCloud Logo">
  </a>
</p>

If you find EasyTier helpful, please consider sponsoring us. Software development and maintenance require time and effort, and your sponsorship helps us keep improving EasyTier.

<p align="center">
  <img src="assets/wechat.png" width="200" alt="WeChat sponsor QR code">
  <img src="assets/alipay.png" width="200" alt="Alipay sponsor QR code">
</p>
