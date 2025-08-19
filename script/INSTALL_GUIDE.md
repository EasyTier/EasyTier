# EasyTier 安装脚本使用指南

## 📖 概述

`install.sh` 是 EasyTier 的官方安装脚本，提供了完整的安装、更新和卸载功能。该脚本支持多种配置模式和平台，能够自动处理系统服务配置。


## 🚀 快速开始

```bash
# 默认安装（配置文件）
./script/install.sh install

# 使用官方服务器（用户名）
./script/install.sh install -w myteam --machine-id server01

# 使用自定义服务器（完整URL）
./script/install.sh install -w udp://config.company.com:22020/myteam --machine-id server01
```

## 📋 命令说明

### 基本命令

| 命令 | 说明 |
|------|------|
| `install` | 安装 EasyTier 到系统路径 |
| `uninstall` | 从系统中完全卸载 EasyTier |
| `update` | 更新 EasyTier 到最新版本 |
| `help` | 显示帮助信息 |

### 安装路径

- **二进制文件**：`/usr/local/bin/`
- **配置文件**：`/etc/easytier/`
- **日志文件**：
  - macOS: `/var/log/easytier.log`
  - Linux: 通过 `journalctl` 查看

## ⚙️ 配置模式

EasyTier 安装脚本支持三种互斥的配置模式：

### 1. 配置文件模式（默认）

使用本地配置文件进行管理。

```bash
# 使用默认配置
./script/install.sh install

# 指定自定义配置文件
./script/install.sh install -c /etc/easytier/my-custom.conf
```

**特点：**
- ✅ 简单易用，适合单机部署
- ✅ 配置文件本地存储，离线可用
- ⚠️ 多机管理需要手动同步配置
- ⚠️ 修改配置文件后需要手动重启服务

### 2. 配置服务器模式（推荐）

连接到配置服务器进行集中管理。

```bash
# 使用官方服务器（用户名）
./script/install.sh install -w myteam --machine-id server01

# 使用自定义服务器（完整URL）
./script/install.sh install -w udp://config.company.com:22020/myteam --machine-id server01
```

**支持的URL格式：**
- **用户名格式**: `myteam` （使用官方服务器）
- **UDP**: `udp://server:port/user`
- **TCP**: `tcp://server:port/user`
- **HTTPS**: `https://server:port/user`

**特点：**
- ✅ 集中管理，配置自动同步
- ✅ 支持多设备统一配置
- ✅ 配置历史和版本控制
- ⚠️ 需要网络连接到配置服务器


## 🔧 参数详解

### 配置参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-c <PATH>` | 指定配置文件路径 | `-c /etc/easytier/custom.conf` |
| `-w <URL>` | 配置服务器模式：支持用户名或完整URL | `-w myteam` |

### 设备标识参数

| 参数 | 说明 | 适用模式 |
|------|------|----------|
| `--machine-id <ID>` | 设备唯一标识符 | 配置服务器模式 |

**Machine ID 作用：**
- 在配置服务器中唯一标识设备
- 支持配置恢复和设备管理
- 在 Web 界面中区分不同设备

### 网络参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `--no-gh-proxy` | 禁用 GitHub 代理（直连） | `--no-gh-proxy` |
| `--gh-proxy <URL>` | 自定义 GitHub 代理 | `--gh-proxy https://ghproxy.com/` |

**GitHub 代理说明：**
- **默认行为**：自动使用 `https://ghfast.top/` 代理加速下载
- **适用场景**：解决网络访问 GitHub 较慢或无法访问的问题
- **灵活配置**：可自定义代理或完全禁用

## 🖥️ 平台支持

### 支持的操作系统

| 操作系统 | 架构支持 | Init 系统 |
|----------|----------|-----------|
| **macOS** | x86_64, arm64 | launchd |
| **Linux** | x86_64, aarch64, armv7, mips*, loongarch64, riscv64 | systemd |
| **Alpine Linux** | x86_64, aarch64, armv7 | OpenRC |
| **Gentoo** | x86_64, aarch64, armv7 | OpenRC |

*支持 mips 和 mipsel 架构

### 系统要求

- **必需工具**: `curl`, `unzip`
- **权限**: root 权限（自动提升）
- **网络**: 需要访问 GitHub（下载二进制文件）

## 📝 使用示例

### 基础使用

```bash
# 查看帮助
./script/install.sh help

# 默认安装
./script/install.sh install

# 卸载
./script/install.sh uninstall

# 更新到最新版本
./script/install.sh update
```

### 配置文件模式

```bash
# 使用默认配置
./script/install.sh install

# 使用自定义配置文件
./script/install.sh install -c /path/to/my/config.conf

# 查看默认配置
cat /etc/easytier/default.conf

# 修改配置文件后需要重启服务
sudo systemctl restart easytier@default  # Linux
sudo launchctl unload /Library/LaunchDaemons/com.easytier.plist && sudo launchctl load /Library/LaunchDaemons/com.easytier.plist  # macOS
```

### 配置服务器模式

```bash
# 公司团队使用官方服务器
./script/install.sh install -w myteam --machine-id server01

# 使用自建配置服务器
./script/install.sh install -w udp://config.internal.com:22020/myteam --machine-id server01

```

### 网络代理设置

```bash
# 默认安装（使用默认代理 ghfast.top）
./script/install.sh install

# 配置服务器模式 + 默认代理
./script/install.sh install -w myteam --machine-id server01

# 禁用 GitHub 代理（直连）
./script/install.sh install --no-gh-proxy
./script/install.sh install -w myteam --machine-id server01 --no-gh-proxy

# 使用自定义代理
./script/install.sh install --gh-proxy https://ghproxy.com/
./script/install.sh install -w myteam --machine-id server01 --gh-proxy https://ghproxy.com/
```

## 🛠️ 服务管理

安装完成后，可以使用以下命令管理 EasyTier 服务：

### macOS (launchd)

```bash
# 查看服务状态
sudo launchctl list | grep easytier

# 停止服务
sudo launchctl unload /Library/LaunchDaemons/com.easytier.plist

# 启动服务
sudo launchctl load /Library/LaunchDaemons/com.easytier.plist

# 查看日志
tail -f /var/log/easytier.log
```

### Linux (systemd)

**单一服务模式**（配置服务器模式、参数模式）：
```bash
# 查看状态
systemctl status easytier

# 启动/停止/重启
systemctl start easytier
systemctl stop easytier
systemctl restart easytier

# 查看日志
journalctl -u easytier -f
```

**模板服务模式**（配置文件模式）：
```bash
# 查看状态
systemctl status easytier@default

# 启动/停止/重启
systemctl start easytier@default
systemctl stop easytier@default
systemctl restart easytier@default

# 查看日志
journalctl -u easytier@default -f

# 多实例管理
systemctl start easytier@production
systemctl start easytier@development
```

### Alpine/Gentoo (OpenRC)

```bash
# 查看状态
rc-service easytier status

# 启动/停止/重启
rc-service easytier start
rc-service easytier stop
rc-service easytier restart

# 开机自启
rc-update add easytier default
rc-update del easytier default
```

## 🔒 安全特性

### 安全验证

脚本包含多重安全验证机制：

1. **二进制文件验证**：
   - SHA256 校验和验证（从官方 SHA256SUMS 文件）
   - 确保下载文件完整性和一致性

2. **输入验证**：
   - 路径遍历攻击防护
   - 配置服务器 URL 格式验证
   - 特殊字符过滤

3. **连接测试**：
   - 配置服务器连通性测试（非阻塞）
   - 网络连接验证

### 权限管理

- 脚本自动请求 root 权限
- 二进制文件安装到系统路径
- 服务以适当权限运行

## ⚠️ 重要提醒

### 配置文件修改后重启服务

**注意**：修改配置文件后，服务不会自动重新加载配置，需要手动重启：

```bash
# Linux (systemd)
sudo systemctl restart easytier@default

# macOS (launchd)
sudo launchctl unload /Library/LaunchDaemons/com.easytier.plist
sudo launchctl load /Library/LaunchDaemons/com.easytier.plist

# Alpine/Gentoo (OpenRC)
sudo rc-service easytier restart
```

**原因**：EasyTier 在启动时读取配置文件，运行期间不会监控配置文件变化，这样设计是为了避免配置错误导致服务意外重启，保证网络连接的稳定性。

## 🐛 故障排除

### 常见问题

#### 1. 下载失败

```bash
# 问题：网络连接失败
# 解决：使用代理或禁用代理
./script/install.sh install --no-gh-proxy
./script/install.sh install --gh-proxy https://ghproxy.com/
```

#### 2. 权限问题

```bash
# 问题：Permission denied
# 解决：确保有 sudo 权限
sudo ./script/install.sh install
```

#### 3. 配置服务器连接失败

```bash
# 问题：配置服务器无法连接
# 解决：检查网络和防火墙设置
# 注意：连接测试失败不会阻止安装
```

#### 4. 服务启动失败

```bash
# 检查服务状态
systemctl status easytier

# 查看详细日志
journalctl -u easytier -n 50

# 检查配置文件
cat /etc/easytier/default.conf
```

### 日志查看

```bash
# macOS
tail -f /var/log/easytier.log

# Linux (systemd)
journalctl -u easytier -f
journalctl -u easytier@default -f

# 查看安装日志
journalctl -u easytier --since "1 hour ago"
```

### 完全重装

```bash
# 完全卸载并重新安装
./script/install.sh uninstall
./script/install.sh install
```


## 📚 高级配置

### 自定义配置文件

创建自定义配置文件 `/etc/easytier/production.conf`：

```toml
instance_name = "production"
dhcp = true
listeners = [
    "tcp://0.0.0.0:11010",
    "udp://0.0.0.0:11010",
    "wg://0.0.0.0:11011"
]

[[peer]]
uri = "tcp://public.easytier.top:11010"

[network_identity]
network_name = "production"
network_secret = "your-secret-here"

[flags]
enable_encryption = true
mtu = 1380
```

然后安装：
```bash
./script/install.sh install -c /etc/easytier/production.conf
```

### 多实例部署

```bash
# 安装多个实例（仅支持配置文件模式）
./script/install.sh install  # 创建模板服务

# 创建多个配置文件
sudo cp /etc/easytier/default.conf /etc/easytier/prod.conf
sudo cp /etc/easytier/default.conf /etc/easytier/dev.conf

# 启动多个实例
systemctl start easytier@prod
systemctl start easytier@dev
```


## 🔗 相关链接

- [EasyTier 官方文档](https://easytier.cn/guide/introduction.html)

## 📄 许可证

EasyTier 遵循 Apache 2.0 许可证。详情请查看项目根目录的 LICENSE 文件。

---

**最后更新**: 2025-08-19