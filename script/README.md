# EasyTier 管理脚本

这是一个用于管理 EasyTier VPN 的命令行工具，提供了完整的安装、配置和管理功能。

## 快速开始

### 一键安装

使用以下任一命令安装：

bash
使用国内镜像加速

bash <(curl -sL https://ghp.ci/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)
备用镜像

bash <(curl -sL https://mirror.ghproxy.com/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

bash <(curl -sL https://hub.gitmirror.com/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

bash <(curl -sL https://gh.ddlc.top/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

bash <(curl -sL https://gh.api.99988866.xyz/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

如果以上镜像都无法访问，可以使用原始地址

bash <(curl -sL https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)



如果遇到 GitHub 访问问题，可以尝试修改 hosts：


## 功能特性

1. 安装管理
   - 自动安装 EasyTier
   - 检查并更新到最新版本
   - 完全卸载（可选保留配置）

2. 配置管理
   - 创建新配置
   - 修改现有配置
   - 删除配置
   - 查看配置
   - 备份/恢复配置

3. 服务管理
   - 启动/停止服务
   - 重启服务
   - 查看服务状态
   - 查看服务日志

## 配置模式说明

### 1. 服务器模式
- 用于创建您自己的私有网络节点服务器
- 适合拥有公网IP的服务器，作为网络的中心节点
- 可以创建和管理您自己的私有网络

### 2. 客户端模式
- 用于连接到已有的网络节点
- 可以连接到您的私有服务器或其他公开的节点
- 支持多种连接协议：TCP、UDP、WebSocket、WebSocket SSL

### 3. 公共服务器模式
- 加入公共服务器节点集群，服务于社区
- 建议具有稳定公网IP的服务器选择此模式
- 您的节点将帮助其他用户获得更好的网络体验
- 自动配置为公共网络参数

### 4. 公共客户端模式
- 连接到公共节点集群网络
- 特别适合没有公网IP的用户
- 可以利用公共节点集群获得稳定的网络服务
- 支持选择或使用全部公共节点
- 默认启用延迟优先模式

## 系统要求

- 支持的系统：Linux (需要 systemd)
- 支持的架构：x86_64, aarch64, armv7, arm, mips, mipsel
- 需要 root 权限运行

## 使用建议

1. 服务器部署：
   - 选择具有公网IP的服务器
   - 确保防火墙开放相应端口
   - 建议使用服务器模式或公共服务器模式

2. 客户端使用：
   - 根据需求选择合适的模式
   - 记录网络名称和密钥信息
   - 可以使用多种协议连接

3. 网络优化：
   - 合理设置MTU值
   - 选择合适的连接协议
   - 必要时启用延迟优先模式

## 常见问题

1. 无法连接服务器？
   - 检查网络名称和密钥是否正确
   - 确认服务器端口是否开放
   - 验证服务器是否正常运行

2. 连接速度慢？
   - 尝试不同的连接协议
   - 启用延迟优先模式
   - 选择地理位置较近的节点

3. 配置文件在哪里？
   - 默认路径：/opt/easytier/config/
   - 所有配置文件以 .conf 结尾
   - 可以通过配置管理功能查看

## 技术支持

如有问题，请访问：
- GitHub: https://github.com/CGG888/EasyTier
- 官网：https://www.easytier.top

## 许可证

本脚本遵循 MIT 许可证开源。





主要更新：
添加了完整的安装命令，包含多个国内镜像源
添加了 hosts 修改建议
保持了其他内容不变
需要我继续完善其他部分吗？