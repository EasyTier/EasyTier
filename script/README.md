# EasyTier 配置管理脚本

这是一个用于管理 EasyTier VPN 配置的 Shell 脚本集合。

## 安装方法

使用以下任一命令安装：

#### 使用国内镜像加速

bash <(curl -sL https://ghp.ci/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)


备用镜像

bash <(curl -sL https://mirror.ghproxy.com/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

bash <(curl -sL https://hub.gitmirror.com/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

bash <(curl -sL https://gh.ddlc.top/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

bash <(curl -sL https://gh.api.99988866.xyz/https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

如果以上镜像都无法访问，可以使用原始地址

bash <(curl -sL https://raw.githubusercontent.com/CGG888/EasyTier/main/script/easytier.sh)

### 使用国内镜像加速


## 功能特性

- 创建和管理 EasyTier 配置
- 支持服务器模式、客户端模式和公共服务器模式
- 自动生成和管理 systemd 服务文件
- 配置文件备份和恢复
- WireGuard 配置生成和管理
- 支持配置二维码生成（PNG格式和终端显示）

## 配置模式

1. 服务器模式
   - 创建私有网络节点服务器
   - 适合拥有公网IP的服务器
   - 支持 WireGuard 配置生成

2. 客户端模式
   - 连接到现有网络节点
   - 支持连接私有服务器或社区公共节点
   - 支持 WireGuard 客户端配置

3. 公共服务器模式
   - 加入公共服务器节点集群
   - 适合具有稳定公网IP的服务器

## WireGuard 支持

- 自动生成 WireGuard 配置文件
- 配置文件保存在 /opt/easytier/wireguard/ 目录
- 支持生成二维码（需要安装 qrencode）
  - PNG 格式二维码保存在 /opt/easytier/wireguard/ 目录
  - 支持在终端直接显示二维码
- 配置文件命名格式：{config_name}_wg.conf
- 二维码文件命名格式：{config_name}_wg.png

## 使用说明

1. 配置管理
     ```

2. 创建新配置
   - 选择配置模式（服务器/客户端/公共服务器）
   - 按照提示输入必要信息
   - 配置文件将自动生成并保存

3. WireGuard 配置
   - 在创建配置时选择启用 WireGuard
   - 配置文件和二维码将自动生成
   - 可以通过手机扫描二维码快速导入配置

## 文件位置

- 主程序：/opt/easytier/
- 配置文件：/opt/easytier/config/
- WireGuard 配置：/opt/easytier/wireguard/
- 服务文件：/etc/systemd/system/easytier@*.service
- 运行时目录：/run/easytier/
- 备份文件：$HOME/.easytier_backup/

## 依赖

- systemd
- curl
- qrencode (用于生成 WireGuard 配置二维码)

## 注意事项

1. 请确保系统已安装所需依赖
2. WireGuard 配置生成需要安装 qrencode
3. 建议定期备份重要配置
4. 修改配置后需要重启相应服务
5. 请妥善保管网络密钥和配置信息

## 许可证

MIT License
