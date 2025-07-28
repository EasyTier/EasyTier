# EasyTier 贡献指南

[English Version](CONTRIBUTING.md)

感谢您对 EasyTier 项目的关注！本文档提供了参与项目贡献的指南和说明。

## 目录

- [EasyTier 贡献指南](#easytier-贡献指南)
  - [目录](#目录)
  - [开发环境配置](#开发环境配置)
    - [前置要求](#前置要求)
      - [必需工具](#必需工具)
      - [平台特定依赖](#平台特定依赖)
    - [安装步骤](#安装步骤)
  - [项目结构](#项目结构)
  - [构建指南](#构建指南)
    - [构建核心组件](#构建核心组件)
    - [构建桌面应用](#构建桌面应用)
    - [构建移动应用](#构建移动应用)
    - [构建注意事项](#构建注意事项)
  - [开发工作流](#开发工作流)
  - [测试指南](#测试指南)
    - [运行测试](#运行测试)
    - [测试要求](#测试要求)
  - [Pull Request 规范](#pull-request-规范)
  - [其他资源](#其他资源)
  - [需要帮助？](#需要帮助)

## 开发环境配置

### 前置要求

#### 必需工具
- Node.js v21 或更高版本
- pnpm v9 或更高版本
- Rust 工具链（版本 1.87）
- LLVM 和 Clang
- Protoc（Protocol Buffers 编译器）

#### 平台特定依赖

**Linux (Ubuntu/Debian)**
```bash
# 核心构建依赖
sudo apt-get update && sudo apt-get install -y \
    musl-tools \
    llvm \
    clang \
    protobuf-compiler

# GUI 构建依赖
sudo apt install -y \
    libwebkit2gtk-4.1-dev \
    build-essential \
    curl \
    wget \
    file \
    libgtk-3-dev \
    librsvg2-dev \
    libxdo-dev \
    libssl-dev \
    libappindicator3-dev \
    patchelf

# 测试依赖
sudo apt install -y bridge-utils
```

**交叉编译依赖**
- musl-cross 工具链（用于 MIPS 和其他架构）
- 可能需要额外配置（详见 `.github/workflows/` 目录）

**Android 开发依赖**
- Java 20
- Android SDK（Build Tools 34.0.0）
- Android NDK（26.0.10792818）

### 安装步骤

1. 克隆仓库：
   ```bash
   git clone https://github.com/EasyTier/EasyTier.git
   cd EasyTier
   ```

2. 安装依赖：
   ```bash
   # 安装 Rust 工具链
   rustup install 1.87
   rustup default 1.87

   # 安装项目依赖
   pnpm -r install
   ```

## 项目结构

```
easytier/          # 核心功能和库
easytier-web/      # Web 仪表盘和前端
easytier-gui/      # 桌面 GUI 应用
.github/workflows/ # CI/CD 配置文件
```

## 构建指南

### 构建核心组件

```bash
# 标准构建
cargo build --release

# 特定平台构建
cargo build --release --target x86_64-unknown-linux-musl     # Linux x86_64
cargo build --release --target aarch64-unknown-linux-musl    # Linux ARM64
cargo build --release --target x86_64-apple-darwin           # macOS x86_64
cargo build --release --target aarch64-apple-darwin          # macOS M1/M2
cargo build --release --target x86_64-pc-windows-msvc        # Windows x86_64
```

构建产物位置：`target/[target-triple]/release/`

### 构建桌面应用

```bash
# 1. 构建前端
pnpm -r build

# 2. 构建 GUI 应用
cd easytier-gui

# Linux
pnpm tauri build --target x86_64-unknown-linux-gnu

# macOS
pnpm tauri build --target x86_64-apple-darwin      # Intel
pnpm tauri build --target aarch64-apple-darwin     # Apple Silicon

# Windows
pnpm tauri build --target x86_64-pc-windows-msvc   # x64
```

构建产物位置：`easytier-gui/src-tauri/target/release/bundle/`

### 构建移动应用

```bash
# 1. 安装 Android 目标平台
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

# 2. 构建 Android 应用
cd easytier-gui
pnpm tauri android build
```

构建产物位置：`easytier-gui/src-tauri/gen/android/app/build/outputs/apk/universal/release/`

### 构建注意事项

1. ARM/MIPS 的交叉编译需要额外配置
2. Windows 构建需要正确的 DLL 文件
3. 详细构建配置请参考 `.github/workflows/` 目录

## 开发工作流

1. 从 `develop` 分支创建特性分支：
   ```bash
   git checkout develop
   git checkout -b feature/your-feature-name
   ```

2. 按照代码规范进行修改

3. 编写或更新测试

4. 使用规范的提交信息：
   ```
   feat: 添加新功能
   fix: 修复问题
   docs: 更新文档
   test: 添加测试
   chore: 更新依赖
   ```

5. 提交 Pull Request 到 `develop` 分支

## 测试指南

### 运行测试

```bash
# 配置系统（Linux）
sudo modprobe br_netfilter
sudo sysctl net.bridge.bridge-nf-call-iptables=0
sudo sysctl net.bridge.bridge-nf-call-ip6tables=0

# 运行测试
cargo test --no-default-features --features=full --verbose
```

### 测试要求

- 为新功能编写测试
- 维护现有测试覆盖率
- 测试应该是独立且可重复的
- 包含单元测试和集成测试

## Pull Request 规范

1. 目标分支为 `develop`
2. 确保所有测试通过
3. 包含清晰的描述和目的
4. 关联相关的 issues
5. 保持变更的原子性和聚焦性
6. 及时更新相关文档

## 其他资源

- [问题追踪](https://github.com/EasyTier/EasyTier/issues)
- [项目文档](https://github.com/EasyTier/EasyTier/wiki)

## 需要帮助？

欢迎：
- 提出问题
- 参与社区讨论
- 联系维护者

感谢您为 EasyTier 做出贡献！ 