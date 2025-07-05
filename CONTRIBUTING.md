# Contributing to EasyTier

[中文版](CONTRIBUTING_zh.md)

Thank you for your interest in contributing to EasyTier! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Development Environment Setup](#development-environment-setup)
  - [Prerequisites](#prerequisites)
  - [Installation Steps](#installation-steps)
- [Project Structure](#project-structure)
- [Build Guide](#build-guide)
  - [Building Core](#building-core)
  - [Building GUI](#building-gui)
  - [Building Mobile](#building-mobile)
- [Development Workflow](#development-workflow)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Guidelines](#pull-request-guidelines)
- [Additional Resources](#additional-resources)

## Development Environment Setup

### Prerequisites

#### Required Tools
- Node.js v21 or higher
- pnpm v9 or higher
- Rust toolchain (version 1.86)
- LLVM and Clang
- Protoc (Protocol Buffers compiler)

#### Platform-Specific Dependencies

**Linux (Ubuntu/Debian)**
```bash
# Core build dependencies
sudo apt-get update && sudo apt-get install -y \
    musl-tools \
    libappindicator3-dev \
    llvm \
    clang \
    protobuf-compiler

# GUI build dependencies
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
    patchelf

# Testing dependencies
sudo apt install -y bridge-utils
```

**For Cross-Compilation**
- musl-cross toolchain (for MIPS and other architectures)
- Additional setup may be required (see `.github/workflows/` for details)

**For Android Development**
- Java 20
- Android SDK (Build Tools 34.0.0)
- Android NDK (26.0.10792818)

### Installation Steps

1. Clone the repository:
   ```bash
   git clone https://github.com/EasyTier/EasyTier.git
   cd EasyTier
   ```

2. Install dependencies:
   ```bash
   # Install Rust toolchain
   rustup install 1.86
   rustup default 1.86

   # Install project dependencies
   pnpm -r install
   ```

## Project Structure

```
easytier/          # Core functionality and libraries
easytier-web/      # Web dashboard and frontend
easytier-gui/      # Desktop GUI application
.github/workflows/ # CI/CD configuration files
```

## Build Guide

### Building Core

```bash
# Standard build
cargo build --release

# Platform-specific builds
cargo build --release --target x86_64-unknown-linux-musl     # Linux x86_64
cargo build --release --target aarch64-unknown-linux-musl    # Linux ARM64
cargo build --release --target x86_64-apple-darwin           # macOS x86_64
cargo build --release --target aarch64-apple-darwin          # macOS M1/M2
cargo build --release --target x86_64-pc-windows-msvc        # Windows x86_64
```

Build artifacts: `target/[target-triple]/release/`

### Building GUI

```bash
# 1. Build frontend
pnpm -r build

# 2. Build GUI application
cd easytier-gui

# Linux
pnpm tauri build --target x86_64-unknown-linux-gnu

# macOS
pnpm tauri build --target x86_64-apple-darwin      # Intel
pnpm tauri build --target aarch64-apple-darwin     # Apple Silicon

# Windows
pnpm tauri build --target x86_64-pc-windows-msvc   # x64
```

Build artifacts: `easytier-gui/src-tauri/target/release/bundle/`

### Building Mobile

```bash
# 1. Install Android targets
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add i686-linux-android
rustup target add x86_64-linux-android

# 2. Build Android application
cd easytier-gui
pnpm tauri android build
```

Build artifacts: `easytier-gui/src-tauri/gen/android/app/build/outputs/apk/universal/release/`

### Build Notes

1. Cross-compilation for ARM/MIPS requires additional setup
2. Windows builds need correct DLL files
3. Check `.github/workflows/` for detailed build configurations

## Development Workflow

1. Create a feature branch from `develop`:
   ```bash
   git checkout develop
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards

3. Write or update tests as needed

4. Use conventional commit messages:
   ```
   feat: add new feature
   fix: resolve bug
   docs: update documentation
   test: add tests
   chore: update dependencies
   ```

5. Submit a pull request to `develop`

## Testing Guidelines

### Running Tests

```bash
# Configure system (Linux)
sudo modprobe br_netfilter
sudo sysctl net.bridge.bridge-nf-call-iptables=0
sudo sysctl net.bridge.bridge-nf-call-ip6tables=0

# Run tests
cargo test --no-default-features --features=full --verbose
```

### Test Requirements

- Write tests for new features
- Maintain existing test coverage
- Tests should be isolated and repeatable
- Include both unit and integration tests

## Pull Request Guidelines

1. Target the `develop` branch
2. Ensure all tests pass
3. Include clear description and purpose
4. Reference related issues
5. Keep changes focused and atomic
6. Update documentation as needed

## Additional Resources

- [Issue Tracker](https://github.com/EasyTier/EasyTier/issues)
- [Project Documentation](https://github.com/EasyTier/EasyTier/wiki)

## Questions or Need Help?

Feel free to:
- Open an issue for questions
- Join our community discussions
- Reach out to maintainers

Thank you for contributing to EasyTier! 