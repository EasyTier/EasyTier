# CONTRIBUTING

Thank you for your interest in contributing to EasyTier! This document provides guidelines and instructions to help you set up your development environment and start contributing.

## Development Setup

Before you start contributing to the project, you need to set up your development environment. Here are the steps you need to follow:

### Prerequisites

**Install Rust and Node.js**: Our project requires both Rust and Node.js. Please follow the instructions provided [here](https://tauri.app/v1/guides/getting-started/prerequisites) to install them on your system.

### Install Node.js Package

After installing Rust and Node.js, install the necessary Node.js and Node Package Manager:

```shell
npm install pnpm -g
```

### Compile For Desktop (Win/Mac/Linux)

```
cd ./tauri-plugin-vpnservice
pnpm install
pnpm build

cd - && cd ./easytier-web/frontend-lib
pnpm install
pnpm build

cd - && cd ./easytier-gui
pnpm install
pnpm tauri build
```

### Compile For Android

Need to install android SDK / emulator / NDK / Java (easy with android studio)

```
# For ArchLinux
sudo pacman -Sy sdkmanager
sudo sdkmanager --install platform-tools platforms\;android-34 ndk\;r26 build-tools
export PATH=/opt/android-sdk/platform-tools:$PATH
export ANDROID_HOME=/opt/android-sdk/
export NDK_HOME=/opt/android-sdk/ndk/26.0.10792818/
rustup target add aarch64-linux-android

install java 20
```

Java version depend on gradle version specified in (easytier-gui\src-tauri\gen\android\build.gradle.kts)

See [Gradle compatibility matrix](https://docs.gradle.org/current/userguide/compatibility.html) for detail .

```
pnpm install
pnpm tauri android init
pnpm tauri android build
```
