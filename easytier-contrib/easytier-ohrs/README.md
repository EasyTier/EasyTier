# OpenHarmonyOS 项目构建说明

本项目需要 OpenHarmonyOS SDK 和多个基础库支持才能成功编译。请按照以下步骤准备构建环境。
如存在任何编译问题，请前往[Easytier for OHOS](https://github.com/FrankHan052176/EasyTier)

## 前置要求

### 1. 安装 OpenHarmonyOS SDK

**SDK 下载链接**：  
[OpenHarmony 每日构建版本](https://ci.openharmony.cn/workbench/cicd/dailybuild/dailylist)

**版本要求**：  
请选择版本号 **小于 OpenHarmony_5.1.0.58** 的 ohos-sdk-full 版本

下载后请解压到适当位置（如 `/usr/local/ohos-sdk`），并记下安装路径。

### 2. 编译依赖库
在编译本项目前，需要先自行编译以下四个基础库：

- glib
- libffi
- pcre2
- zlib

这些库需要使用 OpenHarmonyOS 的工具链进行交叉编译。

## 环境配置

### 1. 设置环境变量
创建并运行以下脚本设置环境变量（请根据您的实际 SDK 安装路径修改）：

```bash
#!/bin/bash
# 请修改为您的实际 SDK 路径
export OHOS_SDK_PATH="/usr/local/ohos-sdk/linux"
export OHOS_TOOLCHAIN_DIR="${OHOS_SDK_PATH}/native/llvm"
export TARGET_ARCH="aarch64-linux-ohos"
export OHOS_SYSROOT="${OHOS_SDK_PATH}/native/sysroot"
export CC="${OHOS_TOOLCHAIN_DIR}/bin/aarch64-unknown-linux-ohos-clang"
export CXX="${OHOS_TOOLCHAIN_DIR}/bin/aarch64-unknown-linux-ohos-clang++"
export AS="${OHOS_TOOLCHAIN_DIR}/bin/llvm-as"
export AR="${OHOS_TOOLCHAIN_DIR}/bin/llvm-ar"
export LD="${OHOS_TOOLCHAIN_DIR}/bin/ld.lld"
export RANLIB="${OHOS_TOOLCHAIN_DIR}/bin/llvm-ranlib"
export STRIP="${OHOS_TOOLCHAIN_DIR}/bin/llvm-strip"
export OBJDUMP="${OHOS_TOOLCHAIN_DIR}/bin/llvm-objdump"
export OBJCOPY="${OHOS_TOOLCHAIN_DIR}/bin/llvm-objcopy"
export NM="${OHOS_TOOLCHAIN_DIR}/bin/llvm-nm"
export CFLAGS="-fPIC -D__MUSL__=1 -march=armv8-a --target=${TARGET_ARCH} -Wno-error --sysroot=${OHOS_SYSROOT} -I${OHOS_SYSROOT}/usr/include/${TARGET_ARCH}"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="--sysroot=${OHOS_SYSROOT} -L${OHOS_SYSROOT}/usr/lib/${TARGET_ARCH} -fuse-ld=${LD}"
export PKG_CONFIG_PATH="${OHOS_SYSROOT}/usr/lib/pkgconfig:${OHOS_SYSROOT}/usr/local/lib/pkgconfig"
export PKG_CONFIG_LIBDIR="${OHOS_SYSROOT}/usr/lib:${OHOS_SYSROOT}/usr/local/lib"
export PKG_CONFIG_SYSROOT_DIR="${OHOS_SYSROOT}"
export HOST_TRIPLET="${TARGET_ARCH}"
export BUILD_TRIPLET="$(dpkg-architecture -qDEB_BUILD_GNU_TYPE)"
export PATH="${OHOS_TOOLCHAIN_DIR}/bin:${PATH}"

echo "OpenHarmonyOS 环境变量已设置:"
echo "OHOS_SDK_PATH: ${OHOS_SDK_PATH}"
echo "OHOS_TOOLCHAIN_DIR: ${OHOS_TOOLCHAIN_DIR}"
echo "OHOS_SYSROOT: ${OHOS_SYSROOT}"
echo "PKG_CONFIG_PATH: ${PKG_CONFIG_PATH}"
echo "PATH: ${PATH}"
