#!/bin/bash

# EasyTier Android JNI 构建脚本
# 用于编译适用于 Android 平台的 JNI 库

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

REPO_ROOT=$(git rev-parse --show-toplevel)

echo -e "${GREEN}EasyTier Android JNI 构建脚本${NC}"
echo "=============================="

# 检查 Rust 是否安装
if ! command -v rustc &> /dev/null; then
    echo -e "${RED}错误: 未找到 Rust 编译器，请先安装 Rust${NC}"
    exit 1
fi

# 检查 cargo 是否安装
if ! command -v cargo &> /dev/null; then
    echo -e "${RED}错误: 未找到 Cargo，请先安装 Rust 工具链${NC}"
    exit 1
fi

# Android 目标架构
# TARGETS=("aarch64-linux-android" "armv7-linux-androideabi" "i686-linux-android" "x86_64-linux-android")
TARGETS=("aarch64-linux-android")

# 检查是否安装了 Android 目标
echo -e "${YELLOW}检查 Android 目标架构...${NC}"
for target in "${TARGETS[@]}"; do
    if ! rustup target list --installed | grep -q "$target"; then
        echo -e "${YELLOW}安装目标架构: $target${NC}"
        rustup target add "$target"
    else
        echo -e "${GREEN}目标架构已安装: $target${NC}"
    fi
done

# 创建输出目录
OUTPUT_DIR="./target/android"
mkdir -p "$OUTPUT_DIR"

# 构建函数
build_for_target() {
    local target=$1
    echo -e "${YELLOW}构建目标: $target${NC}"
    
    # 设置环境变量
    export CC_aarch64_linux_android="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"
    export CC_armv7_linux_androideabi="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang"
    export CC_i686_linux_android="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android21-clang"
    export CC_x86_64_linux_android="$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang"
    
    # 首先构建 easytier-ffi
    echo -e "${YELLOW}构建 easytier-ffi for $target${NC}"
    (cd $REPO_ROOT/easytier-contrib/easytier-ffi && cargo build --target="$target" --release)
    
    # 设置链接器环境变量
    export RUSTFLAGS="-L $(readlink -f $REPO_ROOT/target/$target/release) -l easytier_ffi"
    echo $RUSTFLAGS
    
    # 构建 JNI 库
    cargo build --target="$target" --release
    
    # 复制库文件到输出目录
    local arch_dir
    case $target in
        "aarch64-linux-android")
            arch_dir="arm64-v8a"
            ;;
        "armv7-linux-androideabi")
            arch_dir="armeabi-v7a"
            ;;
        "i686-linux-android")
            arch_dir="x86"
            ;;
        "x86_64-linux-android")
            arch_dir="x86_64"
            ;;
    esac
    
    mkdir -p "$OUTPUT_DIR/$arch_dir"
    cp "$REPO_ROOT/target/$target/release/libeasytier_android_jni.so" "$OUTPUT_DIR/$arch_dir/"
    echo -e "${GREEN}库文件已复制到: $OUTPUT_DIR/$arch_dir/${NC}"
}

# 检查 Android NDK
if [ -z "$ANDROID_NDK_ROOT" ]; then
    echo -e "${RED}错误: 未设置 ANDROID_NDK_ROOT 环境变量${NC}"
    echo "请设置 ANDROID_NDK_ROOT 指向您的 Android NDK 安装目录"
    echo "例如: export ANDROID_NDK_ROOT=/path/to/android-ndk"
    exit 1
fi

if [ ! -d "$ANDROID_NDK_ROOT" ]; then
    echo -e "${RED}错误: Android NDK 目录不存在: $ANDROID_NDK_ROOT${NC}"
    exit 1
fi

echo -e "${GREEN}使用 Android NDK: $ANDROID_NDK_ROOT${NC}"

# 构建所有目标
echo -e "${YELLOW}开始构建所有目标架构...${NC}"
for target in "${TARGETS[@]}"; do
    build_for_target "$target"
done

echo -e "${GREEN}构建完成！${NC}"
echo -e "${GREEN}所有库文件已生成到: $OUTPUT_DIR${NC}"
echo ""
echo "目录结构:"
ls -la "$OUTPUT_DIR"/*/

echo ""
echo -e "${YELLOW}使用说明:${NC}"
echo "1. 将生成的 .so 文件复制到您的 Android 项目的 src/main/jniLibs/ 目录下"
echo "2. 将 java/com/easytier/jni/EasyTierJNI.java 复制到您的 Android 项目中"
echo "3. 在您的 Android 代码中调用 EasyTierJNI 类的方法"