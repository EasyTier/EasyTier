#!/usr/bin/env bash

# env needed:
# - TARGET
# - GUI_TARGET
# - OS

# dependencies are only needed on ubuntu as that's the only place where
# we make cross-compilation
if [[ $OS =~ ^ubuntu.*$ ]]; then
    sudo apt-get update && sudo apt-get install -qq crossbuild-essential-arm64 crossbuild-essential-armhf musl-tools libappindicator3-dev llvm clang
    #  curl -s musl.cc | grep mipsel
    case $TARGET in
    mipsel-unknown-linux-musl)
        MUSL_URI=mipsel-linux-muslsf
        ;;
    mips-unknown-linux-musl)
        MUSL_URI=mips-linux-muslsf
        ;;
    aarch64-unknown-linux-musl)
        MUSL_URI=aarch64-linux-musl
        ;;
    armv7-unknown-linux-musleabihf)
        MUSL_URI=armv7l-linux-musleabihf
        ;;
    armv7-unknown-linux-musleabi)
        MUSL_URI=armv7m-linux-musleabi
        ;;
    arm-unknown-linux-musleabihf)
        MUSL_URI=arm-linux-musleabihf
        ;;
    arm-unknown-linux-musleabi)
        MUSL_URI=arm-linux-musleabi
        ;;
    esac

    if [ -n "$MUSL_URI" ]; then
        mkdir -p ./musl_gcc
        wget -c https://musl.cc/${MUSL_URI}-cross.tgz -P ./musl_gcc/
        tar zxf ./musl_gcc/${MUSL_URI}-cross.tgz -C ./musl_gcc/
        sudo ln -s $(pwd)/musl_gcc/${MUSL_URI}-cross/bin/*gcc /usr/bin/
        sudo ln -s $(pwd)/musl_gcc/${MUSL_URI}-cross/${MUSL_URI}/include/ /usr/include/musl-cross
    fi
fi

# see https://github.com/rust-lang/rustup/issues/3709
rustup set auto-self-update disable
rustup install 1.84
rustup default 1.84

# mips/mipsel cannot add target from rustup, need compile by ourselves
if [[ $OS =~ ^ubuntu.*$ && $TARGET =~ ^mips.*$ ]]; then
    cd "$PWD/musl_gcc/${MUSL_URI}-cross/lib/gcc/${MUSL_URI}/11.2.1" || exit 255
    # for panic-abort
    cp libgcc_eh.a libunwind.a

    # for mimalloc
    ar x libgcc.a _ctzsi2.o _clz.o _bswapsi2.o
    ar rcs libctz.a _ctzsi2.o _clz.o _bswapsi2.o

    rustup toolchain install nightly-x86_64-unknown-linux-gnu
    rustup component add rust-src --toolchain nightly-x86_64-unknown-linux-gnu

    # https://github.com/rust-lang/rust/issues/128808
    # remove it after Cargo or rustc fix this.
    RUST_LIB_SRC=$HOME/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/src/rust/
    if [[ -f $RUST_LIB_SRC/library/Cargo.lock && ! -f $RUST_LIB_SRC/Cargo.lock ]]; then 
        cp -f $RUST_LIB_SRC/library/Cargo.lock $RUST_LIB_SRC/Cargo.lock
    fi
else
    rustup target add $TARGET
    if [[ $GUI_TARGET != '' ]]; then
        rustup target add $GUI_TARGET
    fi
fi
