#!/bin/sh
WEBUI_SOURCE="../../easytier-web/config-generator/dist"

if [ -f "${WEBUI_SOURCE}/index.html" ]; then
    rm -rf ./webroot
    mkdir -p ./webroot
    cp -R "${WEBUI_SOURCE}/." ./webroot/
elif [ ! -f "./webroot/index.html" ]; then
    echo "Error: WebUI 构建产物不存在，请先运行 pnpm --dir ../../easytier-web/config-generator build."
    exit 1
fi

version=$(grep '^version =' ../../easytier/Cargo.toml | cut -d '"' -f 2)

if [ -z "$version" ]; then
    echo "Error: 版本号不存在."
    exit 1
fi
version="v${version}"

filename="easytier_magisk_${version}.zip"
echo "${version}"

if [ ! -f "./easytier-core" ] || [ ! -f "./easytier-cli" ] || [ ! -f "./easytier-web" ]; then
    wget -O "easytier_last.zip" "https://github.com/EasyTier/EasyTier/releases/download/${version}/easytier-linux-aarch64-${version}.zip"
    unzip -o easytier_last.zip -d ./
    mv ./easytier-linux-aarch64/* ./
    rm -rf ./easytier_last.zip
    rm -rf ./easytier-linux-aarch64
fi

zip -r -o -X "${filename}" ./ -x '.git/*' -x '.github/*' -x 'folder/*' -x 'build.sh' -x 'magisk_update.json'