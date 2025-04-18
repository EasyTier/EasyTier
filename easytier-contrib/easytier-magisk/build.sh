#!/bin/sh

version=$(cat module.prop | grep 'version=' | awk -F '=' '{print $2}' | sed 's/ (.*//')

filename="Easytier_${version}_release.zip"
version='v'$(grep '^version =' ../../easytier/Cargo.toml | cut -d '"' -f 2)
echo $version  # 输出: 2.2.4
wget -O "easytier_last.zip" https://github.com/EasyTier/EasyTier/releases/download/"$version"/easytier-linux-aarch64-"$version".zip
unzip -o -d ./ easytier_last.zip
mv ./easytier-linux-aarch64/* ./
rm -rf ./easytier_last.zip
rm -rf ./easytier-linux-aarch64
zip -r -o -X -ll "$filename" ./ -x '.git/*' -x '.github/*' -x 'folder/*' -x 'build.sh' -x 'magisk_update.json'