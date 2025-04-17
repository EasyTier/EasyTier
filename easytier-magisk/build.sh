#!/bin/sh

version=$(cat module.prop | grep 'version=' | awk -F '=' '{print $2}' | sed 's/ (.*//')

filename="Easytier_${version}_release.zip"

zip -r -o -X -ll "$filename" ./ -x '.git/*' -x '.github/*' -x 'folder/*' -x 'build.sh' -x 'magisk_update.json'