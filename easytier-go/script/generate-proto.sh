#!/usr/bin/env bash

set -euo pipefail

repository_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
easytier_source="${1:-${EASYTIER_SOURCE:-"${repository_root}/.."}}"
proto_root="${easytier_source}/easytier-proto/proto"

if [[ ! -f "${proto_root}/api_instance.proto" ]]; then
    echo "EasyTier proto source not found at ${proto_root}" >&2
    exit 1
fi

if [[ "$(protoc --version)" != "libprotoc 35.1" ]]; then
    echo "protoc 35.1 is required" >&2
    exit 1
fi
if [[ "$(protoc-gen-go --version)" != "protoc-gen-go v1.36.11" ]]; then
    echo "protoc-gen-go v1.36.11 is required" >&2
    exit 1
fi

protoc \
    -I "${proto_root}" \
    --go_out="${repository_root}" \
    --go_opt=module=github.com/EasyTier/EasyTier/easytier-go \
    --go_opt=Mcommon.proto=github.com/EasyTier/EasyTier/easytier-go/proto/common \
    --go_opt=Merror.proto=github.com/EasyTier/EasyTier/easytier-go/proto/error \
    --go_opt=Macl.proto=github.com/EasyTier/EasyTier/easytier-go/proto/acl \
    --go_opt=Mpeer_rpc.proto=github.com/EasyTier/EasyTier/easytier-go/proto/peer_rpc \
    --go_opt=Mapi_instance.proto=github.com/EasyTier/EasyTier/easytier-go/proto/api/instance \
    --go_opt=Mapi_config.proto=github.com/EasyTier/EasyTier/easytier-go/proto/api/config \
    --go_opt=Mapi_manage.proto=github.com/EasyTier/EasyTier/easytier-go/proto/api/manage \
    --go_opt=Mweb.proto=github.com/EasyTier/EasyTier/easytier-go/proto/web \
    "${proto_root}/common.proto" \
    "${proto_root}/error.proto" \
    "${proto_root}/acl.proto" \
    "${proto_root}/peer_rpc.proto" \
    "${proto_root}/api_instance.proto" \
    "${proto_root}/api_config.proto" \
    "${proto_root}/api_manage.proto" \
    "${proto_root}/web.proto"
