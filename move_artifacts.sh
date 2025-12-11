#!/usr/bin/env bash
set -euo pipefail

BASE="/home/pengcheng/rustPC/demo18_easytier"
SRC="$BASE/EasyTier"
DEST="$BASE/laji_after_compile"

mkdir -p "$DEST"

move_if_exists() {
  local path="$1"
  if [ -e "$path" ]; then
    local name
    name=$(basename "$path")
    echo "Moving $path -> $DEST/$name"
    mv "$path" "$DEST/"
  else
    echo "Skip $path (not found)"
  fi
}

# Rust build artifacts
move_if_exists "$SRC/target"
move_if_exists "$SRC/easytier-web/target"
move_if_exists "$SRC/easytier-gui/src-tauri/target"

# Frontend build outputs and dependencies
move_if_exists "$SRC/node_modules"
move_if_exists "$SRC/easytier-web/frontend/node_modules"
move_if_exists "$SRC/easytier-web/frontend/dist"
move_if_exists "$SRC/easytier-gui/node_modules"
move_if_exists "$SRC/easytier-gui/dist"

# Tauri Android generated project
move_if_exists "$SRC/easytier-gui/src-tauri/gen/android"

# Cargo registries (optional, uncomment if you want to move caches too)
# move_if_exists "$HOME/.cargo/registry"
# move_if_exists "$HOME/.cargo/git"

echo "Done. Contents now under $DEST"
