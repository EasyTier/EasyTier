# EasyTier Agent Instructions

EasyTier is a decentralized, peer-to-peer VPN mesh networking solution written in Rust, with a Tauri/Vue 3 desktop GUI. See [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md) for full project context.

## Workspace Layout

| Path | Purpose |
|------|---------|
| `easytier/` | Core library + `easytier-core` daemon + `easytier-cli` binaries |
| `easytier-web/` | Web dashboard + REST API server |
| `easytier-gui/` | Desktop GUI (Tauri 2 + Vue 3 + TypeScript) |
| `easytier-rpc-build/` | Protobuf code generation utilities |
| `easytier-contrib/` | Optional add-ons: Android JNI, FFI, Magisk module, uptime monitoring |
| `tauri-plugin-vpnservice/` | Tauri plugin for Android VPN service |

`easytier-contrib/easytier-ohrs` is **excluded** from the Cargo workspace (requires OpenHarmony SDK).

## Build & Test

See [CONTRIBUTING.md](CONTRIBUTING.md) for full setup instructions. Quick reference:

```bash
# Core (dev)
cargo build

# Core (all features)
cargo build --release --features full

# Lint (CI-strict)
cargo fmt --all -- --check
cargo clippy --all-targets --features full --all -- -D warnings

# Tests (requires Linux bridge setup)
sudo modprobe br_netfilter
sudo sysctl net.bridge.bridge-nf-call-iptables=0
cargo test --no-default-features --features=full --verbose
# Or with nextest (preferred in CI):
cargo nextest run --test-threads 1

# GUI (desktop)
cd easytier-gui && pnpm tauri build

# Frontend (all packages)
pnpm -r build
```

**Rust version**: 1.95 (enforced by [`rust-toolchain.toml`](rust-toolchain.toml)), **edition 2024**.

**Default features**: `wireguard, websocket, smoltcp, tun, socks5, kcp, quic, faketcp, magic-dns, zstd`

## Architecture

Core data flow:
```
Config (TOML) → ConfigLoader → GlobalContext
    ↓
InstanceManager → NetworkInstance (Launcher)
    ↓
PeerManager → PeerConn/PeerSession → Tunnel (TCP/UDP/QUIC/WS/WireGuard/FakeTcp)
    ↓
Noise handshake + AES-GCM encryption → packet send/receive
```

Key modules in `easytier/src/`:

| Module | Responsibility |
|--------|----------------|
| `common/` | Config, errors, logging, DNS, STUN, network utilities |
| `tunnel/` | Protocol implementations: TCP, UDP, QUIC, WebSocket, WireGuard, ring buffer |
| `peers/` | Peer connections, sessions, routing, encryption, RPC |
| `connector/` | NAT traversal: direct, DNS, HTTP, TCP/UDP hole punch |
| `instance/` | VPN instance lifecycle management |
| `peer_center/` | P2P peer coordination |
| `proto/` | Auto-generated protobuf types (do not edit by hand) |
| `rpc_service/` | gRPC/RPC API layer |
| `gateway/` | Network gateway and subnet proxy |
| `vpn_portal/` | VPN portal mode for subnet sharing |
| `arch/` | Platform-specific code (Windows/Linux/macOS) |

## Conventions

### Error Handling
- Primary error type: `common::error::Error` (thiserror enum); result alias: `Result<T>`
- Use `anyhow::Context` for error chaining; do not use `unwrap()` in non-test code

### Async & Concurrency
- Runtime: Tokio v1, `current_thread` flavor in binaries
- Shared state: `DashMap` for lock-free maps, `Arc<RwLock<T>>` / `Arc<Mutex<T>>` for guarded access
- Task lifecycle: wrap long-running tasks in `ScopedTask` for automatic cleanup
- Use `tokio::sync` channels (`mpsc`, `broadcast`) for inter-task communication

### Protobuf
- `.proto` files live in `easytier/src/proto/`; generated Rust code is committed to the repo
- Config flags are proto-generated (`FlagsInConfig` → `Flags` struct); add new flags there, not ad-hoc

### Feature Flags
- Heavy use of `#[cfg(feature = "...")]` for optional protocols and platform code
- New protocol integrations must be behind a feature flag; update default features in `easytier/Cargo.toml` consciously

### Naming
- `PeerId`: `u32`; `ArcPeerConn`, `ArcGlobalCtx`, `ArcRoute` for Arc-wrapped core types
- Tunnel protocols: `Protocol` enum variants (Tcp, Udp, Quic, WebSocket, WireGuard, FakeTcp)
- Config structs: use `derive_builder`; prefer TOML-friendly field names (snake_case)

### Testing
- Unit tests: inline `#[cfg(test)]` modules within source files
- Integration tests: `easytier/src/tests/`
- Integration tests modify kernel network state — run with `--test-threads 1`; see [CONTRIBUTING.md](CONTRIBUTING.md#testing-guidelines)

### Frontend (GUI)
- Vue 3 SFC with `<script setup>` and TypeScript; Tailwind CSS for styling
- State management via Pinia; Tauri commands use `invoke()` from `@tauri-apps/api`
- pnpm workspace — run `pnpm -r build` from root to build all frontend packages
