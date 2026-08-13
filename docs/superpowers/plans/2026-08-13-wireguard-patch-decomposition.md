# WireGuard Patch Decomposition Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace monolithic commit `f63198e3` with five independently compiling and tested commits that separate generic attached peers, a reusable portal runtime, native WireGuard integration, management APIs, and Web/GUI delivery.

**Architecture:** `peers::attached` constructs one complete, protocol-agnostic `PeerManagerCore` for each authenticated client and connects peer managers through an in-process transport. `gateway::vpn_portal` owns a portable portal runtime that consumes authenticated sessions without knowing WireGuard configuration or packet formats. The native WireGuard adapter owns UDP demultiplexing, BoringTun state, key derivation, and authenticated activation.

**Tech Stack:** Rust 2024, Tokio, BoringTun, prost/protobuf, Vue 3, TypeScript, Vitest, pnpm, Tauri, Docker-based Linux network-namespace integration tests.

## Global Constraints

- Preserve all user-visible behavior and configuration semantics from `f63198e3`.
- Preserve the original implementation at `backup/virtual-peer-wg-f63198e3`.
- Rebuild the current branch from `upstream/main`; do not force-push.
- Produce exactly five feature commits in the order defined below.
- Every commit must compile and pass its focused tests while it is `HEAD` and the working tree is clean.
- Attached-peer code must not depend on VPN portal configuration, WireGuard, BoringTun, HKDF, or UDP sockets.
- Portal runtime code must not depend on WireGuard listen addresses, private keys, receiver indices, cookies, or BoringTun types.
- WireGuard key derivation must use the dedicated portal key; the network secret must never be a fallback.
- A Secure-Mode attached peer must use a portal-owned credential and must not
  receive the network secret, secret digest, ACL group declarations,
  memberships, or group secrets.
- A non-Secure-Mode admin portal retains the legacy admin-attached identity for
  compatibility; a credential peer may never host a portal.
- Do not retain legacy `client_cidr` behavior, compatibility aliases, deprecated execution paths, or duplicate final portal interfaces.
- Portal payloads remain IPv4-only.
- Prefix every shell command with `rtk`; run root/network-namespace integration tests in the existing `rust` container.
- Commit subject and body lines must be at most 72 columns.

## Final File Structure

- `easytier-core/src/peers/attached.rs`
  - Owns one complete attached `PeerManagerCore`, in-process transport, packet ingress/egress, and cleanup; manager configuration owns ACL state.
- `easytier-core/src/peers/credential_manager.rs`
  - Keeps portal-owned ephemeral credential grants in memory, outside persistent
    credentials and management listings.
- `easytier-core/src/config/peers.rs`
  - Sanitizes synchronized ACL policy for credential peers while preserving
    chains and default actions.
- `easytier-core/src/gateway/vpn_portal.rs`
  - Thin public module facade; declares the translator and re-exports the reusable runtime API.
- `easytier-core/src/gateway/vpn_portal/runtime.rs`
  - Owns normalized client configuration, authenticated sessions, host trait, generations, status, packet pumps, and attached-peer lifecycle.
- `easytier-core/src/gateway/vpn_portal/ipv4_translator.rs`
  - Validates packets and transactionally rewrites IPv4 addresses and affected checksums.
- `easytier/src/vpn_portal/wireguard.rs`
  - Owns native host construction, dedicated-key validation, HKDF derivation, socket binding, listener wrapper, and client configuration rendering.
- `easytier/src/vpn_portal/wireguard/engine.rs`
  - Owns shared WireGuard packet dispatch, client slots, BoringTun sessions, timers, endpoint roaming, and bounded portal packet channels.

The external `config::toml::VpnPortalConfig` remains WireGuard-specific. The portable `PortalRuntimeConfig` contains only `Vec<VpnPortalClientConfig>`.

---

### Task 1: Protocol-Agnostic Attached Peers

**Files:**
- Create: `easytier-core/src/peers/attached.rs`
- Modify: `easytier-core/src/peers/mod.rs`
- Modify: `easytier-core/src/peers/conn/peer.rs`
- Modify: `easytier-core/src/peers/conn/peer_conn.rs`
- Modify: `easytier-core/src/peers/conn/peer_map.rs`
- Modify: `easytier-core/src/peers/peer_manager.rs`
- Modify: `easytier-core/src/peers/credential_manager.rs`
- Modify: `easytier-core/src/config/peers.rs`
- Modify: `easytier-core/src/peers/foreign_network/client.rs`
- Modify: `easytier-core/src/peers/tests.rs`
- Modify test-only subscription observation: `easytier-core/src/config/runtime.rs`
- Modify selected ACL-publication hunks only: `easytier-core/src/instance/mod.rs`

**Interfaces:**
- Consumes: `PeerManagerCore`, `CoreRuntimeConfigStore`, `HostPacket`, and
  `create_ring_tunnel_pair()` already present on `upstream/main`.
- Produces:

```rust
pub struct AttachedPeerConfig {
    pub name: String,
    pub virtual_ip: Ipv4Addr,
    pub groups: Vec<String>,
    pub identity_private_key: [u8; 32],
}

impl AttachedPeerRuntime {
    pub async fn connect(
        network_peer_manager: Arc<PeerManagerCore>,
        network_runtime_config: CoreRuntimeConfigStore,
        config: AttachedPeerConfig,
    ) -> anyhow::Result<Arc<Self>>;

    pub fn peer_id(&self) -> PeerId;
    pub async fn recv_packet(&self) -> Option<HostPacket>;
    pub async fn send_packet(&self, payload: &[u8]) -> anyhow::Result<()>;
    pub async fn close(&self);
}
```

Every call to `connect` constructs one complete `PeerManagerCore`. The existing
manager and the client manager are flat protocol peers connected over an
in-process ring; `AttachedPeerRuntime` owns client-session lifecycle only.
Each manager owns an independent `AclFilter`, route service, RPC endpoint,
secure sessions, counters, and connection state. There is no attached-peer
coordinator. Initial ACL loading and subsequent network-policy application are
ordinary `PeerManagerCore` configuration operations.

If the network manager uses Secure Mode, `connect` registers the caller's
identity public key as a non-reusable ephemeral credential before constructing
the child manager. The grant contains `groups`, `allow_relay=false`, and no
proxy CIDRs. A scoped registration revokes it on every failure, close, and drop
path. The child has no network or group secrets. Without Secure Mode, `connect`
retains the existing network-secret identity.
- Produces trusted provenance types used by attached admission and relay policy:

```rust
pub(crate) enum PeerConnectionOrigin { Network, Attached }

pub(crate) enum PeerPacketIngress {
    Local,
    Peer {
        peer_id: PeerId,
        conn_id: PeerConnId,
        origin: PeerConnectionOrigin,
    },
}
```

- [ ] **Step 1: Preserve the planning state, then reset to a clean base**

After this plan has been committed, preserve the documentation commits and make the current branch exactly `upstream/main`:

```bash
rtk git branch backup/virtual-peer-wg-planning HEAD
rtk git reset --hard upstream/main
```

Expected: `backup/virtual-peer-wg-f63198e3` points to the original implementation, `backup/virtual-peer-wg-planning` points to the approved spec and plan, and the current branch has a clean `upstream/main` tree.

- [ ] **Step 2: Restore the files that belong wholly to attached peers**

```bash
rtk git restore --source backup/virtual-peer-wg-f63198e3 -- \
  easytier-core/src/peers/attached.rs \
  easytier-core/src/peers/mod.rs \
  easytier-core/src/peers/conn/peer.rs \
  easytier-core/src/peers/conn/peer_conn.rs \
  easytier-core/src/peers/conn/peer_map.rs \
  easytier-core/src/peers/peer_manager.rs \
  easytier-core/src/peers/foreign_network/client.rs \
  easytier-core/src/peers/tests.rs
```

Do not restore portal, TOML, protobuf, Web, GUI, or WireGuard files in this task.

- [ ] **Step 3: Make Secure-Mode attached clients credential peers**

First add failing tests:

```rust
#[tokio::test]
async fn secure_attached_peer_uses_credential_identity_and_granted_groups() {
    // Connect to a Secure-Mode admin manager.
    // Assert !attached.peer_manager.can_manage_credentials().
    // Assert the network manager learns exactly the configured credential group.
}

#[tokio::test]
async fn secure_attached_peer_revokes_group_after_declaration_removal() {
    // Remove `ops` from the source declarations while the session stays up.
    // Assert the network route view removes `ops` from the attached peer.
}

#[test]
fn ephemeral_credentials_are_trusted_but_not_persisted_or_listed() {
    // Register a fixed public key, verify its least-privilege grant, revoke it,
    // and assert storage plus list_credentials() never expose it.
}
```

Run:

```bash
rtk cargo test -p easytier-core secure_attached_peer_uses_credential_identity_and_granted_groups -- --nocapture
rtk cargo test -p easytier-core ephemeral_credentials_are_trusted_but_not_persisted_or_listed -- --nocapture
```

Expected: both fail because attached snapshots still copy `network_secret` and
the credential manager has no ephemeral registration API.

Add one in-memory ephemeral map to `CredentialManager`. Registration accepts a
32-byte public key and explicit grant attributes; it rejects a key already used
by either a managed or ephemeral credential. Trust export and local trust lookup
include both maps, while persistence, expiry cleanup, and management listing
continue to use only managed credentials.

`PeerManagerCore` wraps registration, group replacement, and revocation so each
effective mutation emits the existing `CredentialChanged` event.
`AttachedPeerRuntime` owns a scoped registration and a source-policy watcher.
The watcher computes
`configured_groups ∩ source.peer.acl_group_declarations` initially and after
every peer-policy change, then replaces the transient grant groups. Closing or
dropping the registration stops that watcher and revokes the grant; every
construction failure therefore rolls back without stale trust.

In `attached.rs`, preserve the caller-supplied stable key. If the source manager
has Secure Mode enabled, clear `network_secret`, `network_secret_digest`,
`peer_group_memberships`, and `acl_group_declarations`, then assign:

```rust
let private = StaticSecret::from(config.identity_private_key);
let public = PublicKey::from(&private);
snapshot.runtime.secure_mode = Some(SecureModeConfig {
    enabled: true,
    local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
    local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
});
```

Register `public` with the currently declared subset of
`AttachedPeerConfig::groups`, `allow_relay=false`, `allowed_proxy_cidrs=[]`, and
`reusable=false` before opening the ring. The policy watcher keeps that grant
subset current without copying declaration secrets into the child. If the
source manager does not use Secure Mode, retain its network secret and legacy
group-proof behavior.

- [ ] **Step 4: Keep attached trust in admission metadata**

Retain the restored `PeerConnectionOrigin` on `PeerConn`, construct `PeerPacketIngress` inside `PeerConn::start_recv_loop()`, and carry it through `PacketRecvChan`. Public/local `PacketRecvChan::send()` must always create `PeerPacketIngress::Local`.

`PeerConnectionAdmission` must reject `Attached` connections whose authenticated network name differs from the local network. `should_drop_relay_data()` may bypass relay-disable only for attached ingress or a live direct attached destination.

- [ ] **Step 5: Give every peer manager one safe policy update path**

Add a generic `PeerManagerCore` runtime-configuration operation that validates
and builds changed ACL rules before publication, preserves runtime-owned peer
identity and live state, atomically replaces the manager's configuration,
reloads its own ACL filter, and refreshes its own route groups.

Add `AclRuleConfig::for_credential_peer()`: clone the ACL, preserve every chain
and default action, and remove `AclV1.group` entirely. Use it both before the
credential child manager's initial ACL load and on every synchronized service
update. Credential children keep declarations and memberships empty; their
route groups come from the credential grant. Legacy admin-attached peers keep
the existing declaration/membership synchronization.

`CoreInstance::update_runtime_config()` delegates its peer-manager portion to
the generic operation before updating instance-only proxy and Host state. The
attached layer must not call `AclRuleConfig::build`, `reload_acl`, or
`Route::refresh_acl_groups` directly.

- [ ] **Step 6: Format and create the first commit**

```bash
rtk cargo fmt --all
rtk git add \
  easytier-core/src/peers/attached.rs \
  easytier-core/src/peers/mod.rs \
  easytier-core/src/peers/conn/peer.rs \
  easytier-core/src/peers/conn/peer_conn.rs \
  easytier-core/src/peers/conn/peer_map.rs \
  easytier-core/src/peers/peer_manager.rs \
  easytier-core/src/peers/credential_manager.rs \
  easytier-core/src/config/peers.rs \
  easytier-core/src/peers/foreign_network/client.rs \
  easytier-core/src/peers/tests.rs \
  easytier-core/src/instance/mod.rs
rtk git commit -m "$COMMIT_MSG"
```

Use this message:

```text
feat(peer): support protocol-agnostic attached peers

Add locally attached peers backed by independent, peer-level portable
managers and authenticated in-process ring connections. Carry trusted
connection provenance through packet admission so attached relay
privileges cannot be forged through packet headers.

Let every peer manager own ACL loading, sanitized policy updates, route
refresh, and runtime cleanup. In Secure Mode, grant attached identities
ephemeral credentials instead of sharing administrator and group secrets.
```

- [ ] **Step 7: Verify the first commit as `HEAD`**

```bash
rtk cargo check -p easytier-core
rtk cargo test -p easytier-core attached -- --nocapture
rtk cargo test -p easytier-core local_packet_channel_injection_has_no_attached_privilege
rtk cargo test -p easytier-core forged_attached_source_header_does_not_bypass_relay_disable
```

Expected: all commands pass with a clean working tree. If a fix is required, commit it with `rtk git commit --amend --no-edit` and rerun the failed command.

---

### Task 2: Reusable Attached-Peer Portal Runtime

**Files:**
- Create: `easytier-core/src/gateway/vpn_portal/runtime.rs`
- Create: `easytier-core/src/gateway/vpn_portal/ipv4_translator.rs`
- Modify only to declare the new submodules: `easytier-core/src/gateway/vpn_portal.rs`

**Interfaces:**
- Consumes: `AttachedPeerRuntime::connect` and
  `AttachedPeerRuntime::{recv_packet, send_packet, close}` from Task 1.
- Produces:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortalRuntimeConfig {
    pub clients: Vec<VpnPortalClientConfig>,
}

pub struct PortalSession {
    pub client_name: String,
    pub endpoint: String,
    pub identity_private_key: [u8; 32],
    pub from_client: mpsc::Receiver<Vec<u8>>,
    pub to_client: mpsc::Sender<Vec<u8>>,
}

pub type PortalListener = Box<dyn SocketListener<Accepted = PortalSession>>;

#[async_trait]
pub trait PortalHost: Send + Sync + 'static {
    async fn start_listeners(&self) -> anyhow::Result<Vec<PortalListener>>;
    fn name(&self) -> String;
    fn render_client_config(&self, plan: &PortalClientConfigPlan) -> String;
}

pub struct PortalModule;

impl PortalModule {
    pub fn new(
        peer_manager: Arc<PeerManagerCore>,
        runtime_config: CoreRuntimeConfigStore,
        config: Option<PortalRuntimeConfig>,
        host: Option<Arc<dyn PortalHost>>,
        events: Arc<dyn CoreEventSink>,
    ) -> anyhow::Result<Arc<Self>>;

    pub async fn start(&self) -> anyhow::Result<()>;
    pub async fn stop(&self);
    pub async fn info_snapshot(&self) -> PortalInfoSnapshot;
}
```

For this commit, `PortalInfoSnapshot` retains the aggregate management shape so Task 3 can cut over production without changing management APIs:

```rust
pub struct PortalInfoSnapshot {
    pub vpn_type: String,
    pub client_config: String,
    pub connected_clients: Vec<String>,
}
```

Internally, the runtime still tracks each client's state, generation, peer ID, endpoint, tunnel IP, and error for Task 4.

- [ ] **Step 1: Restore the checksum-safe translator**

```bash
rtk git restore --source backup/virtual-peer-wg-f63198e3 -- \
  easytier-core/src/gateway/vpn_portal/ipv4_translator.rs
```

Keep `rewrite_ipv4_source()` and `rewrite_ipv4_destination()` protocol-neutral. Their validation must complete before mutation, including ICMP quoted-packet analysis.

- [ ] **Step 2: Add the reusable runtime module beside the existing production path**

Add these declarations to the existing `vpn_portal.rs` without replacing its old implementation yet:

```rust
pub mod runtime;
pub(crate) mod ipv4_translator;
```

Create `runtime.rs` by extracting the portable orchestration from the backup implementation and applying the Task 1 method and field names. Use `Portal*` names so the new interface does not collide with the temporarily retained `VpnPortal*` production path.

`PortalModule::run_session()` must:

```rust
let attached = AttachedPeerRuntime::connect(
    peer_manager.clone(),
    runtime_config.clone(),
    AttachedPeerConfig {
        name: client.name.clone(),
        virtual_ip: client.virtual_ip,
        groups: client.groups.clone(),
        identity_private_key: session.identity_private_key,
    },
)
.await?;
```

Use `attached.recv_packet()` for mesh-to-client traffic and `attached.send_packet(&payload)` for client-to-mesh traffic.

- [ ] **Step 3: Remove all WireGuard knowledge from generic validation**

`validate_config()` accepts `PortalRuntimeConfig` and validates only:

- one to `MAX_VPN_PORTAL_CLIENTS` clients;
- an admin portal node with a non-empty network secret;
- static IPv4 configuration on the network peer manager;
- unique DNS-label-style names;
- unique, usable virtual IPv4 addresses inside the network prefix; and
- declared ACL groups.

Reject a credential portal node before any listener starts. The error must
contain `VPN portal requires an admin node`. Secure Mode controls whether its
attached clients use credentials; it does not grant a credential node authority
to host a portal.

Do not decode or inspect `wireguard_private_key` in this module.

- [ ] **Step 4: Use listener identity and one terminating session loop**

Capture `listener.local_url()` before spawning each listener task. Pass that URL
into `run_session()` and use it for connected/disconnected events. Do not read a
WireGuard listen address from runtime configuration.

Keep one `Mutex<()>` per configured client. After the attached runtime is
online, one `tokio::select!` must observe all four liveness sources:

```rust
_ = cancel.cancelled() => break,
result = &mut mesh_to_client => { mesh_to_client_finished = true; break; }
changed = endpoint.changed() => { /* publish endpoint or break on closure */ }
payload = client_stream.recv() => { /* translate and inject, or break */ }
```

All exits use one cleanup tail. Abort and join `mesh_to_client` only if it did
not already finish, await `attached.close()`, publish final status and the
disconnect event, then release the generation lock. A new generation may enter
only after attached-peer and transient-credential cleanup. `PortalModule::stop`
must complete even when the protocol host retains accepted channel senders.

- [ ] **Step 5: Add focused runtime tests**

Add tests in `runtime.rs` that construct a network runtime snapshot and assert:

```rust
#[test]
fn portal_runtime_rejects_duplicate_names_and_virtual_ips() { /* exact duplicate fixtures */ }

#[test]
fn portal_runtime_rejects_unknown_acl_groups() { /* configured group absent */ }

#[test]
fn portal_session_debug_redacts_identity_private_key() { /* debug output omits bytes */ }

#[test]
fn portal_runtime_rejects_credential_node() { /* no network secret */ }

#[tokio::test]
async fn portal_session_cancellation_closes_attached_peer_with_input_open() {
    /* keep the inbound sender alive, cancel, and require bounded completion */
}

#[tokio::test]
async fn portal_session_stops_when_outbound_packet_task_ends() {
    /* close the client sink, route one packet, and require common cleanup */
}
```

Use concrete clients `alice=10.82.0.2` and `bob=10.82.0.3`, network peer
`10.82.0.1/24`, and group `ops`. Assert the exact error fragments
`duplicate VPN portal client name`, `duplicate VPN portal virtual IP`,
`unknown ACL group`, and `VPN portal requires an admin node`. For both lifecycle
tests, keep unrelated session channels alive and wrap session completion in
`tokio::time::timeout`; assert the attached route and client `peer_id` disappear
before the timeout.

Retain all translator tests restored from the backup implementation, including TCP, UDP-zero-checksum, ICMP echo, ICMP errors with quoted packets, fragments, malformed lengths, and transactional no-mutation cases.

- [ ] **Step 6: Format and create the second commit**

```bash
rtk cargo fmt --all
rtk git add \
  easytier-core/src/gateway/vpn_portal.rs \
  easytier-core/src/gateway/vpn_portal/runtime.rs \
  easytier-core/src/gateway/vpn_portal/ipv4_translator.rs
rtk git commit -m "$COMMIT_MSG"
```

Use this message:

```text
feat(vpn): add reusable attached-peer portal runtime

Add a protocol-neutral portal runtime that converts authenticated client
sessions into attached EasyTier peers. Own per-client generations,
status, packet forwarding, address translation, and peer cleanup without
knowing the transport protocol.

Add transactional IPv4 source and destination rewriting with correct
IPv4, TCP, UDP, ICMP, and quoted-packet checksum updates. Keep the old
production portal path temporarily active until the WireGuard adapter is
migrated in the next change.
```

- [ ] **Step 7: Verify the second commit as `HEAD`**

```bash
rtk cargo check -p easytier-core --features vpn-portal
rtk cargo test -p easytier-core gateway::vpn_portal::runtime -- --nocapture
rtk cargo test -p easytier-core gateway::vpn_portal::ipv4_translator -- --nocapture
```

Expected: the reusable runtime and the still-active old production path both compile; all new unit tests pass. Amend and rerun if required.

---

### Task 3: Named WireGuard Clients Through the Generic Runtime

**Files:**
- Create: `easytier/src/vpn_portal/wireguard/engine.rs`
- Replace with thin facade: `easytier-core/src/gateway/vpn_portal.rs`
- Modify: `easytier-core/src/gateway/vpn_portal/runtime.rs`
- Modify: `Cargo.lock`
- Modify: `easytier/Cargo.toml`
- Modify: `easytier-core/src/config/api.rs`
- Modify: `easytier-core/src/config/api_input.rs`
- Modify: `easytier-core/src/config/peers.rs`
- Modify: `easytier-core/src/config/toml.rs`
- Modify: `easytier-core/src/gateway/proxy/cidr_monitor.rs`
- Modify: `easytier-core/src/instance/build_capabilities.rs`
- Modify: `easytier-core/src/instance/config.rs`
- Modify: `easytier-core/src/instance/mod.rs`
- Modify: `easytier-core/src/instance/tests.rs`
- Modify: `easytier-core/src/peers/context.rs`
- Modify: `easytier-core/src/peers/route/peer_ospf_route.rs`
- Modify: `easytier-proto/build/main.rs`
- Modify: `easytier-proto/proto/api_manage.proto`
- Modify: `easytier-proto/src/api.rs`
- Modify: `easytier/locales/app.yml`
- Modify: `easytier/src/common/global_ctx.rs`
- Modify: `easytier/src/core.rs`
- Modify: `easytier/src/instance/composition.rs`
- Modify: `easytier/src/tests/three_node.rs`
- Modify: `easytier/src/vpn_portal/wireguard.rs`

**Interfaces:**
- Consumes: `PortalRuntimeConfig`, `PortalSession`, `PortalListener`, `PortalHost`, and `PortalModule` from Task 2.
- Produces: `WireGuardPortalHost: PortalHost` and the final production cutover.
- The facade becomes:

```rust
mod ipv4_translator;
mod runtime;

pub use runtime::{
    PortalClientConfigPlan, PortalHost, PortalInfoSnapshot, PortalListener,
    PortalModule, PortalRuntimeConfig, PortalSession,
};
```

- [ ] **Step 1: Restore the backend/configuration changes from the original implementation**

Restore the files listed above from `backup/virtual-peer-wg-f63198e3`, except `gateway/vpn_portal.rs`, `gateway/vpn_portal/runtime.rs`, `instance/mod.rs`, and `wireguard.rs`, which require the generic boundary described below.

Use one explicit `rtk git restore --source ... -- <paths>` command. Do not restore management status, Web, GUI, README, or frontend files in this task.

- [ ] **Step 2: Finish the Core cutover and delete the old portal path**

Replace `gateway/vpn_portal.rs` with the thin facade above. Update all Core imports from old `VpnPortal*` runtime types to `Portal*` types.

Change `CoreInstanceConfig` to:

```rust
#[serde(default, skip_serializing_if = "Option::is_none")]
pub vpn_portal: Option<PortalRuntimeConfig>,
```

In `CoreInstanceConfig::from_toml_with_host()`, map the external configuration to the normalized view:

```rust
vpn_portal: (!host.ignore_unsupported_config || host.vpn_portal_enabled)
    .then(|| config.get_vpn_portal_config())
    .flatten()
    .map(|config| PortalRuntimeConfig {
        clients: config.clients,
    }),
```

Keep the full external configuration available to native composition through `global_ctx.config.get_vpn_portal_config()`.

Update `CoreHostAdapters::vpn_portal` to `Option<Arc<dyn PortalHost>>`, and construct `PortalModule` with the normalized config. Preserve the ACL ordering from Task 1 when applying the other `instance/mod.rs` changes.

- [ ] **Step 3: Remove legacy portal CIDR routing**

Delete `vpn_portal_cidr` from `PeerRuntimeSnapshot`, `PeerRuntimeSnapshotInput`, `PeerContext`, `GlobalCtx`, proxy CIDR monitoring, and OSPF self-route construction. Attached peers now advertise their individual virtual routes; no synthetic portal subnet route remains.

Keep legacy protobuf fields only as deprecated wire compatibility fields. `NetworkConfigExt::gen_config()` must reject `enable_vpn_portal == Some(true)` with the exact migration error and ignore disabled legacy defaults.

- [ ] **Step 4: Keep protocol configuration in the native host**

`VpnPortalConfig` remains:

```rust
pub struct VpnPortalConfig {
    pub wireguard_listen: SocketAddr,
    pub wireguard_private_key: Option<String>,
    pub clients: Vec<VpnPortalClientConfig>,
}
```

`WireGuardPortalHost::new(global_ctx, config)` owns this complete value. `PortalModule` receives only `PortalRuntimeConfig { clients }`.

Move dedicated-key validation out of Core. `portal_master_and_server_key()` must reject missing, empty, invalid-base64, or non-32-byte keys and return `(master_key, server_private_key)` without consulting the network secret.

- [ ] **Step 5: Split the native WireGuard engine from host wiring**

Move `DerivedClient`, `ClientSlot`, `ClientSession`, `Endpoint`, `PortalEngine`, packet classifiers, and session retirement into `wireguard/engine.rs`. Keep socket construction, key derivation, listener implementation, and configuration rendering in `wireguard.rs`.

The engine activation boundary must emit:

```rust
PortalSession {
    client_name: slot.client.config.name.clone(),
    endpoint: remote.to_string(),
    identity_private_key: slot.client.identity_private_key,
    from_client: channels.from_client,
    to_client: channels.to_client,
}
```

The engine must pre-verify all datagrams through the shared limiter, use receiver-index high bits for slot dispatch, drain BoringTun's queued packets after handshake writes, activate only after authenticated transport data, update endpoints on authenticated traffic, and drop only the current packet when the bounded portal packet channel is full.

- [ ] **Step 6: Preserve domain-separated deterministic identities**

Keep HKDF-SHA256 with salt `easytier/wireguard-portal/v1`. Encode each context as a 32-bit big-endian length followed by bytes. Derive WireGuard and attached identities with different domains:

```rust
let wireguard_private = derive_named_key(
    &master,
    b"wireguard-client",
    &client.name,
)?;
let identity_private_key = derive_named_key(
    &master,
    b"attached-noise",
    &client.name,
)?;
```

Add `hkdf` and `sha2` only to the `wireguard` feature in `easytier/Cargo.toml`.

- [ ] **Step 7: Retain aggregate management output for this commit**

Do not restore the final management files yet. `PortalModule::info_snapshot()` must render the first configured client's config into `client_config` and list online endpoints in `connected_clients`, preserving the old protobuf consumer until Task 4.

Adjust the Task 3 three-node test to assert the aggregate `client_config` contains `198.51.100.0/24`. Task 4 changes this assertion to the final per-client shape.

- [ ] **Step 8: Redact configuration secrets**

Restore `TomlConfig::dump_redacted()` and use it for startup logging. Redact non-empty network secrets, secure-mode private keys, WireGuard portal private keys, and ACL group secrets. Preserve `dump()` round-trip behavior.

- [ ] **Step 9: Format and create the third commit**

```bash
rtk cargo fmt --all
rtk git add Cargo.lock easytier/Cargo.toml easytier-core easytier-proto \
  easytier/locales/app.yml easytier/src
rtk git commit -m "$COMMIT_MSG"
```

Before committing, ensure the index contains no management status, Web, GUI, README, design, or plan files.

Use this message:

```text
feat(wireguard): attach named clients through peer portal

Replace the proxy-subnet WireGuard portal with authenticated named
clients backed by attached peers. Demultiplex configured public keys on
shared UDP sockets and keep rekeys, roaming, timers, and bounded packet
queues inside the native WireGuard adapter.

Derive WireGuard and attached-peer identities from a dedicated portal
key with domain-separated HKDF. Normalize only client identity into the
portable runtime, remove synthetic portal CIDR routing, reject legacy
configuration, and redact private configuration from startup logs.
```

- [ ] **Step 10: Verify Rust configuration and unit contracts**

```bash
rtk cargo check -p easytier-core
rtk cargo check -p easytier --all-targets
rtk cargo test -p easytier-core vpn_portal_api_config_round_trips_through_toml_model
rtk cargo test -p easytier-core legacy_enabled_vpn_portal_config_reports_migration_error
rtk cargo test -p easytier-core vpn_portal_round_trip_and_redacted_dump_preserve_dump_semantics
rtk cargo test -p easytier named_keys_are_domain_separated_and_stable
rtk cargo test -p easytier portal_key_has_no_network_secret_fallback
rtk cargo test -p easytier vpn_portal_cli_uses_named_clients_and_preserves_unset_fields
```

Expected: all commands pass at the third commit.

- [ ] **Step 11: Verify the WireGuard data path in Docker**

```bash
rtk docker exec -w /data/project/EasyTier-virtual-peer-wg rust \
  cargo test -p easytier wireguard_vpn_portal -- --nocapture
```

Expected: both IPv4-listener and dual-stack parameter cases pass, the WireGuard client reaches all three EasyTier peers, and cleanup completes. Amend the third commit and rerun all failed checks if needed.

---

### Task 4: Per-Client Management and CLI Status

**Files:**
- Modify: `easytier-core/src/gateway/vpn_portal/runtime.rs`
- Modify: `easytier-core/src/instance/vpn_portal_extension.rs`
- Modify: `easytier-core/src/management/full/instance_info.rs`
- Modify: `easytier-core/src/management/instance_rpc/full.rs`
- Modify: `easytier-proto/proto/api_instance.proto`
- Modify: `easytier/src/easytier-cli.rs`
- Modify: `easytier/src/tests/three_node.rs`
- Modify: `easytier-gui/src-tauri/src/lib.rs`

**Interfaces:**
- Consumes: the internal per-client status already maintained by `PortalModule`.
- Produces:

```rust
pub enum PortalClientState { Offline, Connecting, Online, Error }

pub struct PortalClientInfoSnapshot {
    pub name: String,
    pub virtual_ip: Ipv4Addr,
    pub groups: Vec<String>,
    pub state: PortalClientState,
    pub peer_id: Option<u32>,
    pub endpoint: Option<String>,
    pub tunnel_ip: Option<Ipv4Addr>,
    pub client_config: String,
    pub error: Option<String>,
}

pub struct PortalInfoSnapshot {
    pub vpn_type: String,
    pub clients: Vec<PortalClientInfoSnapshot>,
    pub listener: Option<String>,
}
```

- [ ] **Step 1: Replace aggregate Core snapshots with per-client snapshots**

Update `PortalModule::info_snapshot()` to return one entry per configured client in configuration order. Render each client config with its name, `DEFAULT_WIREGUARD_CLIENT_ADDRESS`, network-wide proxy routes, and the active listener URL. Return empty client configs before listener startup.

Delete the aggregate `client_config` and `connected_clients` fields from the portable snapshot. Keep only the deprecated protobuf fields for wire compatibility.

- [ ] **Step 2: Restore and adapt the management protobuf changes**

Restore `api_instance.proto`, `management/full/instance_info.rs`, `management/instance_rpc/full.rs`, `easytier-cli.rs`, and the Tauri command changes from `backup/virtual-peer-wg-f63198e3`.

Map every `PortalClientState` to the matching protobuf enum. Set deprecated `VpnPortalInfo.client_config` to an empty string and `connected_clients` to an empty list. Set `NetworkInstanceRunningInfo.my_node_info.vpn_portal_cfg` to `None`; client private configurations are available only from the explicit portal RPC.

- [ ] **Step 3: Extract and test the protobuf mapping**

In `management/instance_rpc/full.rs`, extract a private pure function:

```rust
fn vpn_portal_info_to_proto(info: PortalInfoSnapshot) -> VpnPortalInfo;
```

Add a unit test with one online and one error client. Assert enum mapping, optional peer/endpoint/tunnel fields, generated config preservation, error preservation, listener preservation, and empty deprecated aggregate fields.

- [ ] **Step 4: Update CLI output and the integration assertion**

The human CLI output must print listener once and, for each client, print name, virtual IP, state, peer ID, endpoint, tunnel IP, comma-separated groups, a delimited client config, and an optional error. JSON output remains protobuf JSON.

Update the three-node test to assert `portal_info.clients.len() == 1` and that `portal_info.clients[0].client_config` contains `198.51.100.0/24`.

- [ ] **Step 5: Format and create the fourth commit**

```bash
rtk cargo fmt --all
rtk git add \
  easytier-core/src/gateway/vpn_portal/runtime.rs \
  easytier-core/src/instance/vpn_portal_extension.rs \
  easytier-core/src/management/full/instance_info.rs \
  easytier-core/src/management/instance_rpc/full.rs \
  easytier-proto/proto/api_instance.proto \
  easytier/src/easytier-cli.rs \
  easytier/src/tests/three_node.rs \
  easytier-gui/src-tauri/src/lib.rs
rtk git commit -m "$COMMIT_MSG"
```

Use this message:

```text
feat(management): expose named VPN portal clients

Report each configured portal client with its connection state, attached
peer ID, remote endpoint, learned tunnel address, generated client
configuration, and last activation error. Render the same information in
the CLI and expose it through the native GUI command bridge.

Stop including client private configuration in broad instance-running
snapshots. Retain deprecated aggregate protobuf fields only for wire
compatibility and leave them empty.
```

- [ ] **Step 6: Verify management consumers as `HEAD`**

```bash
rtk cargo test -p easytier-core vpn_portal_info_to_proto
rtk cargo check -p easytier-core --features management
rtk cargo check -p easytier --all-targets
rtk cargo check -p easytier-gui
```

Expected: protobuf generation, Core management, native CLI, and Tauri bridge all compile; the mapping test passes.

---

### Task 5: Web/GUI Configuration, Status, and Documentation

**Files:**
- Modify: `README.md`
- Modify: `README_CN.md`
- Modify: `easytier-gui/src/auto-imports.d.ts`
- Modify: `easytier-gui/src/composables/backend.ts`
- Modify: `easytier-gui/src/modules/api.ts`
- Modify: `easytier-web/frontend-lib/scripts/test-network-config.mjs`
- Modify: `easytier-web/frontend-lib/src/components/Config.vue`
- Modify: `easytier-web/frontend-lib/src/components/RemoteManagement.vue`
- Modify: `easytier-web/frontend-lib/src/components/Status.vue`
- Modify: `easytier-web/frontend-lib/src/locales/cn.yaml`
- Modify: `easytier-web/frontend-lib/src/locales/en.yaml`
- Modify: `easytier-web/frontend-lib/src/modules/api.ts`
- Modify: `easytier-web/frontend-lib/src/modules/utils.ts`
- Modify: `easytier-web/frontend-lib/src/types/network.ts`
- Modify: `easytier-web/frontend-lib/src/types/networkCompat.ts`
- Modify: `easytier-web/frontend-lib/tests/config-ui.spec.ts`
- Modify: `easytier-web/frontend-lib/tests/remote-management-config.spec.ts`
- Create: `easytier-web/frontend-lib/tests/status-vpn-portal.spec.ts`
- Create: `easytier-web/frontend-lib/tests/uuid.spec.ts`
- Modify: `easytier-web/frontend/src/modules/api.ts`
- Restore approved docs: `docs/superpowers/specs/2026-08-13-wireguard-patch-decomposition-design.md`
- Restore this plan: `docs/superpowers/plans/2026-08-13-wireguard-patch-decomposition.md`

**Interfaces:**
- Consumes: named portal configuration from `api_manage.proto` and per-client status from `api_instance.proto`.
- Produces: existing Web/GUI behavior from `f63198e3`, with no backend contract changes.

- [ ] **Step 1: Restore the frontend, GUI, README, and planning files**

Restore product files from `backup/virtual-peer-wg-f63198e3` and the approved spec/plan from `backup/virtual-peer-wg-planning`:

```bash
rtk git restore --source backup/virtual-peer-wg-f63198e3 -- \
  README.md README_CN.md easytier-gui/src easytier-web/frontend-lib \
  easytier-web/frontend/src/modules/api.ts
rtk git restore --source backup/virtual-peer-wg-planning -- \
  docs/superpowers/specs/2026-08-13-wireguard-patch-decomposition-design.md \
  docs/superpowers/plans/2026-08-13-wireguard-patch-decomposition.md
```

Do not restore `easytier-gui/src-tauri/src/lib.rs`; Task 4 already contains the native command bridge.

- [ ] **Step 2: Confirm final frontend contracts**

`VpnPortalConfig` in TypeScript must contain `wireguardListen`, optional `wireguardPrivateKey`, and `clients`. Each client contains `name`, `virtualIp`, and `groups`.

The status view must render listener, state, peer ID, endpoint, tunnel IP, groups, generated client config, and error for every client. Client list editing must use stable UUID-backed view keys without serializing those UUIDs into backend configuration.

Compatibility normalization must reject or ignore legacy fields exactly as the Rust configuration layer does; it must not synthesize a legacy portal subnet.

- [ ] **Step 3: Run focused frontend tests before committing**

```bash
rtk pnpm --dir easytier-web/frontend-lib exec vitest run \
  --config vitest.config.ts \
  tests/config-ui.spec.ts \
  tests/remote-management-config.spec.ts \
  tests/status-vpn-portal.spec.ts \
  tests/uuid.spec.ts
rtk pnpm --dir easytier-web/frontend-lib test:network-config
rtk pnpm --dir easytier-web/frontend-lib build
rtk pnpm --dir easytier-gui build
```

Expected: named-client editing, remote-management serialization, status rendering, UUID stability, generated network configuration, type checking, and both production builds pass.

- [ ] **Step 4: Smoke the affected UI path in Chromium**

Start the frontend through the process hub with:

```text
application: pnpm
args: ["--dir", "easytier-web/frontend", "dev", "--host", "127.0.0.1"]
```

Wait for the Vite ready banner and port. Open the page with the browser tool, navigate to configuration, add two named portal clients and groups, and confirm the controls remain stable after reordering. Navigate to status with a mocked per-client response and confirm listener, online/error states, generated configuration, and error text render without console errors.

- [ ] **Step 5: Create the fifth commit**

```bash
rtk git add README.md README_CN.md docs/superpowers \
  easytier-gui/src easytier-web/frontend-lib \
  easytier-web/frontend/src/modules/api.ts
rtk git commit -m "$COMMIT_MSG"
```

Use this message:

```text
feat(web): manage named WireGuard portal clients

Add Web and GUI controls for the dedicated portal key and named clients
with virtual addresses and ACL groups. Display per-client runtime state,
attached peer identity, endpoints, generated WireGuard configuration,
and activation errors.

Update frontend compatibility handling, focused UI tests, and English
and Chinese configuration and migration documentation. Include the
approved decomposition design and implementation plan.
```

- [ ] **Step 6: Verify the final commit as `HEAD`**

Rerun the four frontend commands from Step 3 and:

```bash
rtk cargo check -p easytier-gui
rtk docker exec -w /data/project/EasyTier-virtual-peer-wg rust \
  cargo test -p easytier wireguard_vpn_portal -- --nocapture
```

Expected: all frontend, GUI, Rust, IPv4 WireGuard, and dual-stack listener checks pass with a clean working tree.

- [ ] **Step 7: Verify final history and perform the required review**

Confirm the current branch has exactly five commits above `upstream/main`, in the planned order, and that `backup/virtual-peer-wg-f63198e3` still resolves to `f63198e3`.

Run one final read-only code-review subagent against `upstream/main..HEAD`. It must report only high-confidence blocker/major/minor findings involving real behavior regressions, security, concurrency, data consistency, or incorrect architecture. Fix blocker and major findings; record but do not automatically expand scope for minor findings.

After any review fix, amend the owning commit rather than adding a sixth feature commit, rerun that commit's focused verification, then rerun the final WireGuard and frontend smoke checks.
