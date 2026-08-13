# WireGuard Patch Decomposition Design

## Context

Commit `f63198e3` adds attached peers, a multi-client WireGuard portal,
configuration and management APIs, CLI support, Web/GUI support, and
documentation in one change. It touches 57 files with 4,712 insertions and 882
deletions. The implementation is functionally complete, but the patch combines
five independently reviewable concerns and makes the trust boundary between an
attached peer and WireGuard difficult to audit.

The branch will be rewritten from `upstream/main`. The original commit is
preserved at local branch `backup/virtual-peer-wg-f63198e3`.

## Goals

- Replace `f63198e3` with five independently compiling and tested commits.
- Make attached peers independent of WireGuard and reusable by any VPN portal.
- Keep a protocol-neutral portal runtime as a final architecture boundary.
- In Secure Mode, authorize attached peers through portal-owned credentials
  rather than sharing administrator secrets.
- Keep all current `f63198e3` user-visible behavior and configuration semantics.
- Keep WireGuard authentication, key derivation, UDP demultiplexing, rekeying,
  roaming, and backpressure inside the native WireGuard adapter.
- Make every commit useful to reviewers and safe to bisect.

## Non-goals

- Adding another VPN protocol.
- Adding IPv6 client payload support to the portal.
- Restoring the legacy `client_cidr` configuration.
- Adding compatibility aliases or fallback key derivation.
- Changing the UI or management behavior beyond what `f63198e3` already
  implements.

## Architecture

### Protocol-agnostic attached peers

Each authenticated portal client is one independent `PeerManagerCore`. The
existing EasyTier manager and every portal-client manager are protocol peers
connected through ordinary authenticated connections over an in-process ring
tunnel. There is no parent/child manager role and no multi-identity manager.

`easytier-core/src/peers/attached.rs` contains one protocol-neutral
`AttachedPeerRuntime` per client generation. It:

- derives the client manager's ordinary peer configuration;
- constructs and runs exactly one complete `PeerManagerCore`;
- connects that manager to the existing manager over an in-process ring;
- exposes raw IPv4 packet ingress and egress; and
- owns the two connection handles and client-manager cleanup.

ACL execution remains a `PeerManagerCore` responsibility. Every manager loads
ACL chains and default actions from its own runtime configuration and owns an
independent filter, connection tracking, rate limits, cache, and statistics. A
client manager may follow the network policy source through a subscription
owned as one of its normal runtime tasks; the attached layer neither builds nor
reloads ACLs and there is no attached-peer ACL coordinator.

The client configuration contains a name, EasyTier IPv4 address, ACL groups,
and a caller-provided `identity_private_key`. The attached-peer layer does not
derive or generate that key and does not know which protocol authenticated the
client. The portal owns stable identity-key policy.

When the network manager has Secure Mode enabled, the portal registers the
attached public key as an in-memory, non-reusable credential. The effective
grant groups are the configured groups that remain in the current network ACL
declarations; a scoped policy watcher updates that intersection and publishes
the existing credential-change event whenever declarations change. The grant
denies relay advertisement, permits no proxy CIDRs, is excluded from persistent
credential storage and management listing, and is revoked on construction
failure, explicit close, or drop.

The attached snapshot contains the network name and its own Noise keypair, but
no network secret, secret digest, group declarations, group memberships, or
group secrets. Its synchronized ACL keeps chains and default actions while
stripping `AclV1.group`; existing credential-route processing supplies its
trusted group membership from the current portal-owned grant.

For compatibility, a manager without Secure Mode retains the legacy
network-secret attached identity. This fallback is available only to an admin
manager that holds the network secret. A credential peer cannot host a portal.

Attached trust is connection metadata established by peer admission. The
packet channel carries ingress provenance from `PeerConn`; packet headers
cannot claim attached privileges. Relay-disable exceptions apply only to an
admitted attached connection or a destination with a live direct attached
connection.

### Reusable VPN portal runtime

The portable portal runtime in `easytier-core/src/gateway/vpn_portal/` knows
only:

- normalized clients: name, virtual IPv4 address, and ACL groups;
- authenticated sessions: client name, endpoint, identity private key, and
  bounded raw IPv4 packet channels;
- session generations and per-client status;
- IPv4 address translation; and
- direct construction and teardown of one attached peer manager per session.

It does not know WireGuard listener addresses, private keys, packet formats,
receiver indices, cookies, handshakes, or BoringTun types.

`CoreInstanceConfig` stores a normalized portal runtime configuration containing
only clients. The native host adapter owns the complete WireGuard configuration.
This preserves the existing rule that portable runtime state belongs in
`CoreInstanceConfig` while platform/protocol behavior enters through
`CoreHostAdapters`.

The protocol-neutral host interface starts listeners that yield authenticated
portal sessions and renders protocol-specific client configurations. A future
portal can reuse the same runtime by implementing that interface.

### Native WireGuard adapter

`easytier/src/vpn_portal/wireguard/` owns:

- validation of the dedicated portal private key;
- domain-separated HKDF derivation of WireGuard client keys and attached-peer
  identity keys;
- shared IPv4/IPv6 UDP listeners;
- shared MAC/cookie rate limiting;
- client selection by authenticated public key or receiver index;
- per-client BoringTun sessions, rekeys, endpoint roaming, and timers;
- bounded packet-channel backpressure; and
- activation only after authenticated transport traffic.

The dependency direction is:

`WireGuard adapter -> portal runtime -> attached peer -> peer manager`

No reverse dependency is permitted.

## Configuration Ownership

The external TOML/API configuration remains the configuration introduced by
`f63198e3`: WireGuard listen address, dedicated WireGuard private key, and named
clients. Normalization produces:

1. a Core runtime view containing only named clients; and
2. a native WireGuard host configured with the listener, key, and the same
   clients.

The legacy `client_cidr` model remains rejected with an explicit migration
error. A missing dedicated WireGuard key remains an error; the network secret is
never a fallback. Configuration dumps used in startup logs redact the portal
private key and all other existing secret classes.

## Session and Packet Flow

1. The WireGuard engine validates a datagram through its shared MAC/cookie
   limiter and dispatches it to the configured client slot.
2. The first authenticated transport packet activates a generation and emits a
   protocol-neutral session containing the client name, remote endpoint,
   attached identity key, and bounded raw IPv4 packet channels.
3. The portal runtime rejects unknown client names and serializes generations
   for each configured client.
4. It creates one `AttachedPeerRuntime`. In Secure Mode the portal first grants
   the supplied identity public key a transient credential, then starts a
   credential `PeerManagerCore` from the configured virtual address and
   credential groups. Without Secure Mode it starts the legacy admin-attached
   manager.
5. On client-to-mesh traffic, it learns and fixes the generation's tunnel source
   address, rewrites that source to the configured virtual address, updates all
   affected checksums, and injects the packet through the attached peer.
6. On mesh-to-client traffic, it rewrites the configured virtual destination
   back to the learned tunnel address and sends the packet through the
   session's outbound channel.
7. Portal cancellation, inbound closure, endpoint closure, outbound-task
   completion, or packet-send failure all enter one cleanup path. It stops and
   joins the remaining packet task, closes the attached peer, revokes the
   credential grant, and publishes the final client state before releasing the
   generation lock.

The IPv4 translator validates complete IPv4 packets and updates IPv4 header,
TCP/UDP pseudo-header, ICMP, and quoted IPv4 checksums. Translation is
transactional: validation completes before bytes are modified.

## Failure Semantics

- A portal configured on a credential node fails before listener startup with
  an explicit admin-authority error.
- Duplicate names or virtual addresses, invalid names, unusable addresses,
  unknown ACL groups, and invalid WireGuard keys fail before listener startup.
- Unknown clients and unauthenticated datagrams do not create attached peers or
  credential grants.
- IPv6 portal payloads and malformed IPv4 payloads are dropped.
- A tunnel source address cannot change within one client generation.
- A replacement generation starts only after the prior generation exits its
  client lock and completes attached-peer and credential cleanup.
- Portal stop cancels active sessions; it never depends on a protocol host
  dropping accepted channel senders.
- A full adapter packet channel drops only the current packet and logs at debug
  level. No unbounded queue or retry fallback is added.
- Credential groups come only from the portal-owned grant. Removing a network
  ACL group declaration updates every affected transient grant and removes that
  route membership without disconnecting the peer. Synchronized ACL policy
  never copies group declarations, memberships, or secrets into a Secure-Mode
  attached peer. Non-Secure-Mode attached peers retain the legacy group-proof
  path.
- Each manager owns its independent ACL execution state; no attached-peer
  coordinator distributes filters.
- Partial ring attachment is rolled back transactionally.
- Attached-peer construction failure sets the client state to `Error` and
  leaves no route or half-open peer connection.
- All attached relay privileges derive from peer-admission metadata, not packet
  contents.

## Commit Plan

### 1. `feat(peer): support protocol-agnostic attached peers`

Contains the attached peer runtime, connection-origin and packet-ingress
provenance, attached admission paths, relay-disable handling, lifecycle cleanup,
and focused peer tests. It contains no VPN configuration, WireGuard dependency,
or portal runtime.

### 2. `feat(vpn): add reusable attached-peer portal runtime`

Adds the normalized client model, authenticated session and host interface,
generic session runtime, generation and status handling, packet pumps, the IPv4
translator, and fake-host/unit tests.

To keep this commit independent and free of WireGuard edits, the existing
production portal path remains temporarily active. The new runtime is complete
and testable but is not selected by native composition yet. The next commit
switches production and removes the old path. The final tree contains one portal
runtime and one host interface.

### 3. `feat(wireguard): attach named clients through peer portal`

Adds the shared multi-client WireGuard engine, dedicated-key validation and
HKDF derivation, native socket binding, authenticated session activation, and
client configuration rendering. It switches native composition to the reusable
runtime and deletes the legacy portal path.

This commit also introduces the named-client TOML/API/CLI configuration, removes
legacy CIDR route injection, separates normalized Core configuration from the
WireGuard host configuration, redacts secrets, and updates the WireGuard
three-node integration scenario. The management RPC can retain its existing
aggregate representation until the next commit.

### 4. `feat(management): expose named VPN portal clients`

Adds per-client state, peer ID, endpoint, tunnel IP, generated client
configuration, and error fields to the management API. It updates the explicit
portal RPC, CLI output, and native GUI command bridge. Broad instance-running
information stops carrying client private configuration.

### 5. `feat(web): manage named WireGuard portal clients`

Adds Web/GUI configuration editing and runtime status, frontend types and
normalization, API wrappers, localized text, focused frontend tests, and the
English and Chinese documentation and migration examples.

## Verification

Each commit is verified while it is the branch head. A failure blocks creation
of the next commit.

1. Attached peer commit:
   - compile `easytier-core`;
   - run attached runtime route, ACL, close, and drop tests;
   - run ingress-provenance and relay-disable tests.
2. Generic portal commit:
   - compile `easytier-core` with the VPN portal feature;
   - run portal runtime and IPv4 translator tests.
3. WireGuard commit:
   - compile the native crate with WireGuard enabled;
   - run WireGuard key/config unit tests;
   - run the WireGuard three-node integration scenario in the existing `rust`
     container.
4. Management commit:
   - compile protobuf consumers;
   - run config/RPC serialization and portal management tests;
   - exercise CLI portal-info output.
5. Web/GUI commit:
   - run focused frontend configuration and status tests;
   - run frontend type checking and native GUI compilation checks;
   - smoke the affected Web/GUI path.

After the fifth commit, rerun the WireGuard end-to-end scenario and review the
complete `upstream/main..HEAD` diff. The final review reports only high-confidence
behavior regressions, security issues, data-consistency issues, or incorrect
architecture. Blocker and major findings are fixed before delivery.

## History Rewrite

The original feature commit remains reachable through
`backup/virtual-peer-wg-f63198e3`. The current branch is rebuilt from
`upstream/main`; no force push is performed by this task. The final result is a
five-commit feature series with behavior equivalent to `f63198e3` and the
architecture described above.
