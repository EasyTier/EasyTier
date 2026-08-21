//! Locally attached peers backed by their own portable peer runtime.
//!
//! An attached peer participates in routing, ACL identity, and peer lifecycle
//! exactly like a remote EasyTier node. The only privileged part of the seam is
//! the authenticated in-process connection to another peer manager.

use std::{
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use parking_lot::Mutex as StdMutex;
use tokio::{runtime::Handle, sync::Mutex, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::{
    config::{
        IpPrefix, PeerId,
        peers::PeerRuntimeSnapshot,
        runtime::{CoreInstanceRuntimeConfig, CoreRuntimeConfig, CoreRuntimeConfigStore},
    },
    host::packet::{HostPacket, HostPacketReceiver, host_packet_channel},
    packet::ZCPacket,
    peers::{
        conn::peer_conn::PeerConnId,
        peer_manager::{PeerManagerCore, PortablePeerManagerConfig, RouteAlgoType},
        public_ipv6::CorePublicIpv6Runtime,
    },
    tunnel::ring::create_ring_tunnel_pair,
};

/// Configuration for one locally attached peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedPeerConfig {
    pub name: String,
    pub virtual_ip: Ipv4Addr,
    pub groups: Vec<String>,
    /// Stable identity key supplied by the caller; changing it changes the
    /// peer identity, so callers must persist and reuse it across restarts.
    pub identity_private_key: [u8; 32],
}

#[derive(Debug, Clone, Copy)]
struct AttachedConnections {
    network_peer_id: PeerId,
    network_conn_id: PeerConnId,
    attached_peer_id: PeerId,
    attached_conn_id: PeerConnId,
}
#[cfg(test)]
#[derive(Default)]
struct CleanupPause {
    started: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    finished: tokio::sync::Notify,
}

struct AttachedCredentialRegistration {
    network_peer_manager: Arc<PeerManagerCore>,
    credential_id: Option<uuid::Uuid>,
    policy_task: Option<JoinHandle<()>>,
}

impl AttachedCredentialRegistration {
    fn register(
        network_peer_manager: Arc<PeerManagerCore>,
        network_runtime_config: CoreRuntimeConfigStore,
        public_key: [u8; 32],
        configured_groups: Vec<String>,
    ) -> anyhow::Result<Self> {
        let mut peer_changes = network_runtime_config.subscribe_peer_runtime_changes();
        let groups = effective_credential_groups(
            network_runtime_config.snapshot().as_ref(),
            &configured_groups,
        );
        let credential_id = network_peer_manager.register_ephemeral_credential(
            public_key,
            groups,
            false,
            Vec::new(),
            false,
        )?;
        let task_peer_manager = network_peer_manager.clone();
        let policy_task = tokio::spawn(async move {
            while peer_changes.changed().await.is_ok() {
                let _ = peer_changes.borrow_and_update();
                let groups = effective_credential_groups(
                    network_runtime_config.snapshot().as_ref(),
                    &configured_groups,
                );
                if task_peer_manager
                    .update_ephemeral_credential_groups(credential_id, groups)
                    .await
                    .is_none()
                {
                    return;
                }
            }
        });
        Ok(Self {
            network_peer_manager,
            credential_id: Some(credential_id),
            policy_task: Some(policy_task),
        })
    }

    async fn close(mut self) {
        if let Some(policy_task) = self.policy_task.take() {
            policy_task.abort();
            let _ = policy_task.await;
        }
        if let Some(credential_id) = self.credential_id.take() {
            self.network_peer_manager
                .revoke_ephemeral_credential_and_refresh(credential_id)
                .await;
        }
    }

    fn revoke(&mut self) {
        if let Some(credential_id) = self.credential_id.take() {
            self.network_peer_manager
                .revoke_ephemeral_credential(credential_id);
        }
    }
}

impl Drop for AttachedCredentialRegistration {
    fn drop(&mut self) {
        if let Some(policy_task) = self.policy_task.take() {
            policy_task.abort();
        }
        self.revoke();
    }
}
struct AttachedCleanupResources {
    connections: AttachedConnections,
    credential_registration: Option<AttachedCredentialRegistration>,
}

fn effective_credential_groups(
    network: &CoreInstanceRuntimeConfig,
    configured_groups: &[String],
) -> Vec<String> {
    network
        .peer
        .acl_group_declarations
        .iter()
        .filter(|declaration| configured_groups.contains(&declaration.group_name))
        .map(|declaration| declaration.group_name.clone())
        .collect()
}

fn build_attached_services(
    network: &CoreRuntimeConfig,
    credential_peer: bool,
) -> CoreRuntimeConfig {
    let mut services = network.clone();
    if credential_peer {
        services.acl = services.acl.for_credential_peer();
    }
    services
}

/// One complete EasyTier peer connected to another manager in process.
///
/// The runtime owns the attached manager's lifecycle. Callers exchange only
/// raw IPv4 packets through the Host packet seam.
pub struct AttachedPeerRuntime {
    network_peer_manager: Arc<PeerManagerCore>,
    peer_manager: Arc<PeerManagerCore>,
    packet_receiver: Mutex<HostPacketReceiver>,
    cleanup_resources: StdMutex<Option<AttachedCleanupResources>>,
    cleanup_done: CancellationToken,
    runtime_handle: Handle,
    closed: CancellationToken,
    #[cfg(test)]
    cleanup_pause: StdMutex<Option<Arc<CleanupPause>>>,
}

impl AttachedPeerRuntime {
    /// Constructs, starts, and transactionally connects one peer manager.
    pub async fn connect(
        network_peer_manager: Arc<PeerManagerCore>,
        network_runtime_config: CoreRuntimeConfigStore,
        config: AttachedPeerConfig,
    ) -> anyhow::Result<Arc<Self>> {
        let runtime_handle = Handle::current();
        let network = network_runtime_config.snapshot();
        let (peer_snapshot, credential_public_key) = build_peer_snapshot(&network, &config)?;
        let credential_registration = credential_public_key
            .map(|public_key| {
                AttachedCredentialRegistration::register(
                    network_peer_manager.clone(),
                    network_runtime_config.clone(),
                    public_key,
                    config.groups.clone(),
                )
            })
            .transpose()?;
        let services = build_attached_services(&network.services, credential_public_key.is_some());
        let runtime_config = CoreRuntimeConfigStore::new(services, Arc::new(peer_snapshot.clone()));
        let (packet_sender, packet_receiver) = host_packet_channel();
        let public_ipv6_runtime =
            CorePublicIpv6Runtime::new(runtime_config.clone(), Arc::new(()), Arc::new(()));
        let flags = peer_snapshot.flags.clone();
        let peer_manager = Arc::new(PeerManagerCore::new(
            PortablePeerManagerConfig {
                snapshot: peer_snapshot,
                route_algo: RouteAlgoType::Ospf,
                exit_nodes: Vec::new(),
                foreign_context_default_flags: flags,
            },
            runtime_config,
            Arc::new(()),
            packet_sender,
            public_ipv6_runtime,
            Arc::new(()),
            None,
            Arc::new(()),
        )?);
        if let Err(error) = peer_manager
            .follow_network_policy(network_runtime_config, config.groups)
            .await
        {
            peer_manager.clear_resources().await;
            return Err(error);
        }
        if let Err(error) = peer_manager.run().await {
            peer_manager.clear_resources().await;
            return Err(error.into());
        }

        let (network_tunnel, attached_tunnel) = create_ring_tunnel_pair();
        let (network_result, attached_result) = tokio::join!(
            network_peer_manager.add_attached_ring_tunnel_as_server(network_tunnel),
            peer_manager.add_attached_ring_client_tunnel(attached_tunnel),
        );
        let connections = match (network_result, attached_result) {
            (Ok((attached_peer_id, network_conn_id)), Ok((network_peer_id, attached_conn_id)))
                if attached_peer_id == peer_manager.my_peer_id()
                    && network_peer_id == network_peer_manager.my_peer_id() =>
            {
                AttachedConnections {
                    network_peer_id,
                    network_conn_id,
                    attached_peer_id,
                    attached_conn_id,
                }
            }
            (network_result, attached_result) => {
                let network_connection = network_result.as_ref().ok().copied();
                let attached_connection = attached_result.as_ref().ok().copied();
                cleanup_partial(
                    network_peer_manager,
                    peer_manager.clone(),
                    network_connection,
                    attached_connection,
                )
                .await;
                anyhow::bail!(
                    "failed to connect attached peer: \
                     network={network_result:?}, attached={attached_result:?}"
                );
            }
        };

        Ok(Arc::new(Self {
            network_peer_manager,
            peer_manager,
            packet_receiver: Mutex::new(packet_receiver),
            cleanup_resources: StdMutex::new(Some(AttachedCleanupResources {
                connections,
                credential_registration,
            })),
            cleanup_done: CancellationToken::new(),
            runtime_handle,
            closed: CancellationToken::new(),
            #[cfg(test)]
            cleanup_pause: StdMutex::new(None),
        }))
    }

    pub fn peer_id(&self) -> PeerId {
        self.peer_manager.my_peer_id()
    }
    #[cfg(test)]
    fn credential_id(&self) -> Option<uuid::Uuid> {
        self.cleanup_resources
            .lock()
            .as_ref()
            .and_then(|resources| resources.credential_registration.as_ref())
            .and_then(|registration| registration.credential_id)
    }

    /// Receives one packet addressed to the attached peer after routing and ACL.
    pub async fn recv_packet(&self) -> Option<HostPacket> {
        let mut packet_receiver = self.packet_receiver.lock().await;
        tokio::select! {
            biased;
            _ = self.closed.cancelled() => None,
            packet = packet_receiver.recv() => packet,
        }
    }

    /// Injects one raw IPv4 packet as traffic originating from the attached peer.
    pub async fn send_packet(&self, payload: &[u8]) -> anyhow::Result<()> {
        if self.closed.is_cancelled() {
            anyhow::bail!("attached peer is closed");
        }
        let destination = ipv4_destination(payload)?;
        self.peer_manager
            .send_msg_by_ip(
                ZCPacket::new_with_payload(payload),
                IpAddr::V4(destination),
                false,
            )
            .await?;
        Ok(())
    }

    fn start_cleanup(&self) {
        self.closed.cancel();
        let Some(resources) = self.cleanup_resources.lock().take() else {
            return;
        };
        let AttachedCleanupResources {
            connections,
            credential_registration,
        } = resources;
        let network_peer_manager = self.network_peer_manager.clone();
        let peer_manager = self.peer_manager.clone();
        let cleanup_done = self.cleanup_done.clone().drop_guard();
        #[cfg(test)]
        let cleanup_pause = self.cleanup_pause.lock().clone();
        self.runtime_handle.spawn(async move {
            let _cleanup_done = cleanup_done;
            let connection_cleanup = async move {
                #[cfg(test)]
                if let Some(pause) = cleanup_pause.as_ref() {
                    pause.started.notify_one();
                    pause.resume.notified().await;
                }
                cleanup(network_peer_manager, peer_manager, connections).await;
                #[cfg(test)]
                if let Some(pause) = cleanup_pause {
                    pause.finished.notify_one();
                }
            };
            if let Some(credential_registration) = credential_registration {
                tokio::join!(connection_cleanup, credential_registration.close());
            } else {
                connection_cleanup.await;
            }
        });
    }

    /// Idempotently tears down both connections and the attached manager.
    pub async fn close(&self) {
        self.start_cleanup();
        self.cleanup_done.cancelled().await;
    }
}

impl Drop for AttachedPeerRuntime {
    fn drop(&mut self) {
        self.start_cleanup();
    }
}

fn ipv4_destination(payload: &[u8]) -> anyhow::Result<Ipv4Addr> {
    if payload.len() < 20 || payload[0] >> 4 != 4 {
        anyhow::bail!("invalid attached-peer IPv4 header");
    }
    let header_len = usize::from(payload[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([payload[2], payload[3]]));
    if header_len < 20 || header_len > payload.len() || total_len != payload.len() {
        anyhow::bail!("invalid attached-peer IPv4 length");
    }
    Ok(Ipv4Addr::new(
        payload[16],
        payload[17],
        payload[18],
        payload[19],
    ))
}

fn build_peer_snapshot(
    network: &CoreInstanceRuntimeConfig,
    config: &AttachedPeerConfig,
) -> anyhow::Result<(PeerRuntimeSnapshot, Option<[u8; 32]>)> {
    network
        .peer
        .runtime
        .network_identity
        .network_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| anyhow::anyhow!("attached peers require a non-empty network secret"))?;
    if network.services.dhcp_ipv4 {
        anyhow::bail!("attached peers require a static network-manager IPv4 address");
    }
    let network_ipv4 = network
        .peer
        .runtime
        .core
        .routes
        .ipv4
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("attached peers require a network-manager IPv4 prefix"))?;
    let IpAddr::V4(network_address) = network_ipv4.address else {
        anyhow::bail!("attached peers require a network-manager IPv4 prefix");
    };
    let network_prefix = cidr::Ipv4Inet::new(network_address, network_ipv4.prefix_len)
        .map_err(|error| anyhow::anyhow!("invalid network-manager IPv4 prefix: {error}"))?;
    let network_prefix = network_prefix.network();
    if config.virtual_ip == network_address
        || !network_prefix.contains(&config.virtual_ip)
        || config.virtual_ip == network_prefix.first_address()
        || config.virtual_ip == network_prefix.last_address()
    {
        anyhow::bail!("unusable attached-peer IPv4 address: {}", config.virtual_ip);
    }

    let mut snapshot = network.peer.as_ref().clone();
    snapshot.runtime.core.node.peer_id = None;
    snapshot.runtime.core.node.instance_id = None;
    snapshot.runtime.core.node.hostname = Some(config.name.clone());
    snapshot.runtime.core.routes.ipv4 = Some(IpPrefix {
        address: IpAddr::V4(config.virtual_ip),
        prefix_len: network_ipv4.prefix_len,
    });
    snapshot.runtime.core.routes.ipv6 = None;
    snapshot.runtime.core.routes.advertised_routes.clear();
    snapshot.runtime.core.routes.proxy_networks.clear();
    snapshot.runtime.core.routes.foreign_networks.clear();
    snapshot.runtime.core.peer_policy.p2p_enabled = false;
    snapshot.runtime.core.peer_policy.relay_peer_rpc = false;
    snapshot.runtime.core.peer_policy.relay_data = false;
    snapshot.runtime.stun_info = Default::default();
    let supports_conn_list_sync = snapshot.runtime.feature_flags.support_conn_list_sync;
    snapshot.runtime.feature_flags = Default::default();
    snapshot.runtime.feature_flags.support_conn_list_sync = supports_conn_list_sync;
    snapshot.runtime.feature_flags.disable_p2p = true;
    snapshot.runtime.feature_flags.need_p2p = false;
    snapshot.runtime.feature_flags.avoid_relay_data = true;
    snapshot.flags.disable_p2p = true;
    snapshot.flags.need_p2p = false;
    snapshot.flags.relay_all_peer_rpc = false;
    snapshot.flags.disable_relay_data = true;
    snapshot.flags.p2p_only = false;
    snapshot.pinned_peers.clear();
    snapshot.avoid_relay_data_preference = true;
    snapshot.peer_group_memberships.clear();

    let credential_public_key = if snapshot
        .runtime
        .secure_mode
        .as_ref()
        .is_some_and(|secure| secure.enabled)
    {
        let private = StaticSecret::from(config.identity_private_key);
        let public = PublicKey::from(&private);
        snapshot.runtime.network_identity.network_secret = None;
        snapshot.runtime.network_identity.network_secret_digest = None;
        snapshot.hmac_secret_digest = false;
        snapshot.acl_group_declarations.clear();
        snapshot.runtime.secure_mode = Some(crate::proto::common::SecureModeConfig {
            enabled: true,
            local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
            local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
        });
        Some(*public.as_bytes())
    } else {
        None
    };
    Ok((snapshot, credential_public_key))
}

async fn cleanup(
    network_peer_manager: Arc<PeerManagerCore>,
    attached_peer_manager: Arc<PeerManagerCore>,
    connections: AttachedConnections,
) {
    cleanup_partial(
        network_peer_manager,
        attached_peer_manager,
        Some((connections.attached_peer_id, connections.network_conn_id)),
        Some((connections.network_peer_id, connections.attached_conn_id)),
    )
    .await;
}

async fn cleanup_partial(
    network_peer_manager: Arc<PeerManagerCore>,
    attached_peer_manager: Arc<PeerManagerCore>,
    network_connection: Option<(PeerId, PeerConnId)>,
    attached_connection: Option<(PeerId, PeerConnId)>,
) {
    if let (Some((attached_peer_id, network_conn_id)), Some((network_peer_id, attached_conn_id))) =
        (network_connection, attached_connection)
    {
        let _ = tokio::join!(
            network_peer_manager.close_peer_conn(attached_peer_id, &network_conn_id),
            attached_peer_manager.close_peer_conn(network_peer_id, &attached_conn_id),
        );
    } else {
        if let Some((attached_peer_id, network_conn_id)) = network_connection {
            let _ = network_peer_manager
                .close_peer_conn(attached_peer_id, &network_conn_id)
                .await;
        }
        if let Some((network_peer_id, attached_conn_id)) = attached_connection {
            let _ = attached_peer_manager
                .close_peer_conn(network_peer_id, &attached_conn_id)
                .await;
        }
    }
    if let Some((attached_peer_id, _)) = network_connection {
        let _ = network_peer_manager
            .get_peer_map()
            .close_peer(attached_peer_id)
            .await;
    }
    if let Some((network_peer_id, _)) = attached_connection {
        let _ = attached_peer_manager
            .get_peer_map()
            .close_peer(network_peer_id)
            .await;
    }
    attached_peer_manager.clear_resources().await;
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, time::Duration};

    use super::*;
    use crate::{
        config::{
            CoreConfig, NetworkIdentity, NodeConfig,
            peers::{HostRoutingPolicy, PeerGroupIdentity, PeerRuntimeConfig},
            runtime::CoreRuntimeConfig,
        },
        proto::{
            acl::{Acl, AclV1, GroupInfo},
            common::{PeerFeatureFlag, StunInfo},
        },
    };

    fn peer_manager_with_acl(
        tcp_whitelist: Vec<String>,
    ) -> (Arc<PeerManagerCore>, CoreRuntimeConfigStore) {
        peer_manager_with_acl_and_secure(tcp_whitelist, false)
    }

    fn peer_manager_with_acl_and_secure(
        tcp_whitelist: Vec<String>,
        secure_mode_enabled: bool,
    ) -> (Arc<PeerManagerCore>, CoreRuntimeConfigStore) {
        let secure_mode = secure_mode_enabled.then(|| {
            let private = StaticSecret::from([99u8; 32]);
            let public = PublicKey::from(&private);
            crate::proto::common::SecureModeConfig {
                enabled: true,
                local_private_key: Some(BASE64_STANDARD.encode(private.as_bytes())),
                local_public_key: Some(BASE64_STANDARD.encode(public.as_bytes())),
            }
        });
        let runtime = PeerRuntimeConfig {
            core: CoreConfig {
                node: NodeConfig {
                    network_name: "attached-test".to_owned(),
                    ..Default::default()
                },
                routes: crate::config::RouteConfig {
                    ipv4: Some(IpPrefix {
                        address: IpAddr::V4(Ipv4Addr::new(10, 82, 0, 1)),
                        prefix_len: 24,
                    }),
                    ..Default::default()
                },
                ..Default::default()
            },
            network_identity: NetworkIdentity::new(
                "attached-test".to_owned(),
                "shared-secret".to_owned(),
            ),
            stun_info: StunInfo::default(),
            feature_flags: PeerFeatureFlag::default(),
            secure_mode,
            host_routing: HostRoutingPolicy::default(),
        };
        let mut portable = PortablePeerManagerConfig::new(runtime);
        portable.snapshot.acl_group_declarations = vec![PeerGroupIdentity {
            group_name: "ops".to_owned(),
            group_secret: "ops-secret".to_owned(),
        }];
        let services = CoreRuntimeConfig {
            acl: crate::config::peers::AclRuleConfig {
                acl: Some(Acl {
                    acl_v1: Some(AclV1 {
                        chains: Vec::new(),
                        group: Some(GroupInfo {
                            declares: vec![crate::proto::acl::GroupIdentity {
                                group_name: "ops".to_owned(),
                                group_secret: "ops-secret".to_owned(),
                            }],
                            members: Vec::new(),
                        }),
                    }),
                }),
                tcp_whitelist,
                ..Default::default()
            },
            ..Default::default()
        };
        let store = CoreRuntimeConfigStore::new(services, Arc::new(portable.snapshot.clone()));
        let (packet_sender, _packet_receiver) = host_packet_channel();
        let public_ipv6_runtime =
            CorePublicIpv6Runtime::new(store.clone(), Arc::new(()), Arc::new(()));
        let peer_manager = Arc::new(
            PeerManagerCore::new(
                portable,
                store.clone(),
                Arc::new(()),
                packet_sender,
                public_ipv6_runtime,
                Arc::new(()),
                None,
                Arc::new(()),
            )
            .unwrap(),
        );
        (peer_manager, store)
    }

    fn peer_manager() -> (Arc<PeerManagerCore>, CoreRuntimeConfigStore) {
        peer_manager_with_acl(Vec::new())
    }

    async fn wait_for_route(
        peer: &PeerManagerCore,
        attached_peer_id: PeerId,
        address: Ipv4Addr,
        present: bool,
    ) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let found = peer.list_route_snapshots().await.iter().any(|route| {
                    route.peer_id == attached_peer_id
                        && route.ipv4_addr == Some(cidr::Ipv4Inet::new(address, 24).unwrap().into())
                });
                if found == present {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("attached route state did not converge");
    }

    async fn wait_for_acl_groups(
        network_peer_manager: &PeerManagerCore,
        peer_id: PeerId,
        expected: &[&str],
    ) {
        let expected = expected
            .iter()
            .map(|group| (*group).to_owned())
            .collect::<BTreeSet<_>>();
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let advertised = network_peer_manager
                    .get_route()
                    .get_peer_groups(peer_id)
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>();
                if advertised == expected {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("attached ACL groups did not converge");
    }

    async fn wait_for_acl_rules(attached: &AttachedPeerRuntime) {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if !attached
                    .peer_manager
                    .acl_filter()
                    .get_processor()
                    .get_rules_stats()
                    .is_empty()
                {
                    return;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("attached peer manager did not apply updated ACL rules");
    }

    #[tokio::test]
    async fn secure_attached_peer_updates_groups_with_declarations() {
        let (network_peer_manager, store) = peer_manager_with_acl_and_secure(Vec::new(), true);
        network_peer_manager.run().await.unwrap();
        let attached = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store.clone(),
            AttachedPeerConfig {
                name: "group-update".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 2),
                groups: vec!["ops".to_owned(), "audit".to_owned()],
                identity_private_key: [2; 32],
            },
        )
        .await
        .unwrap();
        wait_for_acl_groups(&network_peer_manager, attached.peer_id(), &["ops"]).await;
        store.update_peer_with(|peer| {
            peer.acl_group_declarations.push(PeerGroupIdentity {
                group_name: "audit".to_owned(),
                group_secret: "audit-secret".to_owned(),
            });
        });
        wait_for_acl_groups(&network_peer_manager, attached.peer_id(), &["audit", "ops"]).await;

        store.update_peer_with(|peer| peer.acl_group_declarations.clear());

        wait_for_acl_groups(&network_peer_manager, attached.peer_id(), &[]).await;
        attached.close().await;
        network_peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn ephemeral_credential_group_update_refreshes_route() {
        let (network_peer_manager, store) = peer_manager_with_acl_and_secure(Vec::new(), true);
        network_peer_manager.run().await.unwrap();
        let attached = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store,
            AttachedPeerConfig {
                name: "direct-group-update".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 2),
                groups: vec!["ops".to_owned()],
                identity_private_key: [5; 32],
            },
        )
        .await
        .unwrap();
        wait_for_acl_groups(&network_peer_manager, attached.peer_id(), &["ops"]).await;
        let credential_id = attached.credential_id().unwrap();

        assert_eq!(
            network_peer_manager
                .update_ephemeral_credential_groups(credential_id, Vec::new())
                .await,
            Some(true)
        );

        wait_for_acl_groups(&network_peer_manager, attached.peer_id(), &[]).await;
        attached.close().await;
        network_peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn peer_manager_loads_initial_acl_from_its_runtime_config() {
        let (peer_manager, _store) = peer_manager_with_acl(vec!["22".to_owned()]);

        assert!(
            !peer_manager
                .acl_filter()
                .get_processor()
                .get_rules_stats()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn invalid_acl_update_does_not_publish_manager_config() {
        let (peer_manager, store) = peer_manager();
        let before = store.snapshot();
        let mut invalid = before.as_ref().clone();
        invalid.services.acl.tcp_whitelist = vec!["not-a-port".to_owned()];

        assert!(peer_manager.update_runtime_config(invalid).await.is_err());
        assert_eq!(store.snapshot().services.acl, before.services.acl);
        assert!(
            peer_manager
                .acl_filter()
                .get_processor()
                .get_rules_stats()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn dropped_credential_registration_revokes_credential() {
        let (network_peer_manager, store) = peer_manager_with_acl_and_secure(Vec::new(), true);
        let credential_public_key = *PublicKey::from(&StaticSecret::from([4; 32])).as_bytes();

        let registration = AttachedCredentialRegistration::register(
            network_peer_manager.clone(),
            store,
            credential_public_key,
            vec!["ops".to_owned()],
        )
        .unwrap();
        assert!(
            network_peer_manager
                .credential_manager()
                .is_pubkey_trusted(&credential_public_key)
        );

        drop(registration);

        assert!(
            !network_peer_manager
                .credential_manager()
                .is_pubkey_trusted(&credential_public_key)
        );
    }

    #[tokio::test]
    async fn secure_attached_runtime_removes_admin_and_group_secrets() {
        let (_network_peer_manager, store) = peer_manager_with_acl_and_secure(Vec::new(), true);
        let network = store.snapshot();
        let config = AttachedPeerConfig {
            name: "sanitized".to_owned(),
            virtual_ip: Ipv4Addr::new(10, 82, 0, 2),
            groups: vec!["ops".to_owned()],
            identity_private_key: [3; 32],
        };

        let (snapshot, credential_public_key) =
            build_peer_snapshot(network.as_ref(), &config).unwrap();
        let services = build_attached_services(&network.services, credential_public_key.is_some());

        assert!(credential_public_key.is_some());
        assert!(snapshot.runtime.network_identity.network_secret.is_none());
        assert!(
            snapshot
                .runtime
                .network_identity
                .network_secret_digest
                .is_none()
        );
        assert!(snapshot.peer_group_memberships.is_empty());
        assert!(snapshot.acl_group_declarations.is_empty());
        assert!(
            services
                .acl
                .acl
                .as_ref()
                .unwrap()
                .acl_v1
                .as_ref()
                .unwrap()
                .group
                .is_none()
        );
        assert!(
            network
                .services
                .acl
                .acl
                .as_ref()
                .unwrap()
                .acl_v1
                .as_ref()
                .unwrap()
                .group
                .is_some()
        );
    }

    #[tokio::test]
    async fn secure_attached_peer_uses_credential_identity_and_granted_groups() {
        let (network_peer_manager, store) = peer_manager_with_acl_and_secure(Vec::new(), true);
        network_peer_manager.run().await.unwrap();
        let identity_private_key = [1; 32];
        let credential_public_key =
            *PublicKey::from(&StaticSecret::from(identity_private_key)).as_bytes();
        assert!(
            !network_peer_manager
                .credential_manager()
                .is_pubkey_trusted(&credential_public_key)
        );

        let attached = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store,
            AttachedPeerConfig {
                name: "credential".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 2),
                groups: vec!["ops".to_owned()],
                identity_private_key,
            },
        )
        .await
        .unwrap();
        assert!(
            network_peer_manager
                .credential_manager()
                .is_pubkey_trusted(&credential_public_key)
        );

        assert!(
            !attached.peer_manager.can_manage_credentials(),
            "Secure-Mode attached peer retained administrator credentials"
        );
        wait_for_acl_groups(&network_peer_manager, attached.peer_id(), &["ops"]).await;

        attached.close().await;
        assert!(
            !network_peer_manager
                .credential_manager()
                .is_pubkey_trusted(&credential_public_key)
        );
        network_peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn peer_managers_own_acl_updates_for_attached_clients() {
        let (network_peer_manager, store) = peer_manager();
        let peer_subscribers_before_run = store.peer_change_subscriber_count();
        network_peer_manager.run().await.unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            while store.peer_change_subscriber_count() == peer_subscribers_before_run {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("network peer manager did not subscribe to config updates");
        let peer_subscribers = store.peer_change_subscriber_count();
        let service_subscribers = store.service_change_subscriber_count();

        let first = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store.clone(),
            AttachedPeerConfig {
                name: "first".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 2),
                groups: vec!["ops".to_owned()],
                identity_private_key: [1; 32],
            },
        )
        .await
        .unwrap();
        let second = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store.clone(),
            AttachedPeerConfig {
                name: "second".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 3),
                groups: Vec::new(),
                identity_private_key: [2; 32],
            },
        )
        .await
        .unwrap();

        assert_ne!(first.peer_id(), second.peer_id());
        assert!(!Arc::ptr_eq(
            &first.peer_manager.acl_filter(),
            &second.peer_manager.acl_filter()
        ));
        assert_eq!(store.peer_change_subscriber_count(), peer_subscribers + 2);
        assert_eq!(
            store.service_change_subscriber_count(),
            service_subscribers + 2
        );
        wait_for_route(
            &network_peer_manager,
            first.peer_id(),
            Ipv4Addr::new(10, 82, 0, 2),
            true,
        )
        .await;
        wait_for_route(
            &network_peer_manager,
            second.peer_id(),
            Ipv4Addr::new(10, 82, 0, 3),
            true,
        )
        .await;
        wait_for_acl_groups(&network_peer_manager, first.peer_id(), &["ops"]).await;

        store.update_peer_with(|peer| peer.acl_group_declarations.clear());
        wait_for_acl_groups(&network_peer_manager, first.peer_id(), &[]).await;

        let mut updated = store.snapshot().as_ref().clone();
        updated.services.acl.tcp_whitelist.push("22".to_owned());
        store.replace(updated);
        wait_for_acl_rules(&first).await;
        wait_for_acl_rules(&second).await;

        let first_peer_id = first.peer_id();
        first.close().await;
        assert_eq!(store.peer_change_subscriber_count(), peer_subscribers + 1);
        assert_eq!(
            store.service_change_subscriber_count(),
            service_subscribers + 1
        );
        wait_for_route(
            &network_peer_manager,
            first_peer_id,
            Ipv4Addr::new(10, 82, 0, 2),
            false,
        )
        .await;
        second.close().await;
        assert_eq!(store.peer_change_subscriber_count(), peer_subscribers);
        assert_eq!(store.service_change_subscriber_count(), service_subscribers);
        network_peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn attached_peer_reconnects_after_acl_group_removal() {
        let (network_peer_manager, store) = peer_manager();
        network_peer_manager.run().await.unwrap();
        store.update_peer_with(|peer| peer.acl_group_declarations.clear());

        let attached = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store,
            AttachedPeerConfig {
                name: "reconnected".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 4),
                groups: vec!["ops".to_owned()],
                identity_private_key: [3; 32],
            },
        )
        .await
        .unwrap();

        wait_for_route(
            &network_peer_manager,
            attached.peer_id(),
            Ipv4Addr::new(10, 82, 0, 4),
            true,
        )
        .await;
        wait_for_acl_groups(&network_peer_manager, attached.peer_id(), &[]).await;
        attached.close().await;
        network_peer_manager.clear_resources().await;
    }
    #[tokio::test]
    async fn cancelled_close_can_be_awaited_again() {
        let (network_peer_manager, store) = peer_manager();
        network_peer_manager.run().await.unwrap();
        let identity_private_key = [6; 32];
        let attached = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store,
            AttachedPeerConfig {
                name: "cancelled-close".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 4),
                groups: Vec::new(),
                identity_private_key,
            },
        )
        .await
        .unwrap();
        let peer_id = attached.peer_id();
        wait_for_route(
            &network_peer_manager,
            peer_id,
            Ipv4Addr::new(10, 82, 0, 4),
            true,
        )
        .await;
        assert!(
            network_peer_manager
                .get_peer_map()
                .has_direct_attached_peer(peer_id),
            "attached connection was not live before close"
        );

        let pause = Arc::new(CleanupPause::default());
        *attached.cleanup_pause.lock() = Some(pause.clone());
        let first_close = tokio::spawn({
            let attached = attached.clone();
            async move { attached.close().await }
        });
        pause.started.notified().await;
        first_close.abort();
        let _ = first_close.await;
        pause.resume.notify_one();
        assert!(
            network_peer_manager
                .get_peer_map()
                .has_direct_attached_peer(peer_id),
            "cancelling close unexpectedly completed connection cleanup"
        );

        tokio::time::timeout(Duration::from_secs(5), attached.close())
            .await
            .expect("retrying close did not await the in-flight cleanup");
        assert!(
            !network_peer_manager
                .get_peer_map()
                .has_direct_attached_peer(peer_id),
            "cancelled close left the attached connection live"
        );
        wait_for_route(
            &network_peer_manager,
            peer_id,
            Ipv4Addr::new(10, 82, 0, 4),
            false,
        )
        .await;
        network_peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn closing_attached_peer_unblocks_packet_receiver() {
        let (network_peer_manager, store) = peer_manager();
        network_peer_manager.run().await.unwrap();
        let attached = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store,
            AttachedPeerConfig {
                name: "closed-receiver".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 4),
                groups: Vec::new(),
                identity_private_key: [3; 32],
            },
        )
        .await
        .unwrap();
        let waiting = tokio::spawn({
            let attached = attached.clone();
            async move { attached.recv_packet().await }
        });
        tokio::task::yield_now().await;

        attached.close().await;

        let packet = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("packet receiver remained blocked after close")
            .unwrap();
        assert!(packet.is_none());
        network_peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn dropping_attached_peer_removes_its_route() {
        let (network_peer_manager, store) = peer_manager();
        network_peer_manager.run().await.unwrap();
        let attached = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store,
            AttachedPeerConfig {
                name: "dropped".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 4),
                groups: Vec::new(),
                identity_private_key: [3; 32],
            },
        )
        .await
        .unwrap();
        let peer_id = attached.peer_id();
        wait_for_route(
            &network_peer_manager,
            peer_id,
            Ipv4Addr::new(10, 82, 0, 4),
            true,
        )
        .await;

        drop(attached);

        wait_for_route(
            &network_peer_manager,
            peer_id,
            Ipv4Addr::new(10, 82, 0, 4),
            false,
        )
        .await;
        network_peer_manager.clear_resources().await;
    }

    #[tokio::test]
    async fn dropping_secure_attached_peer_refreshes_route_trust_before_disconnect() {
        let (network_peer_manager, store) = peer_manager_with_acl_and_secure(Vec::new(), true);
        network_peer_manager.run().await.unwrap();
        let identity_private_key = [7; 32];
        let credential_public_key =
            *PublicKey::from(&StaticSecret::from(identity_private_key)).as_bytes();
        let attached = AttachedPeerRuntime::connect(
            network_peer_manager.clone(),
            store,
            AttachedPeerConfig {
                name: "dropped-secure".to_owned(),
                virtual_ip: Ipv4Addr::new(10, 82, 0, 5),
                groups: vec!["ops".to_owned()],
                identity_private_key,
            },
        )
        .await
        .unwrap();
        let peer_id = attached.peer_id();
        wait_for_route(
            &network_peer_manager,
            peer_id,
            Ipv4Addr::new(10, 82, 0, 5),
            true,
        )
        .await;
        wait_for_acl_groups(&network_peer_manager, peer_id, &["ops"]).await;

        let pause = Arc::new(CleanupPause::default());
        *attached.cleanup_pause.lock() = Some(pause.clone());
        drop(attached);
        pause.started.notified().await;

        tokio::time::timeout(Duration::from_secs(5), async {
            while network_peer_manager
                .credential_manager()
                .is_pubkey_trusted(&credential_public_key)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropped attached credential remained trusted");
        wait_for_route(
            &network_peer_manager,
            peer_id,
            Ipv4Addr::new(10, 82, 0, 5),
            false,
        )
        .await;
        assert!(
            !network_peer_manager
                .get_peer_map()
                .has_direct_attached_peer(peer_id),
            "credential revocation did not refresh route trust before cleanup resumed"
        );

        pause.resume.notify_one();
        pause.finished.notified().await;
        network_peer_manager.clear_resources().await;
    }
}
