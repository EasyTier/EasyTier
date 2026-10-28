//! Runtime visibility for peers admitted by managed credentials.
//!
//! Credential peers do not need to register with the console. The x25519
//! public key identifies their credential, while the peer ID identifies each
//! online node and joins it with the live routing table.

use std::collections::HashMap;

use base64::Engine as _;
use easytier::proto::api::instance::PeerManageRpc as _;
use easytier::proto::rpc_types::controller::BaseController;
use futures::StreamExt as _;
use sha2::Digest as _;
use uuid::Uuid;

use super::model::{CentralNetworkIntent, NetworkMode};
use crate::central_network::gateway::NetworkInstanceManager;
use crate::client_manager::ClientManager;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TemporaryPeerInfo {
    pub peer_id: u32,
    pub credential_id: Option<String>,
    pub credential_expiry_unix: Option<i64>,
    pub hostname: Option<String>,
    pub ipv4: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CredentialRef {
    pub credential_id: String,
    pub expiry_unix: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConnObservation {
    pub peer_id: u32,
    pub remote_static_pubkey: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RouteObservation {
    pub peer_id: u32,
    pub hostname: String,
    pub ipv4: Option<String>,
    pub version: String,
}

pub(crate) trait ConnFacts {
    fn peer_id(&self) -> u32;
    fn network_name(&self) -> &str;
    fn remote_static_pubkey(&self) -> &[u8];
    fn is_credential_identity(&self) -> bool;
}

impl ConnFacts for easytier_proto::core_peer::peer::PeerConnInfo {
    fn peer_id(&self) -> u32 {
        self.peer_id
    }

    fn network_name(&self) -> &str {
        &self.network_name
    }

    fn remote_static_pubkey(&self) -> &[u8] {
        &self.noise_remote_static_pubkey
    }

    fn is_credential_identity(&self) -> bool {
        self.peer_identity_type == easytier_proto::peer_rpc::PeerIdentityType::Credential as i32
    }
}

impl ConnFacts for easytier_proto::api::instance::PeerConnInfo {
    fn peer_id(&self) -> u32 {
        self.peer_id
    }

    fn network_name(&self) -> &str {
        &self.network_name
    }

    fn remote_static_pubkey(&self) -> &[u8] {
        &self.noise_remote_static_pubkey
    }

    fn is_credential_identity(&self) -> bool {
        self.peer_identity_type == easytier_proto::peer_rpc::PeerIdentityType::Credential as i32
    }
}

pub(crate) fn conn_observation(
    conn: &impl ConnFacts,
    network_name: &str,
) -> Option<ConnObservation> {
    if conn.network_name() != network_name
        || !conn.is_credential_identity()
        || conn.remote_static_pubkey().is_empty()
    {
        return None;
    }
    Some(ConnObservation {
        peer_id: conn.peer_id(),
        remote_static_pubkey: conn.remote_static_pubkey().to_vec(),
    })
}

impl From<&easytier_proto::core_peer::peer::Route> for RouteObservation {
    fn from(route: &easytier_proto::core_peer::peer::Route) -> Self {
        Self {
            peer_id: route.peer_id,
            hostname: route.hostname.clone(),
            ipv4: route.ipv4_addr.as_ref().map(ipv4_to_string),
            version: route.version.clone(),
        }
    }
}

impl From<&easytier_proto::api::instance::Route> for RouteObservation {
    fn from(route: &easytier_proto::api::instance::Route) -> Self {
        Self {
            peer_id: route.peer_id,
            hostname: route.hostname.clone(),
            ipv4: route.ipv4_addr.as_ref().map(ipv4_to_string),
            version: route.version.clone(),
        }
    }
}

fn ipv4_to_string(inet: &easytier_proto::common::Ipv4Inet) -> String {
    format!(
        "{}/{}",
        std::net::Ipv4Addr::from(inet.address.unwrap_or_default().addr),
        inet.network_length
    )
}

pub(crate) fn credential_fingerprint(secret_b64: &str) -> Option<String> {
    let secret: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(secret_b64.trim())
        .ok()?
        .try_into()
        .ok()?;
    let secret = x25519_dalek::StaticSecret::from(secret);
    let public = x25519_dalek::PublicKey::from(&secret);
    Some(hex_sha256(public.as_bytes()))
}

fn remote_pubkey_fingerprint(pubkey: &[u8]) -> String {
    hex_sha256(pubkey)
}

fn hex_sha256(data: &[u8]) -> String {
    sha2::Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn extract_temporary_peers(
    conns: &[ConnObservation],
    routes: &HashMap<u32, RouteObservation>,
    credential_by_fingerprint: &HashMap<String, CredentialRef>,
) -> Vec<TemporaryPeerInfo> {
    let mut by_peer = HashMap::new();
    for conn in conns {
        let fingerprint = remote_pubkey_fingerprint(&conn.remote_static_pubkey);
        let credential = credential_by_fingerprint.get(&fingerprint);
        let info = by_peer
            .entry(conn.peer_id)
            .or_insert_with(|| TemporaryPeerInfo {
                peer_id: conn.peer_id,
                credential_id: None,
                credential_expiry_unix: None,
                hostname: None,
                ipv4: None,
                version: None,
            });
        if info.credential_id.is_none()
            && let Some(credential) = credential
        {
            info.credential_id = Some(credential.credential_id.clone());
            info.credential_expiry_unix = Some(credential.expiry_unix);
        }
    }

    let mut peers = by_peer
        .into_values()
        .map(|mut info| {
            if let Some(route) = routes.get(&info.peer_id) {
                info.hostname = (!route.hostname.is_empty()).then(|| route.hostname.clone());
                info.ipv4 = route.ipv4.clone();
                info.version = (!route.version.is_empty()).then(|| route.version.clone());
            }
            info
        })
        .collect::<Vec<_>>();
    peers.sort_by(|left, right| {
        left.hostname
            .cmp(&right.hostname)
            .then_with(|| left.credential_id.cmp(&right.credential_id))
            .then_with(|| left.peer_id.cmp(&right.peer_id))
    });
    peers
}

/// Collect the current credential-peer view from the authoritative runtime.
/// Runtime queries are deliberately best-effort: an unavailable observer
/// produces a partial or empty view without failing the control-plane read.
pub(crate) async fn collect(
    client_manager: &ClientManager,
    intent: &CentralNetworkIntent,
    network_instances: Option<&NetworkInstanceManager>,
) -> Vec<TemporaryPeerInfo> {
    if !intent.secure_mode || intent.credentials.is_empty() {
        return Vec::new();
    }

    let credential_by_fingerprint = intent
        .credentials
        .iter()
        .filter_map(|credential| {
            credential_fingerprint(&credential.secret).map(|fingerprint| {
                (
                    fingerprint,
                    CredentialRef {
                        credential_id: credential.id.clone(),
                        expiry_unix: credential.expiry_unix,
                    },
                )
            })
        })
        .collect::<HashMap<_, _>>();
    if credential_by_fingerprint.is_empty() {
        return Vec::new();
    }

    let mut conns = Vec::new();
    let mut routes = HashMap::new();
    match intent.mode {
        NetworkMode::Gateway { .. } => {
            if let Some(instances) = network_instances
                && let Some(observation) =
                    instances.observe_network(intent.user_id, intent.id).await
            {
                conns.extend(
                    observation
                        .connections
                        .iter()
                        .filter_map(|conn| conn_observation(conn, &intent.network_name)),
                );
                for route in &observation.routes {
                    let route = RouteObservation::from(route);
                    routes.entry(route.peer_id).or_insert(route);
                }
            }
        }
        _ => collect_from_members(client_manager, intent, &mut conns, &mut routes).await,
    }

    extract_temporary_peers(&conns, &routes, &credential_by_fingerprint)
}

async fn collect_from_members(
    client_manager: &ClientManager,
    intent: &CentralNetworkIntent,
    conns: &mut Vec<ConnObservation>,
    routes: &mut HashMap<u32, RouteObservation>,
) {
    let mut observations = futures::stream::iter(
        intent
            .members
            .iter()
            .map(|member| async move {
                let Ok(device_id) = Uuid::parse_str(&member.device_id) else {
                    return None;
                };
                let session =
                    client_manager.get_session_by_machine_id(intent.user_id, &device_id)?;
                let client = session.scoped_client::<
            easytier::proto::api::instance::PeerManageRpcClientFactory<BaseController>,
        >();
                let instance = easytier::proto::api::instance::InstanceIdentifier {
                    selector: Some(
                        easytier::proto::api::instance::instance_identifier::Selector::Id(
                            intent.id.into(),
                        ),
                    ),
                };
                let peers = client
                    .list_peer(
                        BaseController::default(),
                        easytier::proto::api::instance::ListPeerRequest {
                            instance: Some(instance.clone()),
                        },
                    )
                    .await;
                let routes = client
                    .list_route(
                        BaseController::default(),
                        easytier::proto::api::instance::ListRouteRequest {
                            instance: Some(instance),
                        },
                    )
                    .await;
                Some((peers, routes))
            })
            .collect::<Vec<_>>(),
    )
    .buffered(16);
    while let Some(observation) = observations.next().await {
        let Some((peers, peer_routes)) = observation else {
            continue;
        };
        if let Ok(response) = peers {
            conns.extend(response.peer_infos.iter().flat_map(|peer| {
                peer.conns
                    .iter()
                    .filter_map(|conn| conn_observation(conn, &intent.network_name))
            }));
        }
        if let Ok(response) = peer_routes {
            for route in &response.routes {
                let route = RouteObservation::from(route);
                routes.entry(route.peer_id).or_insert(route);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential() -> (String, Vec<u8>, String) {
        let bytes = [7u8; 32];
        let secret = base64::engine::general_purpose::STANDARD.encode(bytes);
        let private = x25519_dalek::StaticSecret::from(bytes);
        let public = x25519_dalek::PublicKey::from(&private).as_bytes().to_vec();
        let fingerprint = credential_fingerprint(&secret).unwrap();
        (secret, public, fingerprint)
    }

    #[test]
    fn fingerprint_matches_the_handshake_public_key() {
        let (_, public, fingerprint) = credential();
        assert_eq!(remote_pubkey_fingerprint(&public), fingerprint);
        assert!(credential_fingerprint("not base64").is_none());
        assert!(
            credential_fingerprint(&base64::engine::general_purpose::STANDARD.encode([1u8; 8]))
                .is_none()
        );
    }

    #[test]
    fn connection_filter_requires_the_network_and_credential_identity() {
        let (_, public, _) = credential();
        let credential_identity = easytier_proto::peer_rpc::PeerIdentityType::Credential as i32;
        let admin_identity = easytier_proto::peer_rpc::PeerIdentityType::Admin as i32;
        let api_conn = |network_name: &str, identity, public: Vec<u8>| {
            easytier_proto::api::instance::PeerConnInfo {
                peer_id: 42,
                network_name: network_name.to_owned(),
                peer_identity_type: identity,
                noise_remote_static_pubkey: public,
                ..Default::default()
            }
        };
        let core_conn = easytier_proto::core_peer::peer::PeerConnInfo {
            peer_id: 42,
            network_name: "mesh".to_owned(),
            peer_identity_type: credential_identity,
            noise_remote_static_pubkey: public.clone(),
            ..Default::default()
        };

        assert!(
            conn_observation(
                &api_conn("mesh", credential_identity, public.clone()),
                "mesh"
            )
            .is_some()
        );
        assert!(conn_observation(&core_conn, "mesh").is_some());
        assert!(
            conn_observation(
                &api_conn("other", credential_identity, public.clone()),
                "mesh"
            )
            .is_none()
        );
        assert!(
            conn_observation(&api_conn("mesh", admin_identity, public.clone()), "mesh").is_none()
        );
        assert!(
            conn_observation(&api_conn("mesh", credential_identity, Vec::new()), "mesh").is_none()
        );
    }

    #[test]
    fn extraction_keeps_distinct_peers_using_the_same_credential() {
        let (_, public, fingerprint) = credential();
        let credentials = HashMap::from([(
            fingerprint,
            CredentialRef {
                credential_id: "credential-1".to_owned(),
                expiry_unix: 4_102_444_800,
            },
        )]);
        let conns = vec![
            ConnObservation {
                peer_id: 42,
                remote_static_pubkey: public.clone(),
            },
            ConnObservation {
                peer_id: 42,
                remote_static_pubkey: public.clone(),
            },
            ConnObservation {
                peer_id: 99,
                remote_static_pubkey: public,
            },
            ConnObservation {
                peer_id: 7,
                remote_static_pubkey: vec![9; 32],
            },
        ];
        let routes = HashMap::from([
            (
                42,
                RouteObservation {
                    peer_id: 42,
                    hostname: "temporary-phone".to_owned(),
                    ipv4: Some("10.126.0.3/24".to_owned()),
                    version: "2.7.0".to_owned(),
                },
            ),
            (
                99,
                RouteObservation {
                    peer_id: 99,
                    hostname: "temporary-laptop".to_owned(),
                    ipv4: Some("10.126.0.2/24".to_owned()),
                    version: "2.7.0".to_owned(),
                },
            ),
        ]);

        let peers = extract_temporary_peers(&conns, &routes, &credentials);
        assert_eq!(peers.len(), 3);
        let matched = peers.iter().find(|peer| peer.peer_id == 99).unwrap();
        assert_eq!(matched.credential_id.as_deref(), Some("credential-1"));
        assert_eq!(matched.hostname.as_deref(), Some("temporary-laptop"));
        assert_eq!(matched.ipv4.as_deref(), Some("10.126.0.2/24"));
        assert!(peers.iter().any(|peer| peer.peer_id == 42
            && peer.credential_id.as_deref() == Some("credential-1")
            && peer.hostname.as_deref() == Some("temporary-phone")));
        assert!(
            peers
                .iter()
                .any(|peer| peer.peer_id == 7 && peer.credential_id.is_none())
        );
    }
}
