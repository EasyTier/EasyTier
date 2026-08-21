//! Native WireGuard Adapter for the VPN portal.
//!
//! One UDP socket and one shared MAC/cookie limiter demultiplex all configured
//! public keys. Per-client slots keep rekeys and endpoint roaming within one
//! authenticated generation; Core receives a new session only after the prior
//! generation has expired and been detached atomically.

mod engine;

use std::{
    fmt,
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

use anyhow::Context as _;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use boringtun::x25519::{PublicKey, StaticSecret};
use easytier_core::{
    config::toml::VpnPortalConfig,
    gateway::vpn_portal::{PortalClientConfigPlan, PortalHost, PortalListener, PortalSession},
    socket::{
        ListenerConnectionCounter, NetNamespace, SocketContext, SocketListener,
        udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory},
    },
};
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::{sync::mpsc, task::JoinSet};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    host_runtime::{NativeHostRuntime, native_host_runtime},
    socket::udp::RuntimeUdpSocket,
};

use self::engine::{DerivedClient, PortalEngine};

struct WireGuardPortalListener {
    url: url::Url,
    sockets: Vec<Arc<RuntimeUdpSocket>>,
    receiver: mpsc::UnboundedReceiver<PortalSession>,
    engine: Arc<PortalEngine>,
    tasks: JoinSet<anyhow::Result<()>>,
    listened: bool,
}

impl fmt::Debug for WireGuardPortalListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WireGuardPortalListener")
            .field("url", &self.url)
            .finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl SocketListener for WireGuardPortalListener {
    type Accepted = PortalSession;

    async fn listen(&mut self) -> anyhow::Result<()> {
        if self.listened {
            return Ok(());
        }
        self.listened = true;
        for socket in &self.sockets {
            let socket = socket.clone();
            let engine = self.engine.clone();
            self.tasks.spawn(async move {
                loop {
                    let datagram = socket
                        .recv_session_datagram()
                        .await
                        .context("WireGuard portal UDP receive failed")?;
                    engine
                        .handle_datagram(socket.clone(), datagram.remote_addr, &datagram.payload)
                        .await;
                }
            });
        }
        let engine = self.engine.clone();
        self.tasks.spawn(async move {
            engine.run_timers().await;
            Ok(())
        });
        Ok(())
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        let tasks_active = !self.tasks.is_empty();
        tokio::select! {
            biased;
            task = self.tasks.join_next(), if tasks_active => {
                let error = match task {
                    Some(Ok(Err(error))) => {
                        anyhow::anyhow!("WireGuard portal reader stopped: {error:#}")
                    }
                    Some(Ok(Ok(()))) => {
                        anyhow::anyhow!("WireGuard portal task stopped unexpectedly")
                    }
                    Some(Err(error)) => {
                        anyhow::anyhow!("WireGuard portal task failed: {error}")
                    }
                    None => anyhow::anyhow!("WireGuard portal listener stopped"),
                };
                self.engine.cancel();
                self.tasks.abort_all();
                Err(error)
            }
            session = self.receiver.recv() => {
                session.ok_or_else(|| anyhow::anyhow!("WireGuard portal listener stopped"))
            }
        }
    }

    fn local_url(&self) -> url::Url {
        self.url.clone()
    }

    fn connection_counter(&self) -> Arc<dyn ListenerConnectionCounter> {
        Arc::new(PortalConnectionCounter(self.engine.clone()))
    }
}

impl Drop for WireGuardPortalListener {
    fn drop(&mut self) {
        self.engine.cancel();
        self.tasks.abort_all();
    }
}

struct PortalConnectionCounter(Arc<PortalEngine>);

impl fmt::Debug for PortalConnectionCounter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("PortalConnectionCounter").finish()
    }
}

impl ListenerConnectionCounter for PortalConnectionCounter {
    fn get(&self) -> Option<u32> {
        Some(self.0.connection_count())
    }
}

pub struct WireGuardPortalHost {
    global_ctx: ArcGlobalCtx,
    config: VpnPortalConfig,
    setup: Result<WireGuardPortalSetup, String>,
}

struct WireGuardPortalSetup {
    server_private: [u8; 32],
    server_public: PublicKey,
    clients: Vec<DerivedClient>,
}

impl WireGuardPortalHost {
    pub fn new(global_ctx: ArcGlobalCtx, config: VpnPortalConfig) -> Arc<Self> {
        let setup = (|| -> anyhow::Result<_> {
            let (master, server_private) = portal_master_and_server_key(&config)?;
            let server_public = PublicKey::from(&StaticSecret::from(server_private));
            let mut clients = Vec::with_capacity(config.clients.len());
            for client in &config.clients {
                let wireguard_private =
                    derive_named_key(&master, b"wireguard-client", &client.name)?;
                let identity_private_key =
                    derive_named_key(&master, b"attached-noise", &client.name)?;
                clients.push(DerivedClient {
                    config: client.clone(),
                    wireguard_private,
                    wireguard_public: PublicKey::from(&StaticSecret::from(wireguard_private)),
                    identity_private_key,
                });
            }
            Ok(WireGuardPortalSetup {
                server_private,
                server_public,
                clients,
            })
        })()
        .map_err(|error| error.to_string());
        Arc::new(Self {
            global_ctx,
            config,
            setup,
        })
    }

    async fn bind_socket(
        &self,
        runtime: &NativeHostRuntime,
        address: SocketAddr,
        only_v6: bool,
    ) -> anyhow::Result<Arc<RuntimeUdpSocket>> {
        let context = SocketContext::default()
            .with_socket_mark(self.global_ctx.get_flags().socket_mark)
            .with_netns(self.global_ctx.net_ns.name().map(NetNamespace::new));
        runtime
            .bind_udp(
                UdpBindOptions::port_bound_listener(address)
                    .with_context(context)
                    .with_only_v6(only_v6),
            )
            .await
    }
}
fn secondary_ipv6_bind_address(address: SocketAddr, primary_port: u16) -> Option<SocketAddr> {
    let SocketAddr::V4(address) = address else {
        return None;
    };
    address
        .ip()
        .is_unspecified()
        .then(|| SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, primary_port, 0, 0)))
}

#[async_trait::async_trait]
impl PortalHost for WireGuardPortalHost {
    async fn start_listeners(&self) -> anyhow::Result<Vec<PortalListener>> {
        let setup = self
            .setup
            .as_ref()
            .map_err(|error| anyhow::anyhow!(error.clone()))?;
        let runtime = native_host_runtime();
        let primary = self
            .bind_socket(&runtime, self.config.wireguard_listen, false)
            .await
            .context("failed to bind WireGuard VPN portal")?;
        let local = primary.local_addr()?;
        let mut sockets = vec![primary.clone()];
        if let Some(v6_address) =
            secondary_ipv6_bind_address(self.config.wireguard_listen, local.port())
            && let Ok(v6) = self.bind_socket(&runtime, v6_address, true).await
        {
            sockets.push(v6);
        }
        let url = url::Url::parse(&format!("wg://{local}"))?;
        let (accepted, receiver) = mpsc::unbounded_channel();
        let engine = PortalEngine::new(setup.server_private, setup.clients.clone(), accepted);
        Ok(vec![Box::new(WireGuardPortalListener {
            url,
            sockets,
            receiver,
            engine,
            tasks: JoinSet::new(),
            listened: false,
        })])
    }

    fn name(&self) -> String {
        "wireguard".to_owned()
    }

    fn render_client_config(&self, plan: &PortalClientConfigPlan) -> String {
        let client = self
            .setup
            .as_ref()
            .expect("client config is rendered only after successful startup")
            .clients
            .iter()
            .find(|client| client.config.name == plan.name)
            .expect("Core only renders configured clients");
        let endpoint = &plan.listener_url[url::Position::BeforeHost..url::Position::AfterPort];
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = {}/32\n\n[Peer]\nPublicKey = {}\nAllowedIPs = {}\nEndpoint = {} # replace wildcard with the public address\nPersistentKeepalive = 25\n",
            BASE64_STANDARD.encode(client.wireguard_private),
            plan.address,
            BASE64_STANDARD.encode(
                self.setup
                    .as_ref()
                    .expect("client config is rendered only after successful startup")
                    .server_public
                    .as_bytes()
            ),
            plan.allowed_ips.join(", "),
            endpoint,
        )
    }
}

fn portal_master_and_server_key(config: &VpnPortalConfig) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let encoded = config
        .wireguard_private_key
        .as_deref()
        .filter(|key| !key.is_empty())
        .ok_or_else(|| anyhow::anyhow!("WireGuard portal requires a dedicated private key"))?;
    let decoded = BASE64_STANDARD
        .decode(encoded)
        .context("invalid base64 WireGuard portal private key")?;
    let key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("WireGuard portal private key must be 32 bytes"))?;
    Ok((key, key))
}

fn derive_named_key(master: &[u8; 32], domain: &[u8], name: &str) -> anyhow::Result<[u8; 32]> {
    let mut context = Vec::new();
    append_label(&mut context, domain);
    append_label(&mut context, name.as_bytes());
    let hkdf = Hkdf::<Sha256>::new(Some(b"easytier/wireguard-portal/v1"), master);
    let mut output = [0u8; 32];
    hkdf.expand(&context, &mut output)
        .map_err(|_| anyhow::anyhow!("failed to derive portal client key"))?;
    Ok(output)
}

fn append_label(output: &mut Vec<u8>, label: &[u8]) {
    output.extend_from_slice(&(label.len() as u32).to_be_bytes());
    output.extend_from_slice(label);
}

#[cfg(test)]
pub(crate) fn test_wireguard_keys(
    config: &VpnPortalConfig,
    client_name: &str,
) -> anyhow::Result<([u8; 32], [u8; 32])> {
    let (master, server_private) = portal_master_and_server_key(config)?;
    let client_private = derive_named_key(&master, b"wireguard-client", client_name)?;
    let server_public = *PublicKey::from(&StaticSecret::from(server_private)).as_bytes();
    Ok((server_public, client_private))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_keys_are_domain_separated_and_stable() {
        let master = [7; 32];
        let client = derive_named_key(&master, b"wireguard-client", "laptop").unwrap();
        assert_eq!(
            client,
            derive_named_key(&master, b"wireguard-client", "laptop").unwrap()
        );
        assert_ne!(
            client,
            derive_named_key(&master, b"attached-noise", "laptop").unwrap()
        );
        assert_ne!(
            client,
            derive_named_key(&master, b"wireguard-client", "phone").unwrap()
        );
    }

    #[test]
    fn explicit_server_key_is_the_derivation_master() {
        let key = [9; 32];
        let config = VpnPortalConfig {
            wireguard_listen: "127.0.0.1:51820".parse().unwrap(),
            wireguard_private_key: Some(BASE64_STANDARD.encode(key)),
            clients: Vec::new(),
        };
        assert_eq!(portal_master_and_server_key(&config).unwrap(), (key, key));
    }

    #[test]
    fn portal_key_has_no_network_secret_fallback() {
        let config = VpnPortalConfig {
            wireguard_listen: "127.0.0.1:51820".parse().unwrap(),
            wireguard_private_key: None,
            clients: Vec::new(),
        };
        assert!(
            portal_master_and_server_key(&config)
                .unwrap_err()
                .to_string()
                .contains("dedicated private key")
        );
    }

    #[test]
    fn ipv6_wildcard_reuses_primary_ephemeral_port() {
        assert_eq!(
            secondary_ipv6_bind_address("0.0.0.0:0".parse().unwrap(), 43123),
            Some("[::]:43123".parse().unwrap())
        );
        assert_eq!(
            secondary_ipv6_bind_address("127.0.0.1:0".parse().unwrap(), 43123),
            None
        );
    }

    #[tokio::test]
    async fn reader_failure_terminates_listener_accept() {
        let (accepted, receiver) = mpsc::unbounded_channel();
        let engine = PortalEngine::new([11; 32], Vec::new(), accepted);
        let mut tasks: JoinSet<anyhow::Result<()>> = JoinSet::new();
        tasks.spawn(async { anyhow::bail!("UDP receive failed") });
        let mut listener = WireGuardPortalListener {
            url: "wg://127.0.0.1:51820".parse().unwrap(),
            sockets: Vec::new(),
            receiver,
            engine,
            tasks,
            listened: true,
        };

        let error = tokio::time::timeout(std::time::Duration::from_secs(1), listener.accept())
            .await
            .expect("listener accept ignored reader failure")
            .unwrap_err();

        assert!(error.to_string().contains("UDP receive failed"));
    }
}
