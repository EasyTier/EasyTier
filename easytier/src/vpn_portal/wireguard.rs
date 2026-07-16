use std::{
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

use anyhow::Context;
use base64::{Engine, prelude::BASE64_STANDARD};
use easytier_core::{
    listener::SocketListener,
    vpn_portal::{VpnPortalClientConfigPlan, VpnPortalHost, VpnPortalListener},
};

use crate::{
    common::{config::NetworkIdentity, global_ctx::ArcGlobalCtx},
    tunnel::wireguard::{WgConfig, WgTunnelListener},
};

pub(crate) fn get_wg_config_for_portal(nid: &NetworkIdentity) -> WgConfig {
    let key_seed = format!(
        "{}{}",
        nid.network_name,
        nid.network_secret.as_ref().unwrap_or(&String::new())
    );
    WgConfig::new_for_portal(&key_seed, &key_seed)
}

fn listener_endpoint(listener_url: &url::Url) -> &str {
    &listener_url[url::Position::BeforeHost..url::Position::AfterPort]
}

pub struct WireGuardPortalHost {
    global_ctx: ArcGlobalCtx,
    wg_config: WgConfig,
}

impl WireGuardPortalHost {
    pub fn new(global_ctx: ArcGlobalCtx) -> Arc<Self> {
        Arc::new(Self {
            wg_config: get_wg_config_for_portal(&global_ctx.get_network_identity()),
            global_ctx,
        })
    }

    async fn start_listener(&self, listener_addr: SocketAddr) -> anyhow::Result<VpnPortalListener> {
        let mut listener_url = url::Url::parse("wg://0.0.0.0:0").unwrap();
        listener_url.set_port(Some(listener_addr.port())).unwrap();
        listener_url.set_ip_host(listener_addr.ip()).unwrap();
        let mut listener = WgTunnelListener::new(listener_url, self.wg_config.clone());
        {
            let _guard = self.global_ctx.net_ns.guard();
            listener
                .listen()
                .await
                .context("failed to start WireGuard VPN portal listener")?;
        }
        Ok(Box::new(listener))
    }
}

#[async_trait::async_trait]
impl VpnPortalHost for WireGuardPortalHost {
    async fn start_listeners(&self) -> anyhow::Result<Vec<VpnPortalListener>> {
        let listener_addr = self
            .global_ctx
            .config
            .get_vpn_portal_config()
            .context("VPN portal config is not set")?
            .wireguard_listen;
        let mut listeners = vec![self.start_listener(listener_addr).await?];
        if let SocketAddr::V4(v4) = listener_addr
            && v4.ip().is_unspecified()
            && let Ok(listener) = self
                .start_listener(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    v4.port(),
                    0,
                    0,
                )))
                .await
        {
            listeners.push(listener);
        }
        Ok(listeners)
    }

    fn name(&self) -> String {
        "wireguard".to_owned()
    }

    fn render_client_config(&self, plan: &VpnPortalClientConfigPlan) -> String {
        let listener_addr = listener_endpoint(&plan.listener_url);
        format!(
            r#"
[Interface]
PrivateKey = {peer_secret_key}
Address = {address} # should assign an ip from this cidr manually

[Peer]
PublicKey = {my_public_key}
AllowedIPs = {allowed_ips}
Endpoint = {listener_addr} # should be the public ip(or domain) of the vpn server
PersistentKeepalive = 25
"#,
            peer_secret_key = BASE64_STANDARD.encode(self.wg_config.peer_secret_key()),
            my_public_key = BASE64_STANDARD.encode(self.wg_config.my_public_key()),
            listener_addr = listener_addr,
            allowed_ips = plan.allowed_ips.join(","),
            address = plan.client_cidr.first_address().to_string() + "/32",
        )
    }

    fn not_started_client_config(&self) -> String {
        "ERROR: Wireguard VPN Portal Not Started".to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::listener_endpoint;

    #[test]
    fn listener_endpoint_uses_the_active_listener_url() {
        assert_eq!(
            listener_endpoint(&"wg://192.0.2.10:51820".parse().unwrap()),
            "192.0.2.10:51820"
        );
        assert_eq!(
            listener_endpoint(&"wg://[2001:db8::10]:51820".parse().unwrap()),
            "[2001:db8::10]:51820"
        );
    }
}
