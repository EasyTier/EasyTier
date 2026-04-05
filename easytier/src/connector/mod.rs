use std::{
    net::{SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use crate::tunnel::scheme::{DiscoveryProto, IpProto, TunnelScheme};
use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx, idn, network::IPCollector},
    connector::dns_connector::DnsTunnelConnector,
    proto::common::PeerFeatureFlag,
    tunnel::{
        self, FromUrl, IpVersion, TunnelConnector, TunnelError, ring::RingTunnelConnector,
        tcp::TcpTunnelConnector, udp::UdpTunnelConnector,
    },
    utils::BoxExt,
};
use http_connector::HttpTunnelConnector;

pub mod direct;
pub mod manual;
pub mod tcp_hole_punch;
pub mod udp_hole_punch;

pub mod dns_connector;
pub mod http_connector;

pub(crate) fn should_try_p2p_with_peer(
    feature_flag: Option<&PeerFeatureFlag>,
    allow_public_server: bool,
    local_disable_p2p: bool,
    local_need_p2p: bool,
) -> bool {
    feature_flag
        .map(|flag| {
            (allow_public_server || !flag.is_public_server)
                && (!local_disable_p2p || flag.need_p2p)
                && (!flag.disable_p2p || local_need_p2p)
        })
        .unwrap_or(!local_disable_p2p)
}

pub(crate) fn should_background_p2p_with_peer(
    feature_flag: Option<&PeerFeatureFlag>,
    allow_public_server: bool,
    lazy_p2p: bool,
    local_disable_p2p: bool,
    local_need_p2p: bool,
) -> bool {
    should_try_p2p_with_peer(
        feature_flag,
        allow_public_server,
        local_disable_p2p,
        local_need_p2p,
    ) && (!lazy_p2p || feature_flag.map(|flag| flag.need_p2p).unwrap_or(false))
}

async fn set_bind_addr_for_peer_connector(
    connector: &mut (impl TunnelConnector + ?Sized),
    is_ipv4: bool,
    ip_collector: &Arc<IPCollector>,
) {
    if cfg!(any(
        target_os = "android",
        any(
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne")
        ),
        target_env = "ohos"
    )) {
        return;
    }

    let ips = ip_collector.collect_ip_addrs().await;
    if is_ipv4 {
        let mut bind_addrs = vec![];
        for ipv4 in ips.interface_ipv4s {
            let socket_addr = SocketAddrV4::new(ipv4.into(), 0).into();
            bind_addrs.push(socket_addr);
        }
        connector.set_bind_addrs(bind_addrs);
    } else {
        let mut bind_addrs = vec![];
        for ipv6 in ips.interface_ipv6s.iter().chain(ips.public_ipv6.iter()) {
            let socket_addr = SocketAddrV6::new(std::net::Ipv6Addr::from(*ipv6), 0, 0, 0).into();
            bind_addrs.push(socket_addr);
        }
        connector.set_bind_addrs(bind_addrs);
    }
    let _ = connector;
}

pub async fn create_connector_by_url(
    url: &str,
    global_ctx: &ArcGlobalCtx,
    ip_version: IpVersion,
) -> Result<Box<dyn TunnelConnector + 'static>, Error> {
    let url = url::Url::parse(url).map_err(|_| Error::InvalidUrl(url.to_owned()))?;
    let url = idn::convert_idn_to_ascii(url)?;
    let scheme = (&url)
        .try_into()
        .map_err(|_| TunnelError::InvalidProtocol(url.scheme().to_owned()))?;
    let mut connector: Box<dyn TunnelConnector + 'static> = match scheme {
        TunnelScheme::Ring => RingTunnelConnector::new(url).boxed(),
        #[cfg(unix)]
        TunnelScheme::Unix => tunnel::unix::UnixSocketTunnelConnector::new(url).boxed(),
        TunnelScheme::Ip(scheme) => {
            let dst_addr = SocketAddr::from_url(url.clone(), ip_version).await?;
            let mut connector: Box<dyn TunnelConnector> = match scheme.proto {
                IpProto::Tcp => TcpTunnelConnector::new(url).boxed(),
                IpProto::Udp => UdpTunnelConnector::new(url).boxed(),
                #[cfg(feature = "quic")]
                IpProto::Quic => {
                    tunnel::quic::QuicTunnelConnector::new(url, global_ctx.clone()).boxed()
                }
                #[cfg(feature = "wireguard")]
                IpProto::Wg => {
                    use crate::tunnel::wireguard::{WgConfig, WgTunnelConnector};
                    let nid = global_ctx.get_network_identity();
                    let wg_config = WgConfig::new_from_network_identity(
                        &nid.network_name,
                        &nid.network_secret.unwrap_or_default(),
                    );
                    WgTunnelConnector::new(url, wg_config).boxed()
                }
                #[cfg(feature = "websocket")]
                IpProto::Ws | IpProto::Wss => {
                    tunnel::websocket::WsTunnelConnector::new(url).boxed()
                }
                #[cfg(feature = "faketcp")]
                IpProto::FakeTcp => tunnel::fake_tcp::FakeTcpTunnelConnector::new(url).boxed(),
            };
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    dst_addr.is_ipv4(),
                    &global_ctx.get_ip_collector(),
                )
                .await;
            }
            connector
        }
        TunnelScheme::Discovery(scheme) => match scheme.proto {
            DiscoveryProto::Http | DiscoveryProto::Https => {
                HttpTunnelConnector::new(url, global_ctx.clone()).boxed()
            }
            DiscoveryProto::Txt | DiscoveryProto::Srv => {
                if url.host_str().is_none() {
                    return Err(Error::InvalidUrl(format!(
                        "host should not be empty in txt or srv url: {}",
                        url
                    )));
                }
                DnsTunnelConnector::new(url, global_ctx.clone()).boxed()
            }
        },
    };
    connector.set_ip_version(ip_version);

    Ok(connector)
}

#[cfg(test)]
mod tests {
    use crate::proto::common::PeerFeatureFlag;

    use super::{should_background_p2p_with_peer, should_try_p2p_with_peer};

    #[test]
    fn lazy_background_p2p_requires_need_p2p() {
        let no_need_p2p = PeerFeatureFlag {
            need_p2p: false,
            ..Default::default()
        };
        let need_p2p = PeerFeatureFlag {
            need_p2p: true,
            ..Default::default()
        };

        assert!(should_background_p2p_with_peer(
            Some(&no_need_p2p),
            false,
            false,
            false,
            false
        ));
        assert!(!should_background_p2p_with_peer(
            Some(&no_need_p2p),
            false,
            true,
            false,
            false
        ));
        assert!(should_background_p2p_with_peer(
            Some(&need_p2p),
            false,
            true,
            false,
            false
        ));
    }

    #[test]
    fn p2p_policy_respects_public_server_setting() {
        let public_server = PeerFeatureFlag {
            is_public_server: true,
            ..Default::default()
        };

        assert!(!should_try_p2p_with_peer(
            Some(&public_server),
            false,
            false,
            false
        ));
        assert!(should_try_p2p_with_peer(
            Some(&public_server),
            true,
            false,
            false
        ));
        assert!(!should_background_p2p_with_peer(
            Some(&public_server),
            false,
            false,
            false,
            false
        ));
        assert!(should_background_p2p_with_peer(
            Some(&public_server),
            true,
            false,
            false,
            false
        ));
    }

    #[test]
    fn disable_p2p_only_allows_need_p2p_exceptions() {
        let normal_peer = PeerFeatureFlag::default();
        let need_peer = PeerFeatureFlag {
            need_p2p: true,
            ..Default::default()
        };
        let disable_peer = PeerFeatureFlag {
            disable_p2p: true,
            ..Default::default()
        };
        let disable_need_peer = PeerFeatureFlag {
            disable_p2p: true,
            need_p2p: true,
            ..Default::default()
        };

        assert!(should_try_p2p_with_peer(
            Some(&normal_peer),
            false,
            false,
            false
        ));
        assert!(should_try_p2p_with_peer(None, false, false, false));
        assert!(!should_try_p2p_with_peer(None, false, true, false));
        assert!(!should_try_p2p_with_peer(
            Some(&normal_peer),
            false,
            true,
            false
        ));
        assert!(should_try_p2p_with_peer(
            Some(&need_peer),
            false,
            true,
            false
        ));
        assert!(!should_try_p2p_with_peer(
            Some(&disable_peer),
            false,
            false,
            false
        ));
        assert!(should_try_p2p_with_peer(
            Some(&disable_peer),
            false,
            false,
            true
        ));
        assert!(should_try_p2p_with_peer(
            Some(&disable_need_peer),
            false,
            true,
            true
        ));
        assert!(!should_try_p2p_with_peer(
            Some(&disable_need_peer),
            false,
            true,
            false
        ));
    }
}
