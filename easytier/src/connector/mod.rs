use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::{
    common::{dns::socket_addrs, error::Error, global_ctx::ArcGlobalCtx, idn},
    connector::dns_connector::DnsTunnelConnector,
    proto::common::PeerFeatureFlag,
    tunnel::{
        self, IpScheme, IpVersion, TunnelConnector, TunnelError, TunnelScheme,
        ring::RingTunnelConnector, tcp::TcpTunnelConnector, udp::UdpTunnelConnector,
    },
    utils::BoxExt,
};
use http_connector::HttpTunnelConnector;
use rand::seq::SliceRandom;

pub mod direct;
pub mod manual;
pub mod tcp_hole_punch;
pub mod udp_hole_punch;

pub mod dns_connector;
pub mod http_connector;
pub mod dynamic_connector_manager;

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
    global_ctx: &ArcGlobalCtx,
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

    let ips = global_ctx.get_ip_collector().collect_ip_addrs().await;
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
            let ipv6 = std::net::Ipv6Addr::from(*ipv6);
            if global_ctx.is_ip_easytier_managed_ipv6(&ipv6) {
                continue;
            }
            let socket_addr = SocketAddrV6::new(ipv6, 0, 0, 0).into();
            bind_addrs.push(socket_addr);
        }
        connector.set_bind_addrs(bind_addrs);
    }
    let _ = connector;
}

struct ResolvedConnectorAddr {
    addr: SocketAddr,
    ip_version: IpVersion,
}

fn connector_default_port(url: &url::Url) -> Option<u16> {
    url.try_into()
        .ok()
        .and_then(|s: TunnelScheme| s.try_into().ok())
        .map(IpScheme::default_port)
}

fn addr_matches_ip_version(addr: &SocketAddr, ip_version: IpVersion) -> bool {
    match ip_version {
        IpVersion::V4 => addr.is_ipv4(),
        IpVersion::V6 => addr.is_ipv6(),
        IpVersion::Both => true,
    }
}

fn infer_effective_ip_version(addrs: &[SocketAddr], requested_ip_version: IpVersion) -> IpVersion {
    match requested_ip_version {
        IpVersion::Both if addrs.iter().all(SocketAddr::is_ipv4) => IpVersion::V4,
        IpVersion::Both if addrs.iter().all(SocketAddr::is_ipv6) => IpVersion::V6,
        _ => requested_ip_version,
    }
}

async fn easytier_managed_ipv6_source_for_dst(
    global_ctx: &ArcGlobalCtx,
    dst_addr: SocketAddrV6,
) -> Result<Option<Ipv6Addr>, Error> {
    let socket = {
        let _g = global_ctx.net_ns.guard();
        tokio::net::UdpSocket::bind("[::]:0").await?
    };
    socket.connect(SocketAddr::V6(dst_addr)).await?;

    let IpAddr::V6(local_ip) = socket.local_addr()?.ip() else {
        return Ok(None);
    };

    Ok(global_ctx
        .is_ip_easytier_managed_ipv6(&local_ip)
        .then_some(local_ip))
}

async fn ipv6_connector_reject_reason(
    url: &url::Url,
    global_ctx: &ArcGlobalCtx,
    v6_addr: SocketAddrV6,
    skip_source_validation_errors: bool,
) -> Result<Option<String>, Error> {
    if global_ctx.is_ip_easytier_managed_ipv6(v6_addr.ip()) {
        return Ok(Some(format!(
            "{} resolves to EasyTier-managed IPv6 {}",
            url,
            v6_addr.ip()
        )));
    }

    match easytier_managed_ipv6_source_for_dst(global_ctx, v6_addr).await {
        Ok(Some(local_ip)) => Ok(Some(format!(
            "{} would use EasyTier-managed IPv6 {} as local source for {}",
            url, local_ip, v6_addr
        ))),
        Ok(None) => Ok(None),
        Err(err) if skip_source_validation_errors => Ok(Some(format!(
            "{} IPv6 candidate {} could not be validated: {}",
            url, v6_addr, err
        ))),
        Err(err) => Err(err),
    }
}

async fn resolve_connector_socket_addr(
    url: &url::Url,
    global_ctx: &ArcGlobalCtx,
    ip_version: IpVersion,
) -> Result<ResolvedConnectorAddr, Error> {
    let addrs = socket_addrs(url, || connector_default_port(url))
        .await
        .map_err(|e| {
            TunnelError::InvalidAddr(format!(
                "failed to resolve socket addr, url: {}, error: {}",
                url, e
            ))
        })?;

    let mut usable_addrs = Vec::new();
    let mut rejected_ipv6_reason = None;
    let skip_source_validation_errors = ip_version == IpVersion::Both;
    for addr in addrs
        .into_iter()
        .filter(|addr| addr_matches_ip_version(addr, ip_version))
    {
        if let SocketAddr::V6(v6_addr) = addr
            && let Some(reason) = ipv6_connector_reject_reason(
                url,
                global_ctx,
                v6_addr,
                skip_source_validation_errors,
            )
            .await?
        {
            rejected_ipv6_reason = Some(reason);
            continue;
        }

        usable_addrs.push(addr);
    }

    if usable_addrs.is_empty() {
        if let Some(reason) = rejected_ipv6_reason {
            return Err(Error::InvalidUrl(format!(
                "{}, refusing overlay-backed underlay connection",
                reason
            )));
        }

        return Err(Error::TunnelError(TunnelError::NoDnsRecordFound(
            ip_version,
        )));
    }

    let effective_ip_version = infer_effective_ip_version(&usable_addrs, ip_version);

    let addr = usable_addrs
        .choose(&mut rand::thread_rng())
        .copied()
        .ok_or_else(|| Error::TunnelError(TunnelError::NoDnsRecordFound(ip_version)))?;

    Ok(ResolvedConnectorAddr {
        addr,
        ip_version: effective_ip_version,
    })
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
    let mut effective_connector_ip_version = ip_version;
    let mut connector: Box<dyn TunnelConnector + 'static> = match scheme {
        TunnelScheme::Ip(scheme) => {
            let resolved_addr = resolve_connector_socket_addr(&url, global_ctx, ip_version).await?;
            effective_connector_ip_version = resolved_addr.ip_version;
            let mut connector: Box<dyn TunnelConnector> = match scheme {
                IpScheme::Tcp => TcpTunnelConnector::new(url).boxed(),
                IpScheme::Udp => UdpTunnelConnector::new(url).boxed(),
                #[cfg(feature = "quic")]
                IpScheme::Quic => {
                    tunnel::quic::QuicTunnelConnector::new(url, global_ctx.clone()).boxed()
                }
                #[cfg(feature = "wireguard")]
                IpScheme::Wg => {
                    use crate::tunnel::wireguard::{WgConfig, WgTunnelConnector};
                    let nid = global_ctx.get_network_identity();
                    let wg_config = WgConfig::new_from_network_identity(
                        &nid.network_name,
                        &nid.network_secret.unwrap_or_default(),
                    );
                    WgTunnelConnector::new(url, wg_config).boxed()
                }
                #[cfg(feature = "websocket")]
                IpScheme::Ws | IpScheme::Wss => {
                    tunnel::websocket::WsTunnelConnector::new(url).boxed()
                }
                #[cfg(feature = "faketcp")]
                IpScheme::FakeTcp => tunnel::fake_tcp::FakeTcpTunnelConnector::new(url).boxed(),
            };
            connector.set_resolved_addr(resolved_addr.addr);
            if global_ctx.config.get_flags().bind_device {
                set_bind_addr_for_peer_connector(
                    &mut connector,
                    resolved_addr.addr.is_ipv4(),
                    global_ctx,
                )
                .await;
            }
            connector
        }
        #[cfg(unix)]
        TunnelScheme::Unix => tunnel::unix::UnixSocketTunnelConnector::new(url).boxed(),
        TunnelScheme::Http | TunnelScheme::Https => {
            HttpTunnelConnector::new(url, global_ctx.clone()).boxed()
        }
        TunnelScheme::Ring => RingTunnelConnector::new(url).boxed(),
        TunnelScheme::Txt | TunnelScheme::Srv => {
            if url.host_str().is_none() {
                return Err(Error::InvalidUrl(format!(
                    "host should not be empty in txt or srv url: {}",
                    url
                )));
            }
            DnsTunnelConnector::new(url, global_ctx.clone()).boxed()
        }
    };
    connector.set_ip_version(effective_connector_ip_version);

    Ok(connector)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx, proto::common::PeerFeatureFlag,
        tunnel::IpVersion,
    };

    use super::{
        create_connector_by_url, should_background_p2p_with_peer, should_try_p2p_with_peer,
    };

    #[tokio::test]
    async fn connector_rejects_easytier_managed_ipv6_destination() {
        let global_ctx = get_mock_global_ctx();
        let public_route: cidr::Ipv6Inet = "2001:db8::2/128".parse().unwrap();
        global_ctx.set_public_ipv6_routes(BTreeSet::from([public_route]));

        let ret =
            create_connector_by_url("tcp://[2001:db8::2]:11010", &global_ctx, IpVersion::V6).await;

        assert!(matches!(
            ret,
            Err(crate::common::error::Error::InvalidUrl(_))
        ));
    }

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
