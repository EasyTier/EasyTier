use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::{Context, anyhow, bail};
use async_trait::async_trait;
use easytier_core::hole_punch::udp::{
    ActiveUdpPortMapping as CoreActiveUdpPortMapping, UdpPortMappingAttemptError,
    UdpPortMappingBackend, UdpPortMappingLifecycle,
};
use igd_next::{
    AddAnyPortError, PortMappingProtocol, SearchOptions,
    aio::{
        Gateway,
        tokio::{Tokio, search_gateway},
    },
};
use natpmp::{
    Protocol as NatPmpProtocol, Response as NatPmpResponse, new_tokio_natpmp, new_tokio_natpmp_with,
};

use super::netns::NetNS;

const UPNP_SEARCH_TIMEOUT: Duration = Duration::from_secs(1);
const UPNP_SEARCH_RESPONSE_TIMEOUT: Duration = Duration::from_millis(300);
const NAT_PMP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const UPNP_LEASE_DURATION_SECS: u32 = 300;
const UPNP_DESCRIPTION: &str = "EasyTier udp hole punch";

type TokioGateway = Gateway<Tokio>;

enum PortMappingBackend {
    NatPmp { gateway: Ipv4Addr },
    Igd { gateway: TokioGateway },
}

struct ActiveUdpPortMapping {
    backend: PortMappingBackend,
    local_listener: url::Url,
    local_addr: SocketAddr,
    gateway_external_port: u16,
}

impl fmt::Debug for ActiveUdpPortMapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ActiveUdpPortMapping")
            .field("backend", &self.core_backend())
            .field("local_listener", &self.local_listener)
            .field("local_addr", &self.local_addr)
            .field("gateway_external_port", &self.gateway_external_port)
            .finish()
    }
}

impl ActiveUdpPortMapping {
    fn core_backend(&self) -> UdpPortMappingBackend {
        match self.backend {
            PortMappingBackend::Igd { .. } => UdpPortMappingBackend::Igd,
            PortMappingBackend::NatPmp { .. } => UdpPortMappingBackend::NatPmp,
        }
    }

    async fn discover_nat_pmp_gateway(
        local_listener: &url::Url,
    ) -> anyhow::Result<(Ipv4Addr, SocketAddr)> {
        let client = new_tokio_natpmp().await.context("create nat-pmp client")?;
        let gateway = *client.gateway();
        let gateway_addr = SocketAddr::V4(SocketAddrV4::new(gateway, natpmp::NATPMP_PORT));
        let local_addr = resolve_internal_addr(gateway_addr, local_listener).await?;
        Ok((gateway, local_addr))
    }

    async fn establish_via_nat_pmp(
        local_listener: &url::Url,
        gateway: Ipv4Addr,
        local_addr: SocketAddr,
    ) -> anyhow::Result<Self> {
        let gateway_external_port =
            add_udp_mapping_port_nat_pmp(gateway, local_addr, local_listener)
                .await
                .with_context(|| {
                    format!("map udp socket for {local_listener} via nat-pmp gateway {gateway}")
                })?;

        Ok(Self {
            backend: PortMappingBackend::NatPmp { gateway },
            local_listener: local_listener.clone(),
            local_addr,
            gateway_external_port,
        })
    }

    async fn discover_igd_gateway(
        net_ns: &NetNS,
        local_listener: &url::Url,
    ) -> anyhow::Result<(TokioGateway, SocketAddr)> {
        let _g = net_ns.guard();
        let gateway = search_gateway(SearchOptions {
            timeout: Some(UPNP_SEARCH_TIMEOUT),
            single_search_timeout: Some(UPNP_SEARCH_RESPONSE_TIMEOUT),
            ..Default::default()
        })
        .await
        .with_context(|| format!("search igd gateway for {local_listener}"))?;
        let local_addr = resolve_internal_addr(gateway.addr, local_listener).await?;

        Ok((gateway, local_addr))
    }

    async fn establish_via_igd(
        local_listener: &url::Url,
        gateway: TokioGateway,
        local_addr: SocketAddr,
    ) -> anyhow::Result<Self> {
        let gateway_external_port = add_udp_mapping_port_igd(&gateway, local_addr, local_listener)
            .await
            .with_context(|| {
                format!(
                    "map udp socket for {local_listener} via gateway {}",
                    gateway.addr
                )
            })?;

        Ok(Self {
            backend: PortMappingBackend::Igd { gateway },
            local_listener: local_listener.clone(),
            local_addr,
            gateway_external_port,
        })
    }

    async fn renew(&self) -> anyhow::Result<()> {
        match &self.backend {
            PortMappingBackend::NatPmp { gateway } => {
                renew_udp_mapping_nat_pmp(
                    *gateway,
                    self.local_addr,
                    self.gateway_external_port,
                    &self.local_listener,
                )
                .await
            }
            PortMappingBackend::Igd { gateway } => {
                renew_udp_mapping_igd(
                    gateway,
                    self.local_addr,
                    self.gateway_external_port,
                    &self.local_listener,
                )
                .await
            }
        }
    }

    async fn remove(&self) -> anyhow::Result<()> {
        match &self.backend {
            PortMappingBackend::NatPmp { gateway } => {
                remove_udp_mapping_nat_pmp(
                    *gateway,
                    self.local_addr,
                    self.gateway_external_port,
                    &self.local_listener,
                )
                .await
            }
            PortMappingBackend::Igd { gateway } => {
                remove_udp_mapping_igd(gateway, self.gateway_external_port, &self.local_listener)
                    .await
            }
        }
    }
}

#[async_trait]
impl CoreActiveUdpPortMapping for ActiveUdpPortMapping {
    fn backend(&self) -> UdpPortMappingBackend {
        self.core_backend()
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn gateway_external_port(&self) -> u16 {
        self.gateway_external_port
    }

    async fn renew(&self) -> anyhow::Result<()> {
        ActiveUdpPortMapping::renew(self).await
    }

    async fn remove(&self) -> anyhow::Result<()> {
        ActiveUdpPortMapping::remove(self).await
    }
}

pub(crate) async fn establish_udp_port_mapping(
    net_ns: NetNS,
    backend: UdpPortMappingBackend,
    local_listener: url::Url,
) -> Result<Box<dyn CoreActiveUdpPortMapping>, UdpPortMappingAttemptError> {
    let mapping = match backend {
        UdpPortMappingBackend::Igd => {
            let (gateway, local_addr) =
                discover_igd_gateway_in_netns(net_ns.clone(), local_listener.clone())
                    .await
                    .map_err(UdpPortMappingAttemptError::discovery)?;
            establish_igd_mapping_in_netns(net_ns, local_listener, gateway, local_addr)
                .await
                .map_err(UdpPortMappingAttemptError::establishment)?
        }
        UdpPortMappingBackend::NatPmp => {
            let (gateway, local_addr) =
                discover_nat_pmp_gateway_in_netns(net_ns.clone(), local_listener.clone())
                    .await
                    .map_err(UdpPortMappingAttemptError::discovery)?;
            establish_nat_pmp_mapping_in_netns(net_ns, local_listener, gateway, local_addr)
                .await
                .map_err(UdpPortMappingAttemptError::establishment)?
        }
    };
    Ok(Box::new(mapping))
}

pub(crate) fn spawn_udp_port_mapping_lifecycle(
    net_ns: NetNS,
    local_listener: url::Url,
    lifecycle: UdpPortMappingLifecycle,
) {
    if should_run_port_mapping_in_dedicated_thread(&net_ns) {
        tokio::task::spawn_blocking(move || {
            let _g = net_ns.guard();
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime.block_on(lifecycle),
                Err(err) => tracing::error!(
                    ?err,
                    %local_listener,
                    "failed to build runtime for udp port mapping renew task"
                ),
            }
        });
    } else {
        tokio::spawn(lifecycle);
    }
}

async fn discover_igd_gateway_in_netns(
    net_ns: NetNS,
    local_listener: url::Url,
) -> anyhow::Result<(TokioGateway, SocketAddr)> {
    if !should_run_port_mapping_in_dedicated_thread(&net_ns) {
        return ActiveUdpPortMapping::discover_igd_gateway(&net_ns, &local_listener).await;
    }

    tokio::task::spawn_blocking(move || {
        let _g = net_ns.guard();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build runtime for igd gateway discovery")?
            .block_on(ActiveUdpPortMapping::discover_igd_gateway(
                &net_ns,
                &local_listener,
            ))
    })
    .await
    .context("join igd gateway discovery task")?
}

async fn establish_igd_mapping_in_netns(
    net_ns: NetNS,
    local_listener: url::Url,
    gateway: TokioGateway,
    local_addr: SocketAddr,
) -> anyhow::Result<ActiveUdpPortMapping> {
    if !should_run_port_mapping_in_dedicated_thread(&net_ns) {
        return ActiveUdpPortMapping::establish_via_igd(&local_listener, gateway, local_addr).await;
    }

    tokio::task::spawn_blocking(move || {
        let _g = net_ns.guard();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build runtime for igd mapping establishment")?
            .block_on(ActiveUdpPortMapping::establish_via_igd(
                &local_listener,
                gateway,
                local_addr,
            ))
    })
    .await
    .context("join igd mapping establishment task")?
}

async fn discover_nat_pmp_gateway_in_netns(
    net_ns: NetNS,
    local_listener: url::Url,
) -> anyhow::Result<(Ipv4Addr, SocketAddr)> {
    if !should_run_port_mapping_in_dedicated_thread(&net_ns) {
        return ActiveUdpPortMapping::discover_nat_pmp_gateway(&local_listener).await;
    }

    tokio::task::spawn_blocking(move || {
        let _g = net_ns.guard();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build runtime for nat-pmp gateway discovery")?
            .block_on(ActiveUdpPortMapping::discover_nat_pmp_gateway(
                &local_listener,
            ))
    })
    .await
    .context("join nat-pmp gateway discovery task")?
}

async fn establish_nat_pmp_mapping_in_netns(
    net_ns: NetNS,
    local_listener: url::Url,
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
) -> anyhow::Result<ActiveUdpPortMapping> {
    if !should_run_port_mapping_in_dedicated_thread(&net_ns) {
        return ActiveUdpPortMapping::establish_via_nat_pmp(&local_listener, gateway, local_addr)
            .await;
    }

    tokio::task::spawn_blocking(move || {
        let _g = net_ns.guard();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build runtime for nat-pmp mapping establishment")?
            .block_on(ActiveUdpPortMapping::establish_via_nat_pmp(
                &local_listener,
                gateway,
                local_addr,
            ))
    })
    .await
    .context("join nat-pmp mapping establishment task")?
}

fn should_run_port_mapping_in_dedicated_thread(net_ns: &NetNS) -> bool {
    net_ns.name().is_some()
}

async fn add_udp_mapping_port_igd(
    gateway: &TokioGateway,
    local_addr: SocketAddr,
    local_listener: &url::Url,
) -> anyhow::Result<u16> {
    match gateway
        .add_any_port(
            PortMappingProtocol::UDP,
            local_addr,
            UPNP_LEASE_DURATION_SECS,
            UPNP_DESCRIPTION,
        )
        .await
    {
        Ok(external_port) => Ok(external_port),
        Err(AddAnyPortError::RequestError(err)) => {
            tracing::debug!(
                ?err,
                %local_listener,
                gateway = %gateway.addr,
                %local_addr,
                "igd any-port udp mapping failed, retry with same-port mapping"
            );

            gateway
                .add_port(
                    PortMappingProtocol::UDP,
                    local_addr.port(),
                    local_addr,
                    UPNP_LEASE_DURATION_SECS,
                    UPNP_DESCRIPTION,
                )
                .await
                .map(|_| local_addr.port())
                .map_err(|same_port_err| {
                    anyhow!(
                        "igd udp mapping failed for {local_listener}: any-port error: {err}; same-port error: {same_port_err}"
                    )
                })
        }
        Err(err) => Err(err.into()),
    }
}

async fn add_udp_mapping_port_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    local_listener: &url::Url,
) -> anyhow::Result<u16> {
    match request_nat_pmp_mapping(gateway, local_addr.port(), 0, UPNP_LEASE_DURATION_SECS).await {
        Ok(external_port) => Ok(external_port),
        Err(any_port_err) => {
            tracing::debug!(
                ?any_port_err,
                %local_listener,
                gateway = %gateway,
                %local_addr,
                "nat-pmp any-port udp mapping failed, retry with same-port mapping"
            );

            request_nat_pmp_mapping(
                gateway,
                local_addr.port(),
                local_addr.port(),
                UPNP_LEASE_DURATION_SECS,
            )
            .await
            .map_err(|same_port_err| {
                anyhow!(
                    "nat-pmp udp mapping failed for {local_listener}: any-port error: {any_port_err}; same-port error: {same_port_err}"
                )
            })
        }
    }
}

async fn request_nat_pmp_mapping(
    gateway: Ipv4Addr,
    private_port: u16,
    public_port: u16,
    lifetime_secs: u32,
) -> anyhow::Result<u16> {
    let client = new_tokio_natpmp_with(gateway)
        .await
        .with_context(|| format!("create nat-pmp client for gateway {gateway}"))?;
    client
        .send_port_mapping_request(
            NatPmpProtocol::UDP,
            private_port,
            public_port,
            lifetime_secs,
        )
        .await
        .with_context(|| {
            format!(
                "send nat-pmp udp mapping request private_port={private_port} public_port={public_port} gateway={gateway}"
            )
        })?;

    let response = tokio::time::timeout(NAT_PMP_RESPONSE_TIMEOUT, client.read_response_or_retry())
        .await
        .with_context(|| {
            format!(
                "wait nat-pmp udp mapping response private_port={private_port} gateway={gateway}"
            )
        })?
        .map_err(anyhow::Error::from)
        .with_context(|| {
            format!(
                "read nat-pmp udp mapping response private_port={private_port} gateway={gateway}"
            )
        })?;

    match response {
        NatPmpResponse::UDP(mapping) | NatPmpResponse::TCP(mapping) => Ok(mapping.public_port()),
        NatPmpResponse::Gateway(_) => {
            bail!("unexpected nat-pmp gateway response for udp mapping request")
        }
    }
}

async fn renew_udp_mapping_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
) -> anyhow::Result<()> {
    request_nat_pmp_mapping(
        gateway,
        local_addr.port(),
        external_port,
        UPNP_LEASE_DURATION_SECS,
    )
    .await
    .map(|_| ())
    .with_context(|| format!("renew udp port mapping {local_listener}"))
}

async fn remove_udp_mapping_nat_pmp(
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
) -> anyhow::Result<()> {
    request_nat_pmp_mapping(gateway, local_addr.port(), external_port, 0)
        .await
        .map(|_| ())
        .with_context(|| format!("remove udp port mapping {local_listener}"))
}

fn listener_ipv4_host(local_listener: &url::Url) -> Option<Ipv4Addr> {
    local_listener.host_str()?.parse().ok()
}

async fn resolve_internal_addr(
    gateway_addr: SocketAddr,
    local_listener: &url::Url,
) -> anyhow::Result<SocketAddr> {
    let port = local_listener
        .port()
        .ok_or_else(|| anyhow!("listener port is missing"))?;
    let host =
        listener_ipv4_host(local_listener).ok_or_else(|| anyhow!("listener must be ipv4"))?;

    let ip = if host.is_unspecified() {
        let udp = std::net::UdpSocket::bind("0.0.0.0:0")
            .context("bind probe socket for gateway route")?;
        udp.connect(gateway_addr)
            .with_context(|| format!("connect probe socket to gateway {gateway_addr}"))?;
        let SocketAddr::V4(local_addr) = udp.local_addr().context("get probe socket local addr")?
        else {
            bail!("gateway route selected a non-ipv4 local address");
        };
        *local_addr.ip()
    } else {
        host
    };

    Ok(SocketAddr::new(ip.into(), port))
}

async fn renew_udp_mapping_igd(
    gateway: &TokioGateway,
    local_addr: SocketAddr,
    external_port: u16,
    local_listener: &url::Url,
) -> anyhow::Result<()> {
    gateway
        .add_port(
            PortMappingProtocol::UDP,
            external_port,
            local_addr,
            UPNP_LEASE_DURATION_SECS,
            UPNP_DESCRIPTION,
        )
        .await
        .with_context(|| format!("renew udp port mapping {local_listener}"))
}

async fn remove_udp_mapping_igd(
    gateway: &TokioGateway,
    external_port: u16,
    local_listener: &url::Url,
) -> anyhow::Result<()> {
    gateway
        .remove_port(PortMappingProtocol::UDP, external_port)
        .await
        .with_context(|| format!("remove udp port mapping {local_listener}"))
}
