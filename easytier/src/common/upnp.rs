use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Context, anyhow, bail};
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
use tokio::{net::UdpSocket, sync::oneshot};

use super::{
    global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
    stun::StunInfoCollectorTrait as _,
};
use crate::tunnel::build_url_from_socket_addr;

const UPNP_SEARCH_TIMEOUT: Duration = Duration::from_secs(1);
const UPNP_SEARCH_RESPONSE_TIMEOUT: Duration = Duration::from_millis(300);
const NAT_PMP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(1);
const UPNP_LEASE_DURATION_SECS: u32 = 300;
const UPNP_RENEW_INTERVAL: Duration = Duration::from_secs(240);
const UPNP_DESCRIPTION: &str = "EasyTier udp hole punch";
const PORT_MAPPING_BACKEND_NAT_PMP: &str = "nat-pmp";
const PORT_MAPPING_BACKEND_IGD: &str = "igd";

type TokioGateway = Gateway<Tokio>;

#[cfg(test)]
static UDP_PORT_MAPPING_ATTEMPTS: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn reset_udp_port_mapping_attempts_for_test() {
    UDP_PORT_MAPPING_ATTEMPTS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
pub(crate) fn udp_port_mapping_attempts_for_test() -> usize {
    UDP_PORT_MAPPING_ATTEMPTS.load(Ordering::Relaxed)
}

enum PortMappingBackend {
    NatPmp { gateway: Ipv4Addr },
    Igd { gateway: TokioGateway },
}

impl PortMappingBackend {
    fn name(&self) -> &'static str {
        match self {
            Self::NatPmp { .. } => PORT_MAPPING_BACKEND_NAT_PMP,
            Self::Igd { .. } => PORT_MAPPING_BACKEND_IGD,
        }
    }
}

struct ActiveUdpPortMapping {
    backend: PortMappingBackend,
    local_listener: url::Url,
    local_addr: SocketAddr,
    gateway_external_port: u16,
}

impl ActiveUdpPortMapping {
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
        global_ctx: &ArcGlobalCtx,
        local_listener: &url::Url,
    ) -> anyhow::Result<(TokioGateway, SocketAddr)> {
        let _g = global_ctx.net_ns.guard();
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

    fn backend_name(&self) -> &'static str {
        self.backend.name()
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

pub struct UdpPortMappingLease {
    backend: &'static str,
    gateway_external_port: u16,
    stop_tx: Option<oneshot::Sender<()>>,
}

impl UdpPortMappingLease {
    pub fn backend(&self) -> &'static str {
        self.backend
    }

    pub fn gateway_external_port(&self) -> u16 {
        self.gateway_external_port
    }
}

impl fmt::Debug for UdpPortMappingLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpPortMappingLease")
            .field("backend", &self.backend)
            .field("gateway_external_port", &self.gateway_external_port)
            .finish()
    }
}

impl Drop for UdpPortMappingLease {
    fn drop(&mut self) {
        if let Some(stop_tx) = self.stop_tx.take() {
            let _ = stop_tx.send(());
        }
    }
}

async fn try_get_public_addr_via_upnp(
    global_ctx: &ArcGlobalCtx,
    local_listener: &url::Url,
    mapping: &Option<UdpPortMappingLease>,
) -> anyhow::Result<SocketAddr> {
    let (gateway, _local_addr) = ActiveUdpPortMapping::discover_igd_gateway(global_ctx, local_listener).await?;

    let public_ip = gateway.get_external_ip().await
        .context("failed to get external ip from gateway")?;

	let lease_ref = mapping.as_ref();

	let public_addr = if let Some(lease) = lease_ref {
		SocketAddr::new(public_ip, lease.gateway_external_port())
    } else {
		bail!("port mapping lease is required to get external port")
	};
	Ok(public_addr)
}

pub async fn resolve_udp_public_addr(
    global_ctx: ArcGlobalCtx,
    local_listener: &url::Url,
    socket: Arc<UdpSocket>,
) -> anyhow::Result<(SocketAddr, Option<UdpPortMappingLease>)> {
    let port_mapping = match try_start_udp_port_mapping(&global_ctx, local_listener).await {
        Ok(mapping) => mapping,
        Err(err) => {
            tracing::warn!(
                ?err,
                %local_listener,
                "failed to establish udp port mapping, fallback to stun-only public addr resolution"
            );
            None
        }
    };

    let mut mapped_addr = global_ctx
        .get_stun_info_collector()
        .get_udp_port_mapping_with_socket(socket)
        .await
        .map_err(anyhow::Error::from)
        .with_context(|| format!("resolve udp public addr for {local_listener}"))?;

    match try_get_public_addr_via_upnp(&global_ctx, local_listener, &port_mapping).await {
        Ok(public_addr) => {
            tracing::info!(%local_listener, %public_addr, "got public addr via upnp/igd");
            mapped_addr = public_addr;
        }
        Err(err) => {
            tracing::debug!(?err, "upnp/igd failed, fallback to stun");
        }
    }

    if let Some(port_mapping) = port_mapping.as_ref() {
        let mapped_listener = build_url_from_socket_addr(&mapped_addr.to_string(), "udp");
        global_ctx.issue_event(GlobalCtxEvent::ListenerPortMappingEstablished {
            local_listener: local_listener.clone(),
            mapped_listener,
            backend: port_mapping.backend().to_string(),
        });
        tracing::info!(
            %local_listener,
            backend = port_mapping.backend(),
            gateway_external_port = port_mapping.gateway_external_port(),
            stun_mapped_addr = %mapped_addr,
            "udp public addr resolved after port mapping"
        );
    } else {
        tracing::debug!(
            %local_listener,
            stun_mapped_addr = %mapped_addr,
            "udp public addr resolved without port mapping"
        );
    }

    Ok((mapped_addr, port_mapping))
}

async fn try_start_udp_port_mapping(
    global_ctx: &ArcGlobalCtx,
    local_listener: &url::Url,
) -> anyhow::Result<Option<UdpPortMappingLease>> {
    if global_ctx.get_flags().disable_upnp || !should_map_udp_listener(local_listener) {
        return Ok(None);
    }

    #[cfg(test)]
    UDP_PORT_MAPPING_ATTEMPTS.fetch_add(1, Ordering::Relaxed);

    let mapping = discover_udp_port_mapping(global_ctx.clone(), local_listener.clone()).await?;
    tracing::info!(
        %local_listener,
        backend = mapping.backend_name(),
        local_addr = %mapping.local_addr,
        gateway_external_port = mapping.gateway_external_port,
        "udp port mapping established"
    );

    let backend = mapping.backend_name();
    let gateway_external_port = mapping.gateway_external_port;
    let runtime_global_ctx = global_ctx.clone();
    let runtime_local_listener = local_listener.clone();
    let (stop_tx, stop_rx) = oneshot::channel();
    if should_run_port_mapping_in_dedicated_thread(&runtime_global_ctx) {
        tokio::task::spawn_blocking(move || {
            let _g = runtime_global_ctx.net_ns.guard();
            match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => {
                    runtime.block_on(run_udp_port_mapping_task(
                        runtime_local_listener,
                        mapping,
                        stop_rx,
                    ));
                }
                Err(err) => {
                    tracing::error!(
                        ?err,
                        %runtime_local_listener,
                        "failed to build runtime for udp port mapping renew task"
                    );
                }
            }
        });
    } else {
        tokio::spawn(run_udp_port_mapping_task(
            runtime_local_listener,
            mapping,
            stop_rx,
        ));
    }

    Ok(Some(UdpPortMappingLease {
        backend,
        gateway_external_port,
        stop_tx: Some(stop_tx),
    }))
}

async fn discover_udp_port_mapping(
    global_ctx: ArcGlobalCtx,
    local_listener: url::Url,
) -> anyhow::Result<ActiveUdpPortMapping> {
    match discover_igd_gateway_in_netns(global_ctx.clone(), local_listener.clone()).await {
        Ok((gateway, local_addr)) => match establish_igd_mapping_in_netns(
            global_ctx.clone(),
            local_listener.clone(),
            gateway,
            local_addr,
        )
        .await
        {
            Ok(mapping) => Ok(mapping),
            Err(igd_err) => {
                tracing::debug!(
                    ?igd_err,
                    %local_listener,
                    "igd udp port mapping failed, retry with nat-pmp"
                );
                match discover_nat_pmp_gateway_in_netns(global_ctx.clone(), local_listener.clone())
                    .await
                {
                    Ok((gateway, local_addr)) => establish_nat_pmp_mapping_in_netns(
                        global_ctx,
                        local_listener.clone(),
                        gateway,
                        local_addr,
                    )
                    .await
                    .map_err(|nat_pmp_err| {
                        anyhow!(
                            "udp port mapping failed for {local_listener}: igd error: {igd_err}; nat-pmp error: {nat_pmp_err}"
                        )
                    }),
                    Err(nat_pmp_err) => Err(anyhow!(
                        "udp port mapping failed for {local_listener}: igd error: {igd_err}; nat-pmp discovery error: {nat_pmp_err}"
                    )),
                }
            }
        },
        Err(igd_err) => {
            tracing::debug!(
                ?igd_err,
                %local_listener,
                "igd gateway discovery failed, retry with nat-pmp"
            );
            match discover_nat_pmp_gateway_in_netns(global_ctx.clone(), local_listener.clone()).await
            {
                Ok((gateway, local_addr)) => establish_nat_pmp_mapping_in_netns(
                    global_ctx,
                    local_listener.clone(),
                    gateway,
                    local_addr,
                )
                .await
                .map_err(|nat_pmp_err| {
                    anyhow!(
                        "udp port mapping failed for {local_listener}: igd discovery error: {igd_err}; nat-pmp error: {nat_pmp_err}"
                    )
                }),
                Err(nat_pmp_err) => Err(anyhow!(
                    "udp port mapping failed for {local_listener}: igd discovery error: {igd_err}; nat-pmp discovery error: {nat_pmp_err}"
                )),
            }
        }
    }
}

async fn discover_igd_gateway_in_netns(
    global_ctx: ArcGlobalCtx,
    local_listener: url::Url,
) -> anyhow::Result<(TokioGateway, SocketAddr)> {
    if !should_run_port_mapping_in_dedicated_thread(&global_ctx) {
        return ActiveUdpPortMapping::discover_igd_gateway(&global_ctx, &local_listener).await;
    }

    tokio::task::spawn_blocking(move || {
        let _g = global_ctx.net_ns.guard();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("build runtime for igd gateway discovery")?
            .block_on(ActiveUdpPortMapping::discover_igd_gateway(
                &global_ctx,
                &local_listener,
            ))
    })
    .await
    .context("join igd gateway discovery task")?
}

async fn establish_igd_mapping_in_netns(
    global_ctx: ArcGlobalCtx,
    local_listener: url::Url,
    gateway: TokioGateway,
    local_addr: SocketAddr,
) -> anyhow::Result<ActiveUdpPortMapping> {
    if !should_run_port_mapping_in_dedicated_thread(&global_ctx) {
        return ActiveUdpPortMapping::establish_via_igd(&local_listener, gateway, local_addr).await;
    }

    tokio::task::spawn_blocking(move || {
        let _g = global_ctx.net_ns.guard();
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
    global_ctx: ArcGlobalCtx,
    local_listener: url::Url,
) -> anyhow::Result<(Ipv4Addr, SocketAddr)> {
    if !should_run_port_mapping_in_dedicated_thread(&global_ctx) {
        return ActiveUdpPortMapping::discover_nat_pmp_gateway(&local_listener).await;
    }

    tokio::task::spawn_blocking(move || {
        let _g = global_ctx.net_ns.guard();
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
    global_ctx: ArcGlobalCtx,
    local_listener: url::Url,
    gateway: Ipv4Addr,
    local_addr: SocketAddr,
) -> anyhow::Result<ActiveUdpPortMapping> {
    if !should_run_port_mapping_in_dedicated_thread(&global_ctx) {
        return ActiveUdpPortMapping::establish_via_nat_pmp(&local_listener, gateway, local_addr)
            .await;
    }

    tokio::task::spawn_blocking(move || {
        let _g = global_ctx.net_ns.guard();
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

async fn run_udp_port_mapping_task(
    local_listener: url::Url,
    mapping: ActiveUdpPortMapping,
    mut stop_rx: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(UPNP_RENEW_INTERVAL) => {
                if let Err(err) = mapping.renew().await {
                    tracing::warn!(
                        ?err,
                        %local_listener,
                        backend = mapping.backend_name(),
                        gateway_external_port = mapping.gateway_external_port,
                        "failed to renew udp port mapping"
                    );
                }
            }
            _ = &mut stop_rx => break,
        }
    }

    if let Err(err) = mapping.remove().await {
        tracing::debug!(
            ?err,
            %local_listener,
            backend = mapping.backend_name(),
            gateway_external_port = mapping.gateway_external_port,
            "failed to remove udp port mapping"
        );
    }
}

fn should_run_port_mapping_in_dedicated_thread(global_ctx: &ArcGlobalCtx) -> bool {
    global_ctx.net_ns.name().is_some()
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

fn should_map_udp_listener(local_listener: &url::Url) -> bool {
    if local_listener.scheme() != "udp" {
        return false;
    }

    let Some(host) = listener_ipv4_host(local_listener) else {
        return false;
    };

    if host.is_loopback() || host.is_broadcast() {
        return false;
    }

    host.is_unspecified() || host.is_private() || host.is_link_local()
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

#[cfg(test)]
mod tests {
    #[test]
    fn udp_mapping_requires_private_or_unspecified_ipv4_listener() {
        assert!(super::should_map_udp_listener(
            &"udp://0.0.0.0:11010".parse().unwrap()
        ));
        assert!(super::should_map_udp_listener(
            &"udp://192.168.1.10:11010".parse().unwrap()
        ));
        assert!(!super::should_map_udp_listener(
            &"udp://127.0.0.1:11010".parse().unwrap()
        ));
        assert!(!super::should_map_udp_listener(
            &"udp://8.8.8.8:11010".parse().unwrap()
        ));
        assert!(!super::should_map_udp_listener(
            &"tcp://0.0.0.0:11010".parse().unwrap()
        ));
    }
}
