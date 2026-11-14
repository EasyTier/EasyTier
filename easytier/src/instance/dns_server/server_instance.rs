// single-instance server in one machine, every easytier instance that has ip address and tun device will try to create a server instance.

// magic dns client will connect to this server to update the dns records.
// magic dns server will add the dns server ip address to the tun device, and forward the dns request to the dns server

// magic dns client will establish a long live tcp connection to the magic dns server, and when the server stops or crashes,
// all the clients will exit and let the easytier instance to launch a new server instance.

use super::{
    MAGIC_DNS_INSTANCE_SOCKET_ADDR,
    config::{GeneralConfigBuilder, RunConfigBuilder},
    records::build_authorities,
    server::Server,
    system_config::{OSConfig, SystemConfig},
    zone,
};
use crate::{
    common::{
        error::Error as EtError,
        global_ctx::ArcGlobalCtx,
        ifcfg::{IfConfiger, IfConfiguerTrait},
        log,
        netns::NetNS,
    },
    proto::{
        common::{TunnelInfo, Void},
        magic_dns::{
            DnsRecord, DnsRecordA, DnsRecordList, GetDnsRecordResponse, HandshakeRequest,
            HandshakeResponse, MagicDnsServerRpc, MagicDnsServerRpcServer, UpdateDnsRecordRequest,
            dns_record::{self},
        },
        rpc::standalone::{
            RpcServerHook, RuntimeRpcListener, StandAloneServer, runtime_rpc_listener,
        },
        rpc_types::controller::{BaseController, Controller},
    },
};
use anyhow::Context;
use cidr::Ipv4Inet;
use easytier_core::config::toml::ConfigLoader as _;
use easytier_core::gateway::magic_dns::{
    MagicDnsQuery, MagicDnsQueryResolver, MagicDnsRecordSnapshot, MagicDnsRecordStore,
    MagicDnsResolverRegistration, MagicDnsRoute,
};
use easytier_core::instance::CorePacketPlane;
use hickory_proto::rr::LowerName;
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::authority::{MessageRequest, MessageResponse};
use hickory_server::server::{Request, ResponseHandler, ResponseInfo};
use std::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::Ipv4Addr,
    sync::Arc,
};

pub(super) struct MagicDnsServerInstanceData {
    pub(super) dns_server: Server,
    tun_dev: Option<String>,
    net_ns: NetNS,
    fake_ip: Ipv4Addr,
    manage_fake_ip_route: bool,
    route_store: MagicDnsRecordStore,
    record_apply: Arc<tokio::sync::Mutex<()>>,
    owner_instance_id: String,
    default_zone: LowerName,
    system_dns_domains: Arc<Mutex<Vec<String>>>,
    system_dns_guards: Mutex<BTreeSet<LowerName>>,
    #[cfg(target_os = "linux")]
    forwarder_resolv_conf: Mutex<Option<String>>,
    system_dns_ready: std::sync::atomic::AtomicBool,
    closing: std::sync::atomic::AtomicBool,
    system_config: Option<Arc<dyn SystemConfig>>,
}

impl MagicDnsServerInstanceData {
    async fn prepare_forwarder(&self) -> anyhow::Result<()> {
        let Some(configer) = &self.system_config else {
            return Ok(());
        };
        let apply = self.record_apply.clone().lock_owned().await;
        let configer = configer.clone();
        let (_apply, original) = tokio::task::spawn_blocking(move || {
            let original = configer
                .prepare()
                .and_then(|()| configer.original_resolv_conf());
            (apply, original)
        })
        .await?;
        self.refresh_forwarder(original?).await
    }

    async fn refresh_forwarder(&self, original: Option<String>) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        if let Some(text) = original
            && self.forwarder_resolv_conf.lock().unwrap().as_ref() != Some(&text)
        {
            self.dns_server
                .set_forwarder_from_resolv_conf(&text, self.fake_ip.into())
                .await?;
            *self.forwarder_resolv_conf.lock().unwrap() = Some(text);
        }
        #[cfg(not(target_os = "linux"))]
        let _ = original;
        Ok(())
    }

    fn system_domains(&self, snapshot: &MagicDnsRecordSnapshot) -> Vec<String> {
        let default = snapshot
            .clients
            .get(&self.owner_instance_id)
            .map(|client| &client.zone)
            .unwrap_or(&self.default_zone)
            .to_string();
        let mut origins: BTreeSet<_> = snapshot.zones.keys().map(ToString::to_string).collect();
        origins.extend(snapshot.configured_origins().map(ToString::to_string));
        origins.remove(&default);
        let mut domains = vec![default.clone()];
        domains.extend(origins);
        domains
    }

    async fn apply_snapshot(
        &self,
        snapshot: MagicDnsRecordSnapshot,
        apply: tokio::sync::OwnedMutexGuard<()>,
        withdrawing: bool,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.closing.load(std::sync::atomic::Ordering::Acquire),
            "DNS server is closing"
        );
        let previous = self.route_store.snapshot();
        let local_origins = self.dns_server.local_origins().await;
        let previous_guards = self.system_dns_guards.lock().unwrap().clone();
        let mut zones: BTreeSet<LowerName> = snapshot.zones.keys().cloned().collect();
        zones.extend(snapshot.configured_origins().cloned());
        // Preserve the established empty authoritative route-zone behavior.
        zones.extend(previous.zones.keys().cloned());
        if zones.is_empty() {
            zones.insert(self.default_zone.clone());
        }
        let mut removals: BTreeSet<_> = previous
            .configured_origins()
            .filter(|origin| !zones.contains(*origin))
            .cloned()
            .collect();
        // Empty former route zones remain authoritative. Include them when
        // resolving parent/child visibility as well as when publishing records.
        zones.extend(
            local_origins
                .difference(&removals)
                .filter(|origin| !previous_guards.contains(*origin))
                .cloned(),
        );
        let mut authorities = build_authorities(&snapshot, zones.clone())?;
        let domains = self.system_domains(&snapshot);
        let domains_changed = domains != *self.system_dns_domains.lock().unwrap();
        let mut system_result = Ok(());
        // Transfer the application guard into blocking work. Cancellation of
        // the RPC cannot release it while a system write is still running.
        let _apply = if let Some(configer) = &self.system_config
            && domains_changed
            && self
                .system_dns_ready
                .load(std::sync::atomic::Ordering::Acquire)
        {
            // Protect queries before a partial OS write can route new domains
            // here. An existing parent authority already protects its children;
            // inserting an empty child would hide accepted parent records.
            let guards: BTreeSet<_> = zones
                .iter()
                .filter(|origin| !origin.is_root())
                .filter(|origin| !local_origins.iter().any(|local| local.zone_of(origin)))
                .cloned()
                .collect();
            self.dns_server
                .replace_zones(
                    build_authorities(&MagicDnsRecordSnapshot::default(), guards.clone())?,
                    BTreeSet::new(),
                )
                .await;
            self.system_dns_guards.lock().unwrap().extend(guards);
            let configer = configer.clone();
            let system_dns_domains = self.system_dns_domains.clone();
            let cfg = OSConfig {
                nameservers: vec![self.fake_ip.to_string()],
                search_domains: vec![domains[0].clone()],
                match_domains: domains.clone(),
            };
            let reader = configer.clone();
            let (apply, original) =
                tokio::task::spawn_blocking(move || (apply, reader.original_resolv_conf())).await?;
            // Keep the original upstream before a file backend redirects every
            // system query here. Never reload our own nameserver as an upstream.
            let prepared = match original {
                Ok(original) => self.refresh_forwarder(original).await,
                Err(error) => Err(error.into()),
            };
            let (guard, result) = if let Err(error) = prepared {
                system_dns_domains.lock().unwrap().clear();
                (apply, Err(error))
            } else {
                tokio::task::spawn_blocking(move || {
                    // A failed platform write can be partial. Only skip a later
                    // write when these domains were successfully configured.
                    system_dns_domains.lock().unwrap().clear();
                    let result = configer.set_dns(&cfg);
                    if result.is_ok() {
                        *system_dns_domains.lock().unwrap() = domains;
                    }
                    (apply, result.map_err(anyhow::Error::from))
                })
                .await?
            };
            system_result = result;
            if let Err(error) = &system_result
                && !withdrawing
            {
                return Err(anyhow::anyhow!(
                    "DNS contribution rejected: system settings may be partially updated: {error:#}"
                ));
            }
            guard
        } else {
            apply
        };
        if system_result.is_err() {
            // Disconnected publishers must still lose their records. If the OS
            // may retain a withdrawn domain, leave an empty authority unless a
            // remaining zone (or guard) already covers it.
            let mut guards = self.system_dns_guards.lock().unwrap();
            let withdrawn: BTreeSet<_> = removals
                .iter()
                .filter(|origin| !origin.is_root())
                .filter(|origin| {
                    !zones
                        .iter()
                        .chain(guards.iter())
                        .any(|zone| zone.zone_of(origin))
                })
                .cloned()
                .collect();
            authorities.extend(build_authorities(
                &MagicDnsRecordSnapshot::default(),
                withdrawn.clone(),
            )?);
            guards.extend(withdrawn);
        } else {
            // A successful OS update confirms that the temporary routes have
            // been withdrawn or now have accepted authorities in this batch.
            removals.extend(self.system_dns_guards.lock().unwrap().iter().cloned());
        }
        self.dns_server.replace_zones(authorities, removals).await;
        if system_result.is_ok() {
            self.system_dns_guards.lock().unwrap().clear();
        }
        self.route_store.commit(snapshot);
        system_result
    }

    /// Initializes the owner's contribution before accepting DNS queries.
    pub async fn init_zones(&self) -> anyhow::Result<()> {
        let apply = self.record_apply.clone().lock_owned().await;
        self.apply_snapshot(self.route_store.snapshot(), apply, false)
            .await
    }
}

#[async_trait::async_trait]
impl MagicDnsServerRpc for MagicDnsServerInstanceData {
    type Controller = BaseController;
    async fn handshake(
        &self,
        _ctrl: Self::Controller,
        _input: HandshakeRequest,
    ) -> crate::proto::rpc_types::error::Result<HandshakeResponse> {
        Ok(HandshakeResponse::default())
    }

    async fn heartbeat(
        &self,
        _ctrl: Self::Controller,
        _input: Void,
    ) -> crate::proto::rpc_types::error::Result<Void> {
        Ok(Default::default())
    }

    async fn update_dns_record(
        &self,
        ctrl: Self::Controller,
        input: UpdateDnsRecordRequest,
    ) -> crate::proto::rpc_types::error::Result<Void> {
        let Some(tunnel_info) = ctrl.get_tunnel_info() else {
            return Err(anyhow::anyhow!("No tunnel info").into());
        };
        let Some(remote_addr) = &tunnel_info.remote_addr else {
            return Err(anyhow::anyhow!("No remote addr").into());
        };
        let zone = zone::parse_origin(&input.zone)?;
        let apply = self.record_apply.clone().lock_owned().await;
        let remote_addr: url::Url = remote_addr.clone().into();
        let dns = input.dns.unwrap_or_default();
        if let Some(domain) = &dns.domain
            && zone::parse_origin(domain)? != zone
        {
            return Err(anyhow::anyhow!("DNS contribution domain must match route zone").into());
        }
        let routes = input
            .routes
            .into_iter()
            .map(|route| MagicDnsRoute {
                hostname: route.hostname,
                ipv4_addr: route
                    .ipv4_addr
                    .and_then(|addr| addr.address)
                    .map(Into::into),
            })
            .collect();
        let snapshot = self.route_store.replacement(
            input.instance_id,
            Some(remote_addr.to_string()),
            zone,
            routes,
            dns,
        )?;
        if self.closing.load(std::sync::atomic::Ordering::Acquire) {
            return Err(anyhow::anyhow!("DNS server is closing").into());
        }
        if snapshot.clients == self.route_store.snapshot().clients
            && (self.system_config.is_none()
                || (self.system_domains(&snapshot) == *self.system_dns_domains.lock().unwrap()
                    && self.system_dns_guards.lock().unwrap().is_empty()))
        {
            return Ok(Default::default());
        }
        self.apply_snapshot(snapshot, apply, false).await?;
        Ok(Default::default())
    }

    async fn get_dns_record(
        &self,
        _ctrl: Self::Controller,
        _input: Void,
    ) -> crate::proto::rpc_types::error::Result<GetDnsRecordResponse> {
        let mut ret = BTreeMap::new();
        for (zone, routes) in self.route_store.snapshot().zones {
            if routes.is_empty() {
                continue;
            }
            let mut dns_records = DnsRecordList::default();
            for route in routes {
                dns_records.records.push(DnsRecord {
                    record: Some(dns_record::Record::A(DnsRecordA {
                        name: format!("{}.{}", route.hostname, zone),
                        value: route.ipv4_addr.map(Into::into),
                        ttl: 1,
                    })),
                });
            }
            ret.insert(zone.to_string(), dns_records);
        }
        Ok(GetDnsRecordResponse { records: ret })
    }
}

// This should only be used for UDP response.
// For other protocols, the variable `max_size` in `send_response` should be u16::MAX.
#[derive(Clone)]
struct ResponseWrapper {
    response: Arc<Mutex<Vec<u8>>>,
}

trait RecordIter<'a>: Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a {}
impl<'a, T> RecordIter<'a> for T where T: Iterator<Item = &'a hickory_proto::rr::Record> + Send + 'a {}

#[async_trait::async_trait]
impl ResponseHandler for ResponseWrapper {
    async fn send_response<'a>(
        &mut self,
        response: MessageResponse<
            '_,
            'a,
            impl RecordIter<'a>,
            impl RecordIter<'a>,
            impl RecordIter<'a>,
            impl RecordIter<'a>,
        >,
    ) -> io::Result<ResponseInfo> {
        let mut buffer = self
            .response
            .lock()
            .map_err(|_| io::Error::other("lock poisoned"))?;

        let mut encoder = BinEncoder::new(&mut buffer);

        // `max_size` should be u16::MAX for protocol other than UDP.
        let max_size = if let Some(edns) = response.get_edns() {
            edns.max_payload()
        } else {
            hickory_proto::udp::MAX_RECEIVE_BUFFER_SIZE as u16
        };

        encoder.set_max_size(max_size);
        response
            .destructive_emit(&mut encoder)
            .map_err(io::Error::other)
    }
}

impl MagicDnsServerInstanceData {
    async fn resolve_query_inner(&self, query: MagicDnsQuery) -> Option<Vec<u8>> {
        let request = Request::new(
            MessageRequest::from_bytes(&query.payload).ok()?,
            query.source,
            hickory_proto::xfer::Protocol::Udp,
        );
        let response = Arc::new(Mutex::new(Vec::with_capacity(512)));

        self.dns_server
            .handle_request(
                &request,
                ResponseWrapper {
                    response: response.clone(),
                },
            )
            .await;

        Arc::into_inner(response)?.into_inner().ok()
    }
}

#[async_trait::async_trait]
impl MagicDnsQueryResolver for MagicDnsServerInstanceData {
    async fn resolve(&self, query: MagicDnsQuery) -> Option<Vec<u8>> {
        self.resolve_query_inner(query).await
    }
}

#[async_trait::async_trait]
impl RpcServerHook for MagicDnsServerInstanceData {
    async fn on_new_client(
        &self,
        tunnel_info: Option<TunnelInfo>,
    ) -> Result<Option<TunnelInfo>, anyhow::Error> {
        tracing::info!(?tunnel_info, "New client connected");
        Ok(tunnel_info)
    }

    async fn on_client_disconnected(&self, tunnel_info: Option<TunnelInfo>) {
        tracing::info!(?tunnel_info, "Client disconnected");
        let Some(tunnel_info) = tunnel_info else {
            return;
        };
        let Some(remote_addr) = tunnel_info.remote_addr else {
            return;
        };
        let apply = self.record_apply.clone().lock_owned().await;
        let remote_addr: url::Url = remote_addr.into();
        let snapshot = self.route_store.without_source(remote_addr.as_ref());
        if snapshot.clients == self.route_store.snapshot().clients {
            return;
        }
        if let Err(error) = self.apply_snapshot(snapshot, apply, true).await {
            tracing::error!(?error, "failed to update DNS after publisher disconnect");
        }
    }
}

pub struct MagicDnsServerInstance {
    _rpc_server: StandAloneServer<RuntimeRpcListener>,
    pub(super) data: Arc<MagicDnsServerInstanceData>,
    packet_filter: MagicDnsResolverRegistration,
    tun_inet: Ipv4Inet,
}

fn get_system_config(
    _tun_name: Option<&str>,
    _net_ns: &NetNS,
) -> Result<Option<Box<dyn SystemConfig>>, anyhow::Error> {
    #[cfg(target_os = "linux")]
    {
        use super::system_config::linux::new_configurator;
        let Some(tun_name) = _tun_name else {
            return Ok(None);
        };
        anyhow::ensure!(
            _net_ns.name().is_none(),
            "Automatic Magic DNS requires the host network namespace"
        );
        return Ok(Some(new_configurator(tun_name)?));
    }

    #[cfg(target_os = "windows")]
    {
        use super::system_config::windows::WindowsDNSManager;
        let tun_name = _tun_name.ok_or_else(|| anyhow::anyhow!("No tun name"))?;
        return Ok(Some(Box::new(WindowsDNSManager::new(tun_name)?)));
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
    {
        use super::system_config::darwin::DarwinConfigurator;
        return Ok(Some(Box::new(DarwinConfigurator::new())));
    }

    #[allow(unreachable_code)]
    Ok(None)
}

impl MagicDnsServerInstance {
    async fn add_fake_ip_route(
        tun_dev_name: &str,
        fake_ip: Ipv4Addr,
        net_ns: &NetNS,
        cost: Option<i32>,
    ) -> Result<(), anyhow::Error> {
        let ifcfg = IfConfiger::default();
        let _guard = net_ns.guard();
        match ifcfg.add_ipv4_route(tun_dev_name, fake_ip, 32, cost).await {
            Err(EtError::IOError(err)) if err.kind() == io::ErrorKind::AlreadyExists => {
                ifcfg.remove_ipv4_route(tun_dev_name, fake_ip, 32).await?;
                ifcfg
                    .add_ipv4_route(tun_dev_name, fake_ip, 32, cost)
                    .await?;
                Ok(())
            }
            ret => ret.map_err(Into::into),
        }
    }

    async fn remove_fake_ip_route(tun_dev_name: &str, fake_ip: Ipv4Addr, net_ns: &NetNS) {
        let ifcfg = IfConfiger::default();
        let _guard = net_ns.guard();
        if let Err(err) = ifcfg.remove_ipv4_route(tun_dev_name, fake_ip, 32).await {
            tracing::warn!(
                ?err,
                ?tun_dev_name,
                ?fake_ip,
                "remove magic dns route failed"
            );
        }
    }

    pub(crate) async fn new(
        packet_plane: Arc<CorePacketPlane>,
        global_ctx: ArcGlobalCtx,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Result<Self, anyhow::Error> {
        Self::new_inner(packet_plane, global_ctx, tun_dev, tun_inet, fake_ip, true).await
    }

    pub(crate) async fn new_with_external_fake_ip_route(
        packet_plane: Arc<CorePacketPlane>,
        global_ctx: ArcGlobalCtx,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Result<Self, anyhow::Error> {
        Self::new_inner(packet_plane, global_ctx, tun_dev, tun_inet, fake_ip, false).await
    }

    async fn new_inner(
        packet_plane: Arc<CorePacketPlane>,
        global_ctx: ArcGlobalCtx,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
        manage_fake_ip_route: bool,
    ) -> Result<Self, anyhow::Error> {
        // Validate the local DNS configuration before attempting the election:
        // an invalid configuration must not win the listener and then fail or
        // tear down the shared server.
        let default_zone = zone::dns_domain(&global_ctx.config)?;
        let configured = easytier_core::gateway::magic_dns::normalized_dns(&global_ctx.config)
            .context("Invalid local DNS configuration")?;
        let owner_instance_id = global_ctx.config.get_id().to_string();
        let route_store = MagicDnsRecordStore::default();
        route_store.commit(route_store.replacement(
            owner_instance_id.clone(),
            None,
            default_zone.clone(),
            vec![],
            configured,
        )?);

        let system_config: Option<Arc<dyn SystemConfig>> = match get_system_config(
            tun_dev.as_deref(),
            &global_ctx.net_ns,
        ) {
            Ok(configer) => configer.map(Arc::from),
            Err(error) => {
                log::warn!(
                    category: "DNS",
                    ?error,
                    "Magic DNS service will remain available; automatic system DNS is unavailable"
                );
                None
            }
        };
        let defer_system_forwarder = system_config
            .as_ref()
            .is_some_and(|configer| configer.needs_resolv_conf_recovery());
        let dns_config = RunConfigBuilder::default()
            .general(GeneralConfigBuilder::default().build()?)
            .excluded_forward_nameservers(vec![fake_ip.into()])
            .defer_system_forwarder(defer_system_forwarder)
            .build()?;
        let mut dns_server = Server::new(dns_config);
        dns_server.run().await?;

        let data = Arc::new(MagicDnsServerInstanceData {
            dns_server,
            tun_dev: tun_dev.clone(),
            net_ns: global_ctx.net_ns.clone(),
            fake_ip,
            manage_fake_ip_route,
            route_store,
            record_apply: Arc::new(tokio::sync::Mutex::new(())),
            owner_instance_id,
            default_zone: default_zone.clone(),
            system_dns_domains: Arc::new(Mutex::new(Vec::new())),
            system_dns_guards: Mutex::new(BTreeSet::new()),
            #[cfg(target_os = "linux")]
            forwarder_resolv_conf: Mutex::new(None),
            system_dns_ready: std::sync::atomic::AtomicBool::new(false),
            closing: std::sync::atomic::AtomicBool::new(false),
            system_config,
        });

        let tcp_listener = runtime_rpc_listener(MAGIC_DNS_INSTANCE_SOCKET_ADDR.parse()?);
        let server = Self::start(
            StandAloneServer::new(tcp_listener),
            data,
            packet_plane,
            tun_inet,
            async {
                if manage_fake_ip_route
                    && !tun_inet.contains(&fake_ip)
                    && let Some(tun_dev_name) = &tun_dev
                {
                    let cost = if cfg!(target_os = "windows") {
                        Some(4)
                    } else {
                        None
                    };
                    Self::add_fake_ip_route(tun_dev_name, fake_ip, &global_ctx.net_ns, cost)
                        .await?;
                }
                Ok(())
            },
        )
        .await?;
        // Shared TUN routes are installed by the runner before enabling DNS.
        if manage_fake_ip_route {
            server.enable_system_dns().await;
        }
        Ok(server)
    }

    async fn start(
        mut rpc_server: StandAloneServer<RuntimeRpcListener>,
        data: Arc<MagicDnsServerInstanceData>,
        packet_plane: Arc<CorePacketPlane>,
        tun_inet: Ipv4Inet,
        add_route: impl std::future::Future<Output = anyhow::Result<()>>,
    ) -> anyhow::Result<Self> {
        // Binding elects the server; registration enables record publication.
        // Keep those separate until initialization has completed, and install
        // the hook before serve takes ownership of it.
        rpc_server.set_hook(data.clone());
        rpc_server.serve().await?;
        // Only the elected owner may recover a persistent system takeover.
        // In file mode the root authority is deliberately absent until this has
        // restored the original resolver and loaded its actual nameservers.
        if let Err(error) = data.prepare_forwarder().await {
            log::warn!(
                category: "DNS",
                ?error,
                "Magic DNS could not prepare system DNS; local authorities remain available"
            );
        }
        data.init_zones()
            .await
            .context("Failed to initialize DNS zones")?;

        // The query handler must be installed before routing or OS DNS settings
        // can direct packets to it.
        let packet_filter = packet_plane
            .register_magic_dns_resolver(data.fake_ip, data.clone())
            .await;
        if let Err(error) = add_route.await {
            packet_filter.close().await;
            return Err(error);
        }
        rpc_server
            .registry()
            .register(MagicDnsServerRpcServer::new_arc(data.clone()), "");
        Ok(Self {
            _rpc_server: rpc_server,
            data,
            packet_filter,
            tun_inet,
        })
    }

    pub(super) async fn enable_system_dns(&self) {
        let Some(configer) = &self.data.system_config else {
            log::warn!(
                category: "DNS",
                "Magic DNS service is available; automatic system DNS is not configured"
            );
            return;
        };
        let configured = async {
            // Recovery/read failures have not changed OS settings. Do not enter
            // strict application mode until the original upstream is available,
            // or a stale record could prevent local publishers from starting.
            self.data.prepare_forwarder().await?;
            self.data
                .system_dns_ready
                .store(true, std::sync::atomic::Ordering::Release);
            self.data.init_zones().await
        }
        .await;
        if let Err(error) = configured {
            log::warn!(
                category: "DNS",
                ?error,
                "Magic DNS service remains available; automatic system DNS configuration failed"
            );
            // An initial failure must not remove the query service. Only leave
            // strict OS application mode after confirming that partial settings
            // have been removed; otherwise its domain guards must stay active.
            let apply = self.data.record_apply.clone().lock_owned().await;
            let configer = configer.clone();
            let cleanup = tokio::task::spawn_blocking(move || (apply, configer.close())).await;
            match cleanup {
                Ok((apply, Ok(()))) => {
                    self.data
                        .system_dns_ready
                        .store(false, std::sync::atomic::Ordering::Release);
                    self.data.system_dns_domains.lock().unwrap().clear();
                    if let Err(error) = self
                        .data
                        .apply_snapshot(self.data.route_store.snapshot(), apply, false)
                        .await
                    {
                        log::error!(category: "DNS", ?error, "Failed to restore accepted DNS records");
                    }
                }
                Ok((_, Err(error))) => {
                    log::error!(
                        category: "DNS",
                        ?error,
                        "Partial system DNS settings remain; preserving DNS domain guards"
                    );
                }
                Err(error) => {
                    log::error!(category: "DNS", ?error, "System DNS cleanup did not complete");
                }
            }
        } else {
            log::info!(category: "DNS", "Magic DNS service is available and system DNS is configured");
        }
    }

    pub(super) async fn refresh_system_dns(&self) {
        let Some(configer) = &self.data.system_config else {
            return;
        };
        if !self
            .data
            .system_dns_ready
            .load(std::sync::atomic::Ordering::Acquire)
        {
            self.enable_system_dns().await;
            return;
        }
        let apply = self.data.record_apply.clone().lock_owned().await;
        let configer = configer.clone();
        let read = tokio::task::spawn_blocking(move || {
            let original = configer
                .refresh()
                .and_then(|()| configer.original_resolv_conf());
            (apply, original)
        })
        .await;
        let (apply, original) = match read {
            Ok((apply, Ok(original))) => (apply, original),
            Ok((_, Err(error))) => {
                self.data.system_dns_domains.lock().unwrap().clear();
                log::warn!(
                    category: "DNS",
                    ?error,
                    "Magic DNS service remains available; system DNS configuration is no longer confirmed"
                );
                return;
            }
            Err(error) => {
                log::error!(category: "DNS", ?error, "Failed to inspect system DNS configuration");
                return;
            }
        };
        if let Err(error) = self.data.refresh_forwarder(original).await {
            self.data.system_dns_domains.lock().unwrap().clear();
            log::warn!(category: "DNS", ?error, "Keeping the previous Magic DNS upstream");
            return;
        }
        let needs_retry = self.data.system_dns_domains.lock().unwrap().is_empty();
        if needs_retry {
            match self
                .data
                .apply_snapshot(self.data.route_store.snapshot(), apply, false)
                .await
            {
                Ok(()) => {
                    log::info!(category: "DNS", "Magic DNS system configuration recovered");
                }
                Err(error) => {
                    log::warn!(
                        category: "DNS",
                        ?error,
                        "Magic DNS service remains available; system DNS retry failed"
                    );
                }
            }
        }
    }

    pub async fn clean_env(&self) {
        let _apply = self.data.record_apply.lock().await;
        self.data
            .closing
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(configer) = &self.data.system_config {
            let configer = configer.clone();
            let ret = tokio::task::spawn_blocking(move || configer.close()).await;
            let ret = ret
                .map_err(anyhow::Error::from)
                .and_then(|ret| ret.map_err(Into::into));
            if let Err(e) = ret {
                log::error!(category: "DNS", "Failed to close system config: {:?}", e);
            }
        }
        if self.data.manage_fake_ip_route
            && !self.tun_inet.contains(&self.data.fake_ip)
            && let Some(tun_dev_name) = &self.data.tun_dev
        {
            Self::remove_fake_ip_route(tun_dev_name, self.data.fake_ip, &self.data.net_ns).await;
        }

        self.packet_filter.close().await;
    }
}

impl Drop for MagicDnsServerInstance {
    fn drop(&mut self) {
        println!("MagicDnsServerInstance dropped");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::api::instance::Route;
    use easytier_core::config::toml::{DnsConfig, DnsZoneConfig};
    use easytier_proto::core_config::{DnsRecordRaw, DnsRecordType};
    use hickory_proto::{
        op::{Message, Query},
        rr::{RData, RecordType},
    };
    use std::str::FromStr;
    use std::time::Duration;

    type DomainConfigRecord = (Vec<String>, Vec<String>);
    type DomainConfigSpyCalls = Arc<Mutex<Vec<DomainConfigRecord>>>;

    struct SystemConfigSpy(DomainConfigSpyCalls);

    impl SystemConfig for SystemConfigSpy {
        fn set_dns(&self, config: &OSConfig) -> io::Result<()> {
            assert_eq!(config.nameservers, ["100.100.100.101"]);
            self.0
                .lock()
                .unwrap()
                .push((config.search_domains.clone(), config.match_domains.clone()));
            Ok(())
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    fn record(name: &str, kind: DnsRecordType, value: &str, ttl: Option<u32>) -> DnsRecordRaw {
        DnsRecordRaw {
            name: name.into(),
            r#type: kind as i32,
            ttl,
            value: Some(value.into()),
        }
    }

    fn config(zones: &[(&str, &[DnsRecordRaw])]) -> DnsConfig {
        DnsConfig {
            domain: None,
            zone: Some(
                zones
                    .iter()
                    .map(|(origin, records)| DnsZoneConfig {
                        origin: (*origin).to_owned(),
                        ttl: Some(60),
                        records: Some(records.to_vec().into()),
                    })
                    .collect::<Vec<_>>()
                    .into(),
            ),
        }
    }

    async fn data_with_default_zone(
        default_zone: &str,
        dns: Option<&DnsConfig>,
    ) -> MagicDnsServerInstanceData {
        let route_store = MagicDnsRecordStore::default();
        let mut dns = dns.cloned().unwrap_or_default();
        dns.domain = Some(default_zone.to_owned());
        route_store.commit(
            route_store
                .replacement(
                    "00000000-0000-0000-0000-000000000001".to_owned(),
                    None,
                    zone::parse_origin(default_zone).unwrap(),
                    vec![],
                    dns,
                )
                .unwrap(),
        );
        let data = MagicDnsServerInstanceData {
            dns_server: Server::new(
                RunConfigBuilder::default()
                    .general(GeneralConfigBuilder::default().build().unwrap())
                    .build()
                    .unwrap(),
            ),
            tun_dev: None,
            net_ns: NetNS::new(None),
            fake_ip: "100.100.100.101".parse().unwrap(),
            manage_fake_ip_route: false,
            route_store,
            record_apply: Arc::new(tokio::sync::Mutex::new(())),
            owner_instance_id: "00000000-0000-0000-0000-000000000001".to_owned(),
            default_zone: zone::parse_origin(default_zone).unwrap(),
            system_dns_domains: Arc::new(Mutex::new(Vec::new())),
            system_dns_guards: Mutex::new(BTreeSet::new()),
            #[cfg(target_os = "linux")]
            forwarder_resolv_conf: Mutex::new(None),
            system_dns_ready: std::sync::atomic::AtomicBool::new(true),
            closing: std::sync::atomic::AtomicBool::new(false),
            system_config: None,
        };
        data.init_zones().await.unwrap();
        data
    }

    async fn data_with(dns: Option<&DnsConfig>) -> MagicDnsServerInstanceData {
        data_with_default_zone("et.net.", dns).await
    }

    fn controller(port: u16) -> BaseController {
        let mut ctrl = BaseController::default();
        ctrl.set_tunnel_info(Some(TunnelInfo {
            remote_addr: Some(
                url::Url::parse(&format!("tcp://127.0.0.1:{port}"))
                    .unwrap()
                    .into(),
            ),
            ..Default::default()
        }));
        ctrl
    }

    fn request(ip: &str) -> UpdateDnsRecordRequest {
        UpdateDnsRecordRequest {
            zone: "et.net.".to_owned(),
            instance_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            dns: Some(DnsConfig::default()),
            routes: vec![Route {
                hostname: "node".to_owned(),
                ipv4_addr: Some(Ipv4Inet::from_str(ip).unwrap().into()),
                ..Default::default()
            }],
        }
    }

    async fn query(
        data: &MagicDnsServerInstanceData,
        name: &str,
        record_type: RecordType,
    ) -> Message {
        let mut request = Message::new();
        request.set_recursion_desired(true);
        request.add_query(Query::query(name.parse().unwrap(), record_type));
        let response = data
            .resolve_query_inner(MagicDnsQuery {
                source: "127.0.0.1:5353".parse().unwrap(),
                payload: request.to_vec().unwrap(),
            })
            .await
            .unwrap();
        Message::from_vec(&response).unwrap()
    }

    async fn a(data: &MagicDnsServerInstanceData, name: &str) -> Vec<Ipv4Addr> {
        let mut answers = query(data, name, RecordType::A)
            .await
            .answers()
            .iter()
            .filter_map(|record| match record.data() {
                RData::A(ip) => Some(ip.0),
                _ => None,
            })
            .collect::<Vec<_>>();
        answers.sort();
        answers
    }

    #[cfg(feature = "tun")]
    mod startup {
        use super::*;
        use crate::{
            common::global_ctx::tests::get_mock_global_ctx,
            instance::dns_server::tests::build_test_core,
            proto::{
                magic_dns::MagicDnsServerRpcClientFactory, rpc::standalone::runtime_rpc_client,
            },
        };
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        #[derive(Default)]
        struct StartupSystemConfig {
            domains: Mutex<Vec<String>>,
            prepares: AtomicUsize,
            writes: AtomicUsize,
            closes: AtomicUsize,
            fail_prepare: AtomicBool,
            fail_write: AtomicBool,
            fail_close: AtomicBool,
        }

        impl SystemConfig for StartupSystemConfig {
            fn prepare(&self) -> io::Result<()> {
                self.prepares.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }

            fn original_resolv_conf(&self) -> io::Result<Option<String>> {
                if self.fail_prepare.load(Ordering::SeqCst) {
                    return Err(io::Error::other("injected system DNS recovery failure"));
                }
                Ok(None)
            }

            fn set_dns(&self, config: &OSConfig) -> io::Result<()> {
                self.writes.fetch_add(1, Ordering::SeqCst);
                *self.domains.lock().unwrap() = config.match_domains.clone();
                if self.fail_write.load(Ordering::SeqCst) {
                    return Err(io::Error::other("injected partial system DNS failure"));
                }
                Ok(())
            }

            fn close(&self) -> io::Result<()> {
                self.closes.fetch_add(1, Ordering::SeqCst);
                if self.fail_close.load(Ordering::SeqCst) {
                    return Err(io::Error::other("injected system DNS cleanup failure"));
                }
                self.domains.lock().unwrap().clear();
                Ok(())
            }
        }

        #[tokio::test]
        async fn system_dns_failure_keeps_service_and_retry_preserves_records() {
            use hickory_proto::op::{MessageType, ResponseCode};
            use tokio::net::UdpSocket;

            for (fail_prepare, fail_close) in [(false, false), (false, true), (true, true)] {
                let (core, _packets) = build_test_core(get_mock_global_ctx()).await;
                let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let mut data = data_with(None).await;
                data.dns_server = super::super::super::server::tests::forwarding_server(
                    upstream.local_addr().unwrap(),
                )
                .await
                .unwrap();
                let system = Arc::new(StartupSystemConfig::default());
                system.fail_prepare.store(fail_prepare, Ordering::SeqCst);
                system.fail_write.store(true, Ordering::SeqCst);
                system.fail_close.store(fail_close, Ordering::SeqCst);
                data.system_config = Some(system.clone());
                data.system_dns_ready.store(false, Ordering::SeqCst);
                let data = Arc::new(data);
                let address = rpc_address();
                let server = MagicDnsServerInstance::start(
                    StandAloneServer::new(runtime_rpc_listener(address)),
                    data.clone(),
                    core.packet_plane(),
                    "100.100.100.0/24".parse().unwrap(),
                    async { Ok(()) },
                )
                .await
                .unwrap();
                server.enable_system_dns().await;
                assert_eq!(system.closes.load(Ordering::SeqCst), 1);
                let partial_write = !fail_prepare && fail_close;
                assert_eq!(data.system_dns_ready.load(Ordering::SeqCst), partial_write);
                assert_eq!(
                    system.writes.load(Ordering::SeqCst),
                    usize::from(!fail_prepare)
                );

                // The same RPC owner and root forwarder survive an OS failure.
                let mut client = runtime_rpc_client(format!("tcp://{address}").parse().unwrap());
                let rpc = client
                    .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>(String::new())
                    .await
                    .unwrap();
                rpc.handshake(BaseController::default(), HandshakeRequest::default())
                    .await
                    .unwrap();
                let forwarding = {
                    let data = data.clone();
                    tokio::spawn(async move {
                        query(&data, "ordinary.example.org.", RecordType::A).await
                    })
                };
                let mut packet = [0; 4096];
                let (length, source) =
                    tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut packet))
                        .await
                        .unwrap()
                        .unwrap();
                let mut response = Message::from_vec(&packet[..length]).unwrap();
                response
                    .set_message_type(MessageType::Response)
                    .set_response_code(ResponseCode::NXDomain);
                upstream
                    .send_to(&response.to_vec().unwrap(), source)
                    .await
                    .unwrap();
                assert_eq!(
                    forwarding.await.unwrap().response_code(),
                    ResponseCode::NXDomain
                );

                let dns = config(&[(
                    "new.test",
                    &[record("svc", DnsRecordType::A, "10.0.0.8", None)],
                )]);
                let result = rpc
                    .update_dns_record(BaseController::default(), contribution(2, dns.clone()))
                    .await;
                assert_eq!(result.is_err(), partial_write);
                if partial_write {
                    assert_eq!(
                        query(&data, "svc.new.test.", RecordType::A)
                            .await
                            .response_code(),
                        ResponseCode::NXDomain
                    );
                    assert_eq!(data.route_store.snapshot().clients.len(), 1);
                } else {
                    assert_eq!(
                        a(&data, "svc.new.test.").await,
                        vec![Ipv4Addr::new(10, 0, 0, 8)]
                    );
                }
                system.fail_prepare.store(false, Ordering::SeqCst);
                system.fail_write.store(false, Ordering::SeqCst);
                system.fail_close.store(false, Ordering::SeqCst);
                server.refresh_system_dns().await;
                assert!(data.system_dns_ready.load(Ordering::SeqCst));
                assert!(!data.system_dns_domains.lock().unwrap().is_empty());
                assert!(data.system_dns_guards.lock().unwrap().is_empty());
                rpc.update_dns_record(BaseController::default(), contribution(2, dns))
                    .await
                    .unwrap();
                assert_eq!(
                    a(&data, "svc.new.test.").await,
                    vec![Ipv4Addr::new(10, 0, 0, 8)]
                );
                server.clean_env().await;
                core.stop().await;
            }
        }

        #[cfg(target_os = "linux")]
        #[tokio::test]
        async fn startup_loads_plain_forwarder_without_recovery_storage() {
            use std::os::unix::fs::PermissionsExt;

            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("resolv.conf");
            let original = "nameserver 192.0.2.53\nsearch lan.test\n";
            std::fs::write(&path, original).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444)).unwrap();
            std::fs::write(directory.path().join(".easytier-dns"), "not a directory").unwrap();
            let (core, _packets) = build_test_core(get_mock_global_ctx()).await;
            let mut data = data_with(None).await;
            data.dns_server = Server::new(
                RunConfigBuilder::default()
                    .general(GeneralConfigBuilder::default().build().unwrap())
                    .defer_system_forwarder(true)
                    .build()
                    .unwrap(),
            );
            data.system_config = Some(Arc::new(
                super::super::super::system_config::resolv_conf::ResolvConfConfigurator::new(
                    path.clone(),
                ),
            ));
            data.system_dns_ready.store(false, Ordering::SeqCst);
            let data = Arc::new(data);
            let server = MagicDnsServerInstance::start(
                StandAloneServer::new(runtime_rpc_listener(rpc_address())),
                data.clone(),
                core.packet_plane(),
                "100.100.100.0/24".parse().unwrap(),
                async { Ok(()) },
            )
            .await
            .unwrap();
            assert_eq!(
                *data.forwarder_resolv_conf.lock().unwrap(),
                Some(original.to_owned())
            );
            assert_eq!(std::fs::read_to_string(path).unwrap(), original);
            server.clean_env().await;
            core.stop().await;
        }

        fn rpc_address() -> std::net::SocketAddr {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
        }

        #[tokio::test]
        async fn startup_publishes_rpc_only_after_route_and_dns_are_ready() {
            for fail_route in [true, false] {
                let (core, _packets) = build_test_core(get_mock_global_ctx()).await;
                let system = Arc::new(StartupSystemConfig::default());
                let mut data = data_with(None).await;
                data.system_config = Some(system.clone());
                data.system_dns_ready.store(false, Ordering::SeqCst);
                let data = Arc::new(data);
                let address = rpc_address();
                let (entered, started) = tokio::sync::oneshot::channel();
                let (release, blocked) = tokio::sync::oneshot::channel();
                let starting_data = data.clone();
                let packet_plane = core.packet_plane();
                let starting = tokio::spawn(async move {
                    MagicDnsServerInstance::start(
                        StandAloneServer::new(runtime_rpc_listener(address)),
                        starting_data,
                        packet_plane,
                        "100.100.100.0/24".parse().unwrap(),
                        async move {
                            entered.send(()).unwrap();
                            blocked.await?;
                            anyhow::ensure!(!fail_route, "injected fake-IP route failure");
                            Ok(())
                        },
                    )
                    .await
                });
                started.await.unwrap();

                let mut early_client =
                    runtime_rpc_client(format!("tcp://{address}").parse().unwrap());
                let early = early_client
                    .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>(String::new())
                    .await
                    .unwrap();
                let result = early
                    .update_dns_record(BaseController::default(), request("10.0.0.8/24"))
                    .await;
                assert!(
                    matches!(
                        &result,
                        Err(crate::proto::rpc_types::error::Error::InvalidServiceKey(..))
                    ),
                    "expected an unregistered DNS service during startup, got {result:?}"
                );
                assert_eq!(system.writes.load(Ordering::SeqCst), 0);
                assert_eq!(system.prepares.load(Ordering::SeqCst), 1);
                assert_eq!(data.route_store.snapshot().clients.len(), 1);

                let mut loser_data = data_with(None).await;
                let loser_system = Arc::new(StartupSystemConfig::default());
                loser_data.system_config = Some(loser_system.clone());
                let loser_route = AtomicBool::new(false);
                assert!(
                    MagicDnsServerInstance::start(
                        StandAloneServer::new(runtime_rpc_listener(address)),
                        Arc::new(loser_data),
                        core.packet_plane(),
                        "100.100.100.0/24".parse().unwrap(),
                        async {
                            loser_route.store(true, Ordering::SeqCst);
                            Ok(())
                        },
                    )
                    .await
                    .is_err()
                );
                assert!(!loser_route.load(Ordering::SeqCst));
                assert_eq!(loser_system.prepares.load(Ordering::SeqCst), 0);
                assert_eq!(loser_system.writes.load(Ordering::SeqCst), 0);
                assert_eq!(loser_system.closes.load(Ordering::SeqCst), 0);

                release.send(()).unwrap();
                let result = starting.await.unwrap();
                drop(early);
                if fail_route {
                    assert!(
                        result
                            .err()
                            .unwrap()
                            .to_string()
                            .contains("injected fake-IP route failure")
                    );
                    assert_eq!(system.writes.load(Ordering::SeqCst), 0);
                    assert_eq!(system.closes.load(Ordering::SeqCst), 0);
                    assert!(system.domains.lock().unwrap().is_empty());
                    tokio::time::timeout(Duration::from_secs(5), early_client.wait())
                        .await
                        .unwrap();
                    let mut next = StandAloneServer::new(runtime_rpc_listener(address));
                    next.serve().await.unwrap();
                } else {
                    let server = result.ok().unwrap();
                    assert_eq!(system.writes.load(Ordering::SeqCst), 0);
                    server.enable_system_dns().await;
                    assert_eq!(system.writes.load(Ordering::SeqCst), 1);
                    assert_eq!(*system.domains.lock().unwrap(), ["et.net."]);

                    // A connection accepted before registration has no service;
                    // the normal client handshake fails and a later retry reconnects.
                    let mut client =
                        runtime_rpc_client(format!("tcp://{address}").parse().unwrap());
                    let rpc = client
                        .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>(
                            String::new(),
                        )
                        .await
                        .unwrap();
                    rpc.handshake(BaseController::default(), HandshakeRequest::default())
                        .await
                        .unwrap();
                    rpc.update_dns_record(BaseController::default(), request("10.0.0.8/24"))
                        .await
                        .unwrap();
                    assert_eq!(
                        a(&data, "node.et.net.").await,
                        vec![Ipv4Addr::new(10, 0, 0, 8)]
                    );
                    server.clean_env().await;
                    assert_eq!(system.closes.load(Ordering::SeqCst), 1);
                    assert!(system.domains.lock().unwrap().is_empty());
                    let writes = system.writes.load(Ordering::SeqCst);
                    assert!(
                        rpc.update_dns_record(BaseController::default(), request("10.0.0.9/24"))
                            .await
                            .is_err()
                    );
                    assert_eq!(system.writes.load(Ordering::SeqCst), writes);
                }
                core.stop().await;
            }
        }
    }

    #[tokio::test]
    async fn custom_records_survive_route_refresh_and_support_common_types() {
        let dns = config(&[
            (
                "ET.NET",
                &[
                    record("nas", DnsRecordType::A, "10.0.0.8", None),
                    record("nas", DnsRecordType::A, "10.0.0.18", None),
                    record("nas", DnsRecordType::Aaaa, "fd00::8", None),
                    record("nas", DnsRecordType::Aaaa, "fd00::18", None),
                    record("alias", DnsRecordType::Cname, "nas", Some(45)),
                    record("chain", DnsRecordType::Cname, "alias", Some(30)),
                    record("node-alias", DnsRecordType::Cname, "node", None),
                    record("nas.sub", DnsRecordType::A, "10.0.0.98", None),
                    record("specific", DnsRecordType::Cname, "nas.sub", None),
                    record("missing", DnsRecordType::Cname, "absent", None),
                    record("cycle", DnsRecordType::Cname, "cycle.example.test.", None),
                    record("info", DnsRecordType::Txt, "\"local record\"", None),
                ],
            ),
            (
                "example.test.",
                &[
                    record("cross", DnsRecordType::Cname, "chain.et.net.", Some(20)),
                    record("cycle", DnsRecordType::Cname, "cycle.et.net.", None),
                ],
            ),
            (
                "sub.et.net.",
                &[record("nas", DnsRecordType::A, "10.0.0.99", None)],
            ),
        ]);
        let data = data_with(Some(&dns)).await;
        for ip in ["10.0.0.1/24", "10.0.0.2/24"] {
            data.update_dns_record(controller(54001), request(ip))
                .await
                .unwrap();
            assert_eq!(
                a(&data, "nas.et.net.").await,
                vec![Ipv4Addr::new(10, 0, 0, 8), Ipv4Addr::new(10, 0, 0, 18)]
            );
            for (record_type, addresses) in [
                (RecordType::A, ["10.0.0.8", "10.0.0.18"]),
                (RecordType::AAAA, ["fd00::8", "fd00::18"]),
            ] {
                for (name, cnames) in [
                    ("alias.et.net.", vec![("alias.et.net.", 45, "nas.et.net.")]),
                    (
                        "chain.et.net.",
                        vec![
                            ("chain.et.net.", 30, "alias.et.net."),
                            ("alias.et.net.", 45, "nas.et.net."),
                        ],
                    ),
                    (
                        "cross.example.test.",
                        vec![
                            ("cross.example.test.", 20, "chain.et.net."),
                            ("chain.et.net.", 30, "alias.et.net."),
                            ("alias.et.net.", 45, "nas.et.net."),
                        ],
                    ),
                ] {
                    let mut expected = cnames
                        .into_iter()
                        .map(|(owner, ttl, target)| {
                            (owner.to_owned(), ttl, RecordType::CNAME, target.to_owned())
                        })
                        .collect::<Vec<_>>();
                    expected.extend(addresses.map(|address| {
                        (
                            "nas.et.net.".to_owned(),
                            60,
                            record_type,
                            address.to_owned(),
                        )
                    }));
                    let response = query(&data, name, record_type).await;
                    let actual = response
                        .answers()
                        .iter()
                        .map(|record| {
                            (
                                record.name().to_string(),
                                record.ttl(),
                                record.record_type(),
                                record.data().to_string(),
                            )
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(actual, expected, "{name} {record_type}");
                }
            }
            assert_eq!(
                a(&data, "specific.et.net.").await,
                vec![Ipv4Addr::new(10, 0, 0, 99)]
            );
            assert_eq!(
                a(&data, "node-alias.et.net.").await,
                vec![Ipv4Inet::from_str(ip).unwrap().address()]
            );
            assert_eq!(
                a(&data, "node.et.net.").await,
                vec![Ipv4Inet::from_str(ip).unwrap().address()]
            );
        }
        let cname = query(&data, "chain.et.net.", RecordType::CNAME).await;
        assert_eq!(cname.answers().len(), 1);
        assert!(matches!(
            cname.answers()[0].data(),
            RData::CNAME(name) if name.0.to_string() == "alias.et.net."
        ));
        for name in ["missing.et.net.", "cycle.et.net."] {
            assert!(
                tokio::time::timeout(Duration::from_secs(1), a(&data, name))
                    .await
                    .unwrap()
                    .is_empty()
            );
        }
        assert!(matches!(
            query(&data, "nas.et.net.", RecordType::AAAA)
                .await
                .answers()[0]
                .data(),
            RData::AAAA(_)
        ));
        assert!(matches!(
            query(&data, "info.et.net.", RecordType::TXT)
                .await
                .answers()[0]
                .data(),
            RData::TXT(_)
        ));
        assert_eq!(
            query(&data, "nas.et.net.", RecordType::A).await.answers()[0].ttl(),
            60
        );
        // Disconnecting a client removes its node records, not the server's
        // statically configured ones.
        data.on_client_disconnected(controller(54001).get_tunnel_info().cloned())
            .await;
        assert!(
            query(&data, "node.et.net.", RecordType::A)
                .await
                .answers()
                .is_empty()
        );
        assert_eq!(
            a(&data, "nas.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 8), Ipv4Addr::new(10, 0, 0, 18)]
        );
        assert_eq!(
            a(&data, "cross.example.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 8), Ipv4Addr::new(10, 0, 0, 18)]
        );
        assert!(a(&data, "node-alias.et.net.").await.is_empty());
        assert!(
            data.dns_server
                .read_catalog()
                .await
                .contains(&"et.net.".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn configured_zones_with_distinct_origins_are_served() {
        let dns = config(&[
            ("et.net.", &[]),
            (
                "example.test.",
                &[record("svc", DnsRecordType::A, "10.0.0.9", None)],
            ),
        ]);
        let data = data_with(Some(&dns)).await;
        assert_eq!(
            a(&data, "svc.example.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 9)]
        );
        // Refreshing routes on the default zone must not drop static zones.
        data.update_dns_record(controller(54001), request("10.0.0.1/24"))
            .await
            .unwrap();
        assert_eq!(
            a(&data, "svc.example.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 9)]
        );
        assert_eq!(
            a(&data, "node.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 1)]
        );
    }

    #[tokio::test]
    async fn uppercase_zone_and_route_updates_preserve_node_records() {
        let data = data_with_default_zone("ET.NET.", None).await;
        for zone in ["ET.NET.", "et.net"] {
            let req = UpdateDnsRecordRequest {
                zone: zone.to_owned(),
                instance_id: "00000000-0000-0000-0000-000000000002".to_owned(),
                dns: Some(DnsConfig::default()),
                routes: vec![Route {
                    hostname: "node".to_owned(),
                    ipv4_addr: Some(Ipv4Inet::from_str("10.0.0.1/24").unwrap().into()),
                    ..Default::default()
                }],
            };
            data.update_dns_record(controller(54001), req)
                .await
                .unwrap();
            assert_eq!(
                a(&data, "node.et.net.").await,
                vec![Ipv4Addr::new(10, 0, 0, 1)]
            );
        }

        let dns = config(&[(
            "et.net",
            &[record("nas", DnsRecordType::A, "10.0.0.8", None)],
        )]);
        let data = data_with_default_zone("ET.NET.", Some(&dns)).await;
        let req = UpdateDnsRecordRequest {
            zone: "ET.NET".to_owned(),
            instance_id: "00000000-0000-0000-0000-000000000002".to_owned(),
            dns: Some(DnsConfig::default()),
            routes: vec![Route {
                hostname: "node".to_owned(),
                ipv4_addr: Some(Ipv4Inet::from_str("10.0.0.1/24").unwrap().into()),
                ..Default::default()
            }],
        };
        data.update_dns_record(controller(54001), req)
            .await
            .unwrap();
        assert_eq!(
            a(&data, "node.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 1)]
        );
        assert_eq!(
            a(&data, "nas.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 8)]
        );
    }

    #[tokio::test]
    async fn static_zones_are_loaded_during_init_before_any_rpc() {
        let dns = config(&[(
            "example.test.",
            &[record("svc", DnsRecordType::A, "10.0.0.9", None)],
        )]);
        let data = data_with(Some(&dns)).await;
        assert_eq!(
            a(&data, "svc.example.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 9)]
        );
    }

    #[tokio::test]
    async fn system_config_keeps_default_zone_first() {
        let dns = config(&[
            (
                "aaa.test.",
                &[record("@", DnsRecordType::A, "10.0.0.10", None)],
            ),
            ("et.net.", &[]),
        ]);
        let mut data = data_with(Some(&dns)).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        data.system_config = Some(Arc::new(SystemConfigSpy(calls.clone())));
        data.init_zones().await.unwrap();
        assert_eq!(
            *calls.lock().unwrap(),
            vec![(
                vec!["et.net.".to_owned()],
                vec!["et.net.".to_owned(), "aaa.test.".to_owned()]
            )]
        );
    }

    #[tokio::test]
    async fn invalid_local_configuration_is_rejected_before_startup() {
        for dns in [
            config(&[("", &[])]),
            config(&[(
                "example.test.",
                &[record("nas", DnsRecordType::A, "invalid", None)],
            )]),
            config(&[(
                "example.test.",
                &[record(
                    "outside.invalid.",
                    DnsRecordType::A,
                    "10.0.0.8",
                    None,
                )],
            )]),
            config(&[(
                "example.test.",
                &[record("nas", DnsRecordType::A, "$INCLUDE /etc/hosts", None)],
            )]),
        ] {
            assert!(easytier_core::gateway::magic_dns::configured_zones(Some(&dns)).is_err());
        }
        assert!(
            easytier_core::gateway::magic_dns::configured_zones(None)
                .unwrap()
                .is_empty()
        );
    }
    fn contribution(id: u128, dns: DnsConfig) -> UpdateDnsRecordRequest {
        UpdateDnsRecordRequest {
            zone: dns.domain.clone().unwrap_or_else(|| "et.net.".to_owned()),
            instance_id: uuid::Uuid::from_u128(id).to_string(),
            dns: Some(dns),
            routes: vec![],
        }
    }

    #[tokio::test]
    async fn released_dns_protocol_replaces_and_withdraws_connection_owned_routes() {
        use prost::Message as _;

        // v2.6.4 magic_dns.proto defines only these two request fields.
        #[derive(prost::Message)]
        struct ReleasedUpdateDnsRecordRequest {
            #[prost(string, tag = "1")]
            zone: String,
            #[prost(message, repeated, tag = "2")]
            routes: Vec<Route>,
        }

        let released_request = |hostname: &str, ip: Option<&str>| {
            let request = ReleasedUpdateDnsRecordRequest {
                zone: "et.net.".to_owned(),
                routes: ip
                    .into_iter()
                    .map(|ip| Route {
                        hostname: hostname.to_owned(),
                        ipv4_addr: Some(ip.parse::<Ipv4Inet>().unwrap().into()),
                        ..Default::default()
                    })
                    .collect(),
            };
            UpdateDnsRecordRequest::decode(request.encode_to_vec().as_slice()).unwrap()
        };
        let dns = config(&[(
            "configured.test",
            &[record("svc", DnsRecordType::A, "10.0.0.9", None)],
        )]);
        let data = data_with(Some(&dns)).await;
        for (port, hostname, ip) in [
            (54001, "old-a", "10.0.0.1/24"),
            (54002, "old-b", "10.0.0.2/24"),
        ] {
            data.update_dns_record(controller(port), released_request(hostname, Some(ip)))
                .await
                .unwrap();
        }
        let mut modern = request("10.0.0.3/24");
        modern.routes[0].hostname = "modern".to_owned();
        data.update_dns_record(controller(54003), modern.clone())
            .await
            .unwrap();
        data.update_dns_record(
            controller(54001),
            released_request("old-a", Some("10.0.0.4/24")),
        )
        .await
        .unwrap();
        assert_eq!(
            a(&data, "old-a.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 4)]
        );
        assert_eq!(
            a(&data, "old-b.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 2)]
        );
        assert_eq!(
            a(&data, "modern.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 3)]
        );
        data.update_dns_record(controller(54001), released_request("old-a", None))
            .await
            .unwrap();
        assert!(a(&data, "old-a.et.net.").await.is_empty());
        data.update_dns_record(
            controller(54001),
            released_request("old-a", Some("10.0.0.5/24")),
        )
        .await
        .unwrap();
        data.on_client_disconnected(controller(54001).get_tunnel_info().cloned())
            .await;
        assert!(a(&data, "old-a.et.net.").await.is_empty());
        assert_eq!(
            a(&data, "old-b.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 2)]
        );
        // Reconnecting uses a new connection-owned contribution.
        data.update_dns_record(
            controller(54004),
            released_request("old-a", Some("10.0.0.6/24")),
        )
        .await
        .unwrap();
        data.on_client_disconnected(controller(54001).get_tunnel_info().cloned())
            .await;
        assert_eq!(
            a(&data, "old-a.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 6)]
        );
        modern.instance_id = "invalid-uuid".to_owned();
        assert!(
            data.update_dns_record(controller(54003), modern)
                .await
                .is_err()
        );
        assert_eq!(
            a(&data, "modern.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 3)]
        );
        assert_eq!(
            a(&data, "svc.configured.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 9)]
        );
    }

    #[tokio::test]
    async fn different_zones_replace_clear_and_disconnect_independently() {
        let data = data_with(None).await;
        let first = config(&[(
            "first.test",
            &[record("svc", DnsRecordType::A, "10.0.0.1", None)],
        )]);
        let second = config(&[(
            "second.test",
            &[
                record("svc", DnsRecordType::A, "10.0.0.2", None),
                record("cross", DnsRecordType::Cname, "svc.first.test.", None),
            ],
        )]);
        data.update_dns_record(controller(54001), contribution(2, first))
            .await
            .unwrap();
        data.update_dns_record(controller(54002), contribution(3, second))
            .await
            .unwrap();
        assert_eq!(
            a(&data, "cross.second.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 1)]
        );
        let changed = config(&[(
            "FIRST.test.",
            &[record("svc", DnsRecordType::A, "10.0.0.9", None)],
        )]);
        data.update_dns_record(controller(54001), contribution(2, changed))
            .await
            .unwrap();
        assert_eq!(
            a(&data, "cross.second.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 9)]
        );
        data.update_dns_record(controller(54001), contribution(2, config(&[])))
            .await
            .unwrap();
        assert!(
            !data
                .dns_server
                .local_origins()
                .await
                .contains(&"first.test.".parse().unwrap())
        );
        assert_eq!(
            a(&data, "svc.second.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 2)]
        );
        data.on_client_disconnected(controller(54002).get_tunnel_info().cloned())
            .await;
        assert!(
            !data
                .dns_server
                .local_origins()
                .await
                .contains(&"second.test.".parse().unwrap())
        );
        // A new publishing connection can contribute the withdrawn origins.
        data.update_dns_record(
            controller(54003),
            contribution(3, config(&[("second.test", &[])])),
        )
        .await
        .unwrap();
        assert!(
            data.dns_server
                .local_origins()
                .await
                .contains(&"second.test.".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn same_zone_records_replace_clear_and_disconnect_independently() {
        let mut data = data_with(None).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        data.system_config = Some(Arc::new(SystemConfigSpy(calls.clone())));
        data.init_zones().await.unwrap();
        let first = config(&[(
            "shared.test",
            &[
                record("svc", DnsRecordType::A, "10.0.0.1", None),
                record("svc", DnsRecordType::A, "10.0.0.2", None),
                record("svc", DnsRecordType::Aaaa, "fd00::1", None),
                record("svc", DnsRecordType::Aaaa, "fd00::2", None),
                record("first", DnsRecordType::A, "10.0.0.10", None),
            ],
        )]);
        let second = config(&[(
            "SHARED.test.",
            &[
                record("svc", DnsRecordType::A, "10.0.0.2", None),
                record("svc", DnsRecordType::A, "10.0.0.3", None),
                record("svc", DnsRecordType::Aaaa, "fd00::2", None),
                record("svc", DnsRecordType::Aaaa, "fd00::3", None),
                record("second", DnsRecordType::A, "10.0.0.20", None),
            ],
        )]);
        data.update_dns_record(controller(54001), contribution(2, first.clone()))
            .await
            .unwrap();
        data.update_dns_record(controller(54002), contribution(3, second))
            .await
            .unwrap();
        assert_eq!(
            a(&data, "svc.shared.test.").await,
            ["10.0.0.1", "10.0.0.2", "10.0.0.3"].map(|ip| ip.parse::<Ipv4Addr>().unwrap())
        );
        let response = query(&data, "svc.shared.test.", RecordType::AAAA).await;
        let mut values = response
            .answers()
            .iter()
            .map(|record| {
                assert_eq!(record.ttl(), 60);
                record.data().to_string()
            })
            .collect::<Vec<_>>();
        values.sort();
        assert_eq!(values, ["fd00::1", "fd00::2", "fd00::3"]);
        assert_eq!(a(&data, "first.shared.test.").await.len(), 1);
        assert_eq!(a(&data, "second.shared.test.").await.len(), 1);
        // A second publisher of the same origin needs no extra OS domain.
        assert_eq!(calls.lock().unwrap().len(), 2);

        data.update_dns_record(
            controller(54001),
            contribution(
                2,
                config(&[(
                    "shared.test",
                    &[record("svc", DnsRecordType::A, "10.0.0.4", None)],
                )]),
            ),
        )
        .await
        .unwrap();
        assert_eq!(
            a(&data, "svc.shared.test.").await,
            ["10.0.0.2", "10.0.0.3", "10.0.0.4"].map(|ip| ip.parse::<Ipv4Addr>().unwrap())
        );
        assert!(a(&data, "first.shared.test.").await.is_empty());
        data.update_dns_record(controller(54001), contribution(2, config(&[])))
            .await
            .unwrap();
        assert_eq!(
            a(&data, "svc.shared.test.").await,
            ["10.0.0.2", "10.0.0.3"].map(|ip| ip.parse::<Ipv4Addr>().unwrap())
        );
        data.update_dns_record(controller(54001), contribution(2, first))
            .await
            .unwrap();
        data.on_client_disconnected(controller(54002).get_tunnel_info().cloned())
            .await;
        assert_eq!(
            a(&data, "svc.shared.test.").await,
            ["10.0.0.1", "10.0.0.2"].map(|ip| ip.parse::<Ipv4Addr>().unwrap())
        );
        assert!(a(&data, "second.shared.test.").await.is_empty());
        assert_eq!(calls.lock().unwrap().len(), 2);
        data.on_client_disconnected(controller(54001).get_tunnel_info().cloned())
            .await;
        assert!(
            !data
                .dns_server
                .local_origins()
                .await
                .contains(&"shared.test.".parse().unwrap())
        );
        assert_eq!(calls.lock().unwrap().last().unwrap().1, ["et.net."]);
    }

    #[tokio::test]
    async fn same_zone_other_types_merge_and_singletons_deduplicate() {
        let shared = [
            record("alias", DnsRecordType::Cname, "target", None),
            record("aname", DnsRecordType::Aname, "target", None),
            record("@", DnsRecordType::Soa, "ns hostmaster 1 2 3 4 5", None),
        ];
        let first = [
            shared.as_slice(),
            &[
                record("target", DnsRecordType::A, "10.0.0.1", None),
                record("info", DnsRecordType::Txt, "\"one\"", None),
                record("mail", DnsRecordType::Mx, "10 mail-a", None),
                record("_svc._tcp", DnsRecordType::Srv, "10 5 443 host-a", None),
                record("https", DnsRecordType::Https, "1 host-a port=443", None),
            ],
        ]
        .concat();
        let mut second = [
            shared.as_slice(),
            &[
                record("target", DnsRecordType::A, "10.0.0.2", None),
                record("info", DnsRecordType::Txt, "\"one\"", None),
                record("info", DnsRecordType::Txt, "\"two\"", None),
                record("mail", DnsRecordType::Mx, "20 mail-b", None),
                record("_svc._tcp", DnsRecordType::Srv, "20 5 443 host-b", None),
                record("https", DnsRecordType::Https, "2 host-b port=443", None),
            ],
        ]
        .concat();
        // Equivalent absolute targets must deduplicate with relative input.
        second[0].value = Some("TARGET.shared.test.".to_owned());
        second[1].value = Some("TARGET.shared.test.".to_owned());
        second[2].value = Some("NS.shared.test. HOSTMASTER.shared.test. 1 2 3 4 5".to_owned());
        let data = data_with(Some(&config(&[("shared.test", &first)]))).await;
        data.update_dns_record(
            controller(54001),
            contribution(2, config(&[("shared.test", &second)])),
        )
        .await
        .unwrap();
        for (name, kind, count) in [
            ("target", RecordType::A, 2),
            ("alias", RecordType::CNAME, 1),
            ("aname", RecordType::ANAME, 1),
            ("shared.test", RecordType::SOA, 1),
            ("info", RecordType::TXT, 2),
            ("mail", RecordType::MX, 2),
            ("_svc._tcp", RecordType::SRV, 2),
            ("https", RecordType::HTTPS, 2),
        ] {
            let name = if kind == RecordType::SOA {
                format!("{name}.")
            } else {
                format!("{name}.shared.test.")
            };
            let response = query(&data, &name, kind).await;
            assert_eq!(response.answers().len(), count, "{name} {kind}");
            let values = response
                .answers()
                .iter()
                .map(|record| {
                    assert_eq!(record.record_type(), kind);
                    assert_eq!(record.ttl(), 60);
                    record.data().to_string()
                })
                .collect::<BTreeSet<_>>();
            assert_eq!(values.len(), count, "{name} {kind}");
        }
        assert_eq!(
            a(&data, "alias.shared.test.").await,
            ["10.0.0.1", "10.0.0.2"].map(|ip| ip.parse::<Ipv4Addr>().unwrap())
        );
    }

    #[tokio::test]
    async fn same_zone_static_and_automatic_a_records_keep_configured_ttl() {
        for ttl in [0, 60] {
            let dns = |value| {
                config(&[(
                    "et.net",
                    &[record("node", DnsRecordType::A, value, Some(ttl))],
                )])
            };
            let data = data_with(Some(&dns("10.0.0.8"))).await;
            let mut update = request("10.0.0.8/24");
            update.dns = Some(dns("10.0.0.9"));
            data.update_dns_record(controller(54001), update)
                .await
                .unwrap();
            let mut automatic = request("10.0.0.10/24");
            automatic.instance_id = uuid::Uuid::from_u128(3).to_string();
            data.update_dns_record(controller(54002), automatic)
                .await
                .unwrap();
            assert_eq!(
                a(&data, "node.et.net.").await,
                ["10.0.0.8", "10.0.0.9", "10.0.0.10"].map(|ip| ip.parse::<Ipv4Addr>().unwrap())
            );
            data.update_dns_record(controller(54003), contribution(1, config(&[])))
                .await
                .unwrap();
            for answer in query(&data, "node.et.net.", RecordType::A).await.answers() {
                assert_eq!(answer.ttl(), ttl);
            }
            // Clearing the final static contribution keeps automatic values
            // and restores their TTL instead of retaining the static TTL.
            data.update_dns_record(controller(54001), request("10.0.0.8/24"))
                .await
                .unwrap();
            assert_eq!(
                a(&data, "node.et.net.").await,
                ["10.0.0.8", "10.0.0.10"].map(|ip| ip.parse::<Ipv4Addr>().unwrap())
            );
            for answer in query(&data, "node.et.net.", RecordType::A).await.answers() {
                assert_eq!(answer.ttl(), 1);
            }
            data.on_client_disconnected(controller(54001).get_tunnel_info().cloned())
                .await;
            assert_eq!(
                a(&data, "node.et.net.").await,
                ["10.0.0.10".parse::<Ipv4Addr>().unwrap()]
            );
            let accepted = data.route_store.snapshot().clients;
            let error = data
                .update_dns_record(
                    controller(54003),
                    contribution(
                        1,
                        config(&[(
                            "et.net",
                            &[record("node", DnsRecordType::Cname, "target", None)],
                        )]),
                    ),
                )
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("automatic DNS record"),
                "{error}"
            );
            assert_eq!(data.route_store.snapshot().clients, accepted);
        }
    }

    #[tokio::test]
    async fn incompatible_same_zone_records_reject_the_complete_update() {
        let dns = config(&[(
            "shared.test",
            &[
                record("svc", DnsRecordType::A, "10.0.0.1", None),
                record("alias", DnsRecordType::Cname, "svc", None),
                record("aname", DnsRecordType::Aname, "svc", None),
                record("@", DnsRecordType::Soa, "ns hostmaster 1 2 3 4 5", None),
            ],
        )]);
        let mut data = data_with(Some(&dns)).await;
        let previous = config(&[(
            "previous.test",
            &[record("svc", DnsRecordType::A, "10.0.0.2", None)],
        )]);
        data.update_dns_record(controller(54001), contribution(2, previous))
            .await
            .unwrap();
        let calls = Arc::new(Mutex::new(Vec::new()));
        data.system_config = Some(Arc::new(SystemConfigSpy(calls.clone())));
        data.init_zones().await.unwrap();
        let accepted = data.route_store.snapshot().clients;
        for (conflict, message) in [
            (
                record("svc", DnsRecordType::A, "10.0.0.3", Some(61)),
                "RRset TTLs must match",
            ),
            (
                record("svc", DnsRecordType::A, "10.0.0.1", Some(0)),
                "RRset TTLs must match",
            ),
            (
                record("svc", DnsRecordType::Cname, "target", None),
                "CNAME cannot coexist",
            ),
            (
                record("alias", DnsRecordType::A, "10.0.0.3", None),
                "CNAME cannot coexist",
            ),
            (
                record("alias", DnsRecordType::Cname, "other", None),
                "CNAME permits only one value",
            ),
            (
                record("aname", DnsRecordType::Aname, "other", None),
                "ANAME permits only one value",
            ),
            (
                record("@", DnsRecordType::Soa, "ns hostmaster 2 2 3 4 5", None),
                "SOA permits only one value",
            ),
            (
                record("svc", DnsRecordType::A, "invalid address", None),
                "value",
            ),
        ] {
            let rejected = config(&[
                ("SHARED.test.", &[conflict]),
                (
                    "candidate.test",
                    &[record("fresh", DnsRecordType::A, "10.0.0.99", None)],
                ),
            ]);
            let mut update = request("10.0.0.99/24");
            update.dns = Some(rejected);
            let error = data
                .update_dns_record(controller(54001), update)
                .await
                .unwrap_err();
            assert!(error.to_string().contains(message), "{error}");
            assert_eq!(data.route_store.snapshot().clients, accepted);
            assert_eq!(
                a(&data, "svc.shared.test.").await,
                ["10.0.0.1".parse::<Ipv4Addr>().unwrap()]
            );
            assert_eq!(
                a(&data, "svc.previous.test.").await,
                ["10.0.0.2".parse::<Ipv4Addr>().unwrap()]
            );
            assert!(a(&data, "node.et.net.").await.is_empty());
            assert!(
                !data
                    .dns_server
                    .local_origins()
                    .await
                    .contains(&"candidate.test.".parse().unwrap())
            );
            assert_eq!(calls.lock().unwrap().len(), 1);
        }
    }

    #[tokio::test]
    async fn automatic_routes_deduplicate_across_publishers() {
        let data = data_with(None).await;
        // Automatic routes still aggregate and deduplicate in their shared zone.
        for (port, id) in [(54001, 2), (54002, 3)] {
            let mut update = request("10.0.0.8/24");
            update.instance_id = uuid::Uuid::from_u128(id).to_string();
            data.update_dns_record(controller(port), update)
                .await
                .unwrap();
        }
        assert_eq!(
            a(&data, "node.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 8)]
        );
    }

    #[tokio::test]
    async fn unchanged_contribution_keeps_authority_but_ttl_and_system_domains_apply() {
        let dns = config(&[(
            "shared.test",
            &[record("svc", DnsRecordType::A, "10.0.0.1", None)],
        )]);
        let mut data = data_with(Some(&dns)).await;
        let origin = "shared.test.".parse().unwrap();
        let initial = data.dns_server.read_catalog().await.find(&origin).unwrap()[0].clone();
        let request = contribution(1, dns.clone());
        data.update_dns_record(controller(54001), request.clone())
            .await
            .unwrap();
        let accepted = data.dns_server.read_catalog().await.find(&origin).unwrap()[0].clone();
        // The publishing connection must take over the initialized owner.
        assert!(!Arc::ptr_eq(&initial, &accepted));
        for _ in 0..3 {
            data.update_dns_record(controller(54001), request.clone())
                .await
                .unwrap();
            assert!(Arc::ptr_eq(
                &accepted,
                &data.dns_server.read_catalog().await.find(&origin).unwrap()[0]
            ));
        }
        data.on_client_disconnected(controller(54003).get_tunnel_info().cloned())
            .await;
        assert!(Arc::ptr_eq(
            &accepted,
            &data.dns_server.read_catalog().await.find(&origin).unwrap()[0]
        ));

        let mut changed = dns;
        changed.zone.as_mut().unwrap().items[0].ttl = Some(43);
        let changed = contribution(1, changed);
        data.update_dns_record(controller(54001), changed.clone())
            .await
            .unwrap();
        assert_eq!(
            query(&data, "svc.shared.test.", RecordType::A)
                .await
                .answers()[0]
                .ttl(),
            43
        );
        let calls = Arc::new(Mutex::new(Vec::new()));
        data.system_config = Some(Arc::new(SystemConfigSpy(calls.clone())));
        // An unchanged contribution cannot skip an unconfirmed system write.
        data.update_dns_record(controller(54001), changed.clone())
            .await
            .unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        data.update_dns_record(controller(54001), changed.clone())
            .await
            .unwrap();
        assert_eq!(calls.lock().unwrap().len(), 1);
        data.closing
            .store(true, std::sync::atomic::Ordering::Release);
        assert!(
            data.update_dns_record(controller(54001), changed)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn slow_packet_query_does_not_block_contribution_changes() {
        use hickory_proto::op::{MessageType, ResponseCode};
        use tokio::net::UdpSocket;

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut data = data_with(None).await;
        data.dns_server =
            super::super::server::tests::forwarding_server(upstream.local_addr().unwrap())
                .await
                .unwrap();
        data.init_zones().await.unwrap();
        let data = Arc::new(data);
        let forwarding = {
            let data = data.clone();
            tokio::spawn(async move { query(&data, "slow.example.org.", RecordType::A).await })
        };
        let mut packet = [0; 4096];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(1), upstream.recv_from(&mut packet))
                .await
                .unwrap()
                .unwrap();

        tokio::time::timeout(Duration::from_secs(1), async {
            for (ip, ttl) in [("10.0.0.1", 60), ("10.0.0.2", 60), ("10.0.0.2", 42)] {
                let record = record("svc", DnsRecordType::A, ip, None);
                let mut dns = config(&[("et.net", &[record])]);
                dns.zone.as_mut().unwrap().items[0].ttl = Some(ttl);
                data.update_dns_record(controller(54001), contribution(2, dns))
                    .await
                    .unwrap();
                let response = query(&data, "svc.et.net.", RecordType::A).await;
                assert_eq!(response.answers()[0].ttl(), ttl);
                assert_eq!(
                    a(&data, "svc.et.net.").await,
                    vec![ip.parse::<Ipv4Addr>().unwrap()]
                );
            }
            data.update_dns_record(controller(54001), contribution(2, config(&[])))
                .await
                .unwrap();
            assert!(
                query(&data, "svc.et.net.", RecordType::A)
                    .await
                    .answers()
                    .is_empty()
            );
            assert!(!forwarding.is_finished());
        })
        .await
        .unwrap();

        let mut response = Message::from_vec(&packet[..length]).unwrap();
        response
            .set_message_type(MessageType::Response)
            .set_response_code(ResponseCode::NXDomain);
        upstream
            .send_to(&response.to_vec().unwrap(), source)
            .await
            .unwrap();
        assert_eq!(
            forwarding.await.unwrap().response_code(),
            ResponseCode::NXDomain
        );
    }

    struct FailingSystemConfig;
    impl SystemConfig for FailingSystemConfig {
        fn set_dns(&self, _: &OSConfig) -> io::Result<()> {
            Err(io::Error::other("injected OS failure"))
        }
        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn system_domain_union_updates_and_failure_preserves_records() {
        use hickory_proto::op::ResponseCode;

        let mut data = data_with(None).await;
        let calls = Arc::new(Mutex::new(Vec::new()));
        data.system_config = Some(Arc::new(SystemConfigSpy(calls.clone())));
        data.init_zones().await.unwrap();
        let mut dns = config(&[(
            "new.test",
            &[record("svc", DnsRecordType::A, "10.0.0.8", None)],
        )]);
        dns.domain = Some("second.test".to_owned());
        data.update_dns_record(controller(54001), contribution(2, dns.clone()))
            .await
            .unwrap();
        assert_eq!(
            calls.lock().unwrap().last().unwrap().1,
            vec!["et.net.", "new.test.", "second.test."]
        );
        data.system_config = Some(Arc::new(FailingSystemConfig));
        dns.zone.as_mut().unwrap().items[0].origin = "rejected.test".to_owned();
        assert!(
            data.update_dns_record(controller(54001), contribution(2, dns))
                .await
                .is_err()
        );
        assert_eq!(
            a(&data, "svc.new.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 8)]
        );
        assert!(
            data.dns_server
                .read_catalog()
                .await
                .contains(&"rejected.test.".parse().unwrap())
        );
        assert_eq!(
            query(&data, "svc.rejected.test.", RecordType::A)
                .await
                .response_code(),
            ResponseCode::NXDomain
        );
        data.on_client_disconnected(controller(54001).get_tunnel_info().cloned())
            .await;
        assert!(
            data.dns_server
                .read_catalog()
                .await
                .contains(&"new.test.".parse().unwrap())
        );
        assert_eq!(
            query(&data, "svc.new.test.", RecordType::A)
                .await
                .response_code(),
            ResponseCode::NXDomain
        );
        data.system_config = Some(Arc::new(SystemConfigSpy(calls.clone())));
        data.init_zones().await.unwrap();
        assert_eq!(calls.lock().unwrap().last().unwrap().1, vec!["et.net."]);
        assert!(data.system_dns_guards.lock().unwrap().is_empty());
        for origin in ["new.test.", "rejected.test."] {
            assert!(
                !data
                    .dns_server
                    .local_origins()
                    .await
                    .contains(&origin.parse().unwrap())
            );
        }
        let configured = calls.lock().unwrap().len();
        data.init_zones().await.unwrap();
        assert_eq!(calls.lock().unwrap().len(), configured);
    }

    struct BlockingSystemConfig {
        entered: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
        fail: bool,
    }

    impl SystemConfig for BlockingSystemConfig {
        fn set_dns(&self, _: &OSConfig) -> io::Result<()> {
            if let Some(entered) = self.entered.lock().unwrap().take() {
                let _ = entered.send(());
                self.release.lock().unwrap().recv().unwrap();
            }
            if self.fail {
                Err(io::Error::other("injected partial OS failure"))
            } else {
                Ok(())
            }
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn new_domain_guards_preserve_parent_and_child_authorities_until_retry() {
        use hickory_proto::op::ResponseCode;
        use tokio::net::UdpSocket;

        let upstream = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut data = data_with(Some(&config(&[
            (
                "parent.test",
                &[record("keep.child", DnsRecordType::A, "10.0.0.1", None)],
            ),
            (
                "known.outside.test",
                &[record("svc", DnsRecordType::A, "10.0.0.2", None)],
            ),
        ])))
        .await;
        data.dns_server =
            super::super::server::tests::forwarding_server(upstream.local_addr().unwrap())
                .await
                .unwrap();
        data.init_zones().await.unwrap();
        let previous = data.route_store.snapshot().clients;
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        data.system_config = Some(Arc::new(BlockingSystemConfig {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(blocked),
            fail: true,
        }));
        let proposed = config(&[
            (
                "child.parent.test",
                &[record("new", DnsRecordType::A, "10.0.0.3", None)],
            ),
            (
                "outside.test",
                &[record("new", DnsRecordType::A, "10.0.0.4", None)],
            ),
            (
                "fresh.test",
                &[record("new", DnsRecordType::A, "10.0.0.5", None)],
            ),
        ]);
        let data = Arc::new(data);
        let updating = data.clone();
        let request = contribution(2, proposed.clone());
        let task =
            tokio::spawn(
                async move { updating.update_dns_record(controller(54001), request).await },
            );
        started.await.unwrap();
        // Collect results before asserting so a regression cannot leave the
        // injected blocking OS call waiting during runtime shutdown.
        let parent =
            tokio::time::timeout(Duration::from_secs(1), a(&data, "keep.child.parent.test.")).await;
        let child =
            tokio::time::timeout(Duration::from_secs(1), a(&data, "svc.known.outside.test.")).await;
        let guarded = tokio::time::timeout(
            Duration::from_secs(1),
            query(&data, "new.fresh.test.", RecordType::A),
        )
        .await;
        release.send(()).unwrap();
        assert!(task.await.unwrap().is_err());
        assert_eq!(parent.unwrap(), ["10.0.0.1".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(child.unwrap(), ["10.0.0.2".parse::<Ipv4Addr>().unwrap()]);
        assert_eq!(guarded.unwrap().response_code(), ResponseCode::NXDomain);
        assert_eq!(data.route_store.snapshot().clients, previous);
        assert!(
            !data
                .dns_server
                .local_origins()
                .await
                .contains(&"child.parent.test.".parse().unwrap())
        );
        assert_eq!(
            query(&data, "new.outside.test.", RecordType::A)
                .await
                .response_code(),
            ResponseCode::NXDomain
        );
        let mut packet = [0; 4096];
        assert_eq!(
            upstream.try_recv_from(&mut packet).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        let mut data = Arc::try_unwrap(data).ok().unwrap();
        data.system_config = Some(Arc::new(SystemConfigSpy(Arc::default())));
        data.update_dns_record(controller(54001), contribution(2, proposed))
            .await
            .unwrap();
        assert!(data.system_dns_guards.lock().unwrap().is_empty());
        assert_eq!(
            a(&data, "new.fresh.test.").await,
            ["10.0.0.5".parse::<Ipv4Addr>().unwrap()]
        );
        data.update_dns_record(controller(54001), contribution(2, config(&[])))
            .await
            .unwrap();
        assert_eq!(
            a(&data, "svc.known.outside.test.").await,
            ["10.0.0.2".parse::<Ipv4Addr>().unwrap()]
        );
        for origin in ["fresh.test.", "outside.test.", "child.parent.test."] {
            assert!(
                !data
                    .dns_server
                    .local_origins()
                    .await
                    .contains(&origin.parse().unwrap())
            );
        }
    }

    #[tokio::test]
    async fn cancelled_application_keeps_system_write_serialized() {
        let mut data = data_with(None).await;
        let (entered, started) = tokio::sync::oneshot::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        data.system_config = Some(Arc::new(BlockingSystemConfig {
            entered: Mutex::new(Some(entered)),
            release: Mutex::new(blocked),
            fail: false,
        }));
        let data = Arc::new(data);
        let updating = data.clone();
        let task = tokio::spawn(async move {
            updating
                .update_dns_record(
                    controller(54001),
                    contribution(
                        2,
                        config(&[(
                            "cancelled.test",
                            &[record("svc", DnsRecordType::A, "10.0.0.1", None)],
                        )]),
                    ),
                )
                .await
        });
        started.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        // The aborted RPC must not release application ownership while its
        // blocking OS call is still running.
        assert!(data.record_apply.try_lock().is_err());
        release.send(()).unwrap();
        data.update_dns_record(
            controller(54002),
            contribution(
                3,
                config(&[(
                    "accepted.test",
                    &[record("svc", DnsRecordType::A, "10.0.0.2", None)],
                )]),
            ),
        )
        .await
        .unwrap();
        assert!(
            !data
                .dns_server
                .read_catalog()
                .await
                .contains(&"cancelled.test.".parse().unwrap())
        );
        assert_eq!(
            a(&data, "svc.accepted.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 2)]
        );
    }
}
