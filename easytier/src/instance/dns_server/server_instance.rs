// single-instance server in one machine, every easytier instance that has ip address and tun device will try to create a server instance.

// magic dns client will connect to this server to update the dns records.
// magic dns server will add the dns server ip address to the tun device, and forward the dns request to the dns server

// magic dns client will establish a long live tcp connection to the magic dns server, and when the server stops or crashes,
// all the clients will exit and let the easytier instance to launch a new server instance.

use super::{
    MAGIC_DNS_INSTANCE_SOCKET_ADDR,
    config::{GeneralConfigBuilder, RunConfigBuilder},
    server::Server,
    system_config::{OSConfig, SystemConfig},
    zone::{self, ZoneGroup},
};
use crate::{
    common::{
        error::Error as EtError,
        global_ctx::ArcGlobalCtx,
        ifcfg::{IfConfiger, IfConfiguerTrait},
        netns::NetNS,
    },
    instance::dns_server::{
        config::{Record, RecordBuilder, RecordType},
        server::build_authority,
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
use easytier_core::gateway::magic_dns::{
    MagicDnsQuery, MagicDnsQueryResolver, MagicDnsRecordStore, MagicDnsResolverRegistration,
    MagicDnsRoute,
};
use easytier_core::instance::CorePacketPlane;
use hickory_proto::rr::LowerName;
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::authority::{MessageRequest, MessageResponse};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::Ipv4Addr,
    sync::Arc,
    time::Duration,
};

pub(super) struct MagicDnsServerInstanceData {
    pub(super) dns_server: Server,
    tun_dev: Option<String>,
    net_ns: NetNS,
    fake_ip: Ipv4Addr,
    manage_fake_ip_route: bool,
    route_store: MagicDnsRecordStore,
    record_apply: tokio::sync::Mutex<()>,
    default_zone: LowerName,
    /// Static records from this instance's local configuration, grouped once
    /// at startup and merged into every refresh of the matching zone.
    configured: BTreeMap<LowerName, ZoneGroup>,

    system_config: Option<Box<dyn SystemConfig>>,
}

impl MagicDnsServerInstanceData {
    pub async fn update_dns_records<'a, T: Iterator<Item = &'a MagicDnsRoute>>(
        &self,
        routes: T,
        zone: &LowerName,
    ) -> Result<(), anyhow::Error> {
        let mut records: Vec<Record> = vec![];
        for route in routes {
            if route.hostname.is_empty() {
                continue;
            }

            let Some(ipv4_addr) = route.ipv4_addr else {
                continue;
            };

            let record = RecordBuilder::default()
                .rr_type(RecordType::A)
                .name(format!("{}.{}", route.hostname, zone))
                .value(ipv4_addr.to_string())
                .ttl(Duration::from_secs(1))
                .build()?;

            // check record name valid for dns
            if let Err(e) = record.name() {
                tracing::error!("Invalid subdomain label: {}", e);
                continue;
            }

            records.push(record);
        }

        let soa_record = RecordBuilder::default()
            .rr_type(RecordType::SOA)
            .name(zone.to_string())
            .value(format!(
                "ns.{} hostmaster.{} 2023101001 7200 3600 1209600 86400",
                zone, zone
            ))
            .ttl(Duration::from_secs(60))
            .build()?;
        records.push(soa_record);

        let mut authority = build_authority(zone, &records)?;
        if let Some(group) = self.configured.get(zone) {
            group.extend_authority(&mut authority);
        }

        self.dns_server
            .upsert(zone.clone(), Arc::new(authority))
            .await;

        tracing::debug!("Updated DNS records for zone {}: {:?}", zone, records);

        Ok(())
    }

    pub async fn update(&self) -> Result<(), anyhow::Error> {
        let snapshot = self.route_store.snapshot();
        // Route zones from connected clients, plus the default zone and any
        // statically configured origins, must all stay authoritative.
        let mut zones: BTreeSet<LowerName> = snapshot.zones.keys().cloned().collect();
        zones.insert(self.default_zone.clone());
        zones.extend(self.configured.keys().cloned());
        let mut first_err = None;
        for zone in zones {
            let routes = snapshot.zones.get(&zone).into_iter().flatten();
            if let Err(e) = self.update_dns_records(routes, &zone).await {
                tracing::error!("Failed to update DNS records for zone {}: {:?}", zone, e);
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        first_err.map_or(Ok(()), Err)
    }

    /// Initializes the default zone and all configured static zones before
    /// queries are accepted.
    pub async fn init_zones(&self) -> Result<(), anyhow::Error> {
        let _apply = self.record_apply.lock().await;
        self.update().await
    }

    async fn keep_zone_authoritative(&self, zone: &LowerName) {
        if let Err(e) = self
            .update_dns_records(std::iter::empty::<&MagicDnsRoute>(), zone)
            .await
        {
            tracing::error!(
                "Failed to keep DNS zone {} authoritative after route prune: {:?}",
                zone,
                e
            );
        }
    }

    fn do_system_config(&self) -> Result<(), anyhow::Error> {
        if let Some(c) = &self.system_config {
            // The default zone goes first: Windows uses this list as the
            // adapter's search list, so short names must prefer the default
            // suffix.
            let default_zone = self.default_zone.to_string();
            let mut domains = vec![default_zone.clone()];
            domains.extend(
                self.configured
                    .keys()
                    .filter(|&origin| origin != &self.default_zone)
                    .map(ToString::to_string),
            );
            c.set_dns(&OSConfig {
                nameservers: vec![self.fake_ip.to_string()],
                search_domains: vec![default_zone],
                match_domains: domains,
            })?;
        }
        Ok(())
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
        Ok(Default::default())
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
        let _apply = self.record_apply.lock().await;
        let remote_addr: url::Url = remote_addr.clone().into();
        let routes = input
            .routes
            .into_iter()
            .map(|route| MagicDnsRoute {
                hostname: route.hostname,
                ipv4_addr: route.ipv4_addr.unwrap_or_default().address.map(Into::into),
            })
            .collect();
        let zone_removed =
            self.route_store
                .replace_client_routes(zone.clone(), remote_addr.to_string(), routes);

        if zone_removed {
            self.keep_zone_authoritative(&zone).await;
        }

        let _ = self.update().await;
        Ok(Default::default())
    }

    async fn get_dns_record(
        &self,
        _ctrl: Self::Controller,
        _input: Void,
    ) -> crate::proto::rpc_types::error::Result<GetDnsRecordResponse> {
        let mut ret = BTreeMap::new();
        for (zone, routes) in self.route_store.snapshot().zones {
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
            .read_catalog()
            .await
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
        let _apply = self.record_apply.lock().await;
        let remote_addr: url::Url = remote_addr.into();
        for zone in self.route_store.remove_client(remote_addr.as_ref()) {
            self.keep_zone_authoritative(&zone).await;
        }
        let _ = self.update().await;
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
) -> Result<Option<Box<dyn SystemConfig>>, anyhow::Error> {
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
        let configured = zone::configured_zones(global_ctx.config.get_dns().as_ref())
            .context("Invalid local DNS configuration")?;

        let tcp_listener = runtime_rpc_listener(MAGIC_DNS_INSTANCE_SOCKET_ADDR.parse()?);
        let mut rpc_server = StandAloneServer::new(tcp_listener);
        rpc_server.serve().await?;

        let dns_config = RunConfigBuilder::default()
            .general(GeneralConfigBuilder::default().build()?)
            .excluded_forward_nameservers(vec![fake_ip.into()])
            .build()?;
        let mut dns_server = Server::new(dns_config);
        dns_server.run().await?;

        if manage_fake_ip_route
            && !tun_inet.contains(&fake_ip)
            && let Some(tun_dev_name) = &tun_dev
        {
            let cost = if cfg!(target_os = "windows") {
                Some(4)
            } else {
                None
            };
            Self::add_fake_ip_route(tun_dev_name, fake_ip, &global_ctx.net_ns, cost).await?;
        }

        let data = Arc::new(MagicDnsServerInstanceData {
            dns_server,
            tun_dev: tun_dev.clone(),
            net_ns: global_ctx.net_ns.clone(),
            fake_ip,
            manage_fake_ip_route,
            route_store: MagicDnsRecordStore::default(),
            record_apply: tokio::sync::Mutex::new(()),
            default_zone: default_zone.clone(),
            configured,
            system_config: get_system_config(tun_dev.as_deref())?,
        });

        rpc_server
            .registry()
            .register(MagicDnsServerRpcServer::new_arc(data.clone()), "");
        rpc_server.set_hook(data.clone());

        data.init_zones()
            .await
            .context("Failed to initialize DNS zones")?;

        let data_clone = data.clone();
        tokio::task::spawn_blocking(move || data_clone.do_system_config())
            .await
            .context("Failed to configure system")??;

        // Install the resolver only after all fallible initialization has
        // completed, so construction failure cannot leave a managed pipeline
        // registration that never reaches async cleanup.
        let packet_filter = packet_plane
            .register_magic_dns_resolver(fake_ip, data.clone())
            .await;

        Ok(Self {
            _rpc_server: rpc_server,
            data,
            packet_filter,
            tun_inet,
        })
    }

    pub async fn clean_env(&self) {
        if let Some(configer) = &self.data.system_config {
            let ret = configer.close();
            if let Err(e) = ret {
                tracing::error!("Failed to close system config: {:?}", e);
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

    type DomainConfigRecord = (Vec<String>, Vec<String>);
    type DomainConfigSpyCalls = Arc<Mutex<Vec<DomainConfigRecord>>>;

    struct SystemConfigSpy(DomainConfigSpyCalls);

    impl SystemConfig for SystemConfigSpy {
        fn set_dns(&self, config: &OSConfig) -> io::Result<()> {
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
            route_store: MagicDnsRecordStore::default(),
            record_apply: tokio::sync::Mutex::new(()),
            default_zone: zone::parse_origin(default_zone).unwrap(),
            configured: zone::configured_zones(dns).unwrap(),
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

    fn route(hostname: &str, addr: [u8; 4]) -> MagicDnsRoute {
        MagicDnsRoute {
            hostname: hostname.to_owned(),
            ipv4_addr: Some(addr.into()),
        }
    }

    #[test]
    fn replaces_routes_for_the_same_client_without_touching_other_clients() {
        let store = MagicDnsRecordStore::default();
        let zone = zone::parse_origin("et.net.").unwrap();
        assert!(!store.replace_client_routes(
            zone.clone(),
            "tcp://client-a".to_owned(),
            vec![route("old-a", [10, 0, 0, 1])],
        ));
        assert!(!store.replace_client_routes(
            zone.clone(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        ));
        assert!(!store.replace_client_routes(
            zone.clone(),
            "tcp://client-a".to_owned(),
            vec![route("new-a", [10, 0, 0, 3])],
        ));

        let routes = &store.snapshot().zones[&zone];
        assert_eq!(routes.len(), 2);
        assert!(routes.iter().any(|route| route.hostname == "new-a"));
        assert!(routes.iter().any(|route| route.hostname == "peer-b"));
        assert!(!routes.iter().any(|route| route.hostname == "old-a"));
    }

    #[test]
    fn empty_update_removes_only_the_target_client_and_reports_empty_zone() {
        let store = MagicDnsRecordStore::default();
        let zone = zone::parse_origin("et.net.").unwrap();
        store.replace_client_routes(
            zone.clone(),
            "tcp://client-a".to_owned(),
            vec![route("peer-a", [10, 0, 0, 1])],
        );
        store.replace_client_routes(
            zone.clone(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        );

        assert!(!store.replace_client_routes(
            zone.clone(),
            "tcp://client-a".to_owned(),
            Vec::new(),
        ));
        assert!(store.replace_client_routes(zone, "tcp://client-b".to_owned(), Vec::new(),));
        assert!(store.snapshot().zones.is_empty());
    }

    #[test]
    fn disconnect_removes_client_from_all_zones() {
        let store = MagicDnsRecordStore::default();
        for zone in ["a.et.net.", "b.et.net."] {
            store.replace_client_routes(
                zone::parse_origin(zone).unwrap(),
                "tcp://client-a".to_owned(),
                vec![route("peer-a", [10, 0, 0, 1])],
            );
        }
        store.replace_client_routes(
            zone::parse_origin("b.et.net.").unwrap(),
            "tcp://client-b".to_owned(),
            vec![route("peer-b", [10, 0, 0, 2])],
        );

        assert_eq!(
            store.remove_client("tcp://client-a"),
            vec![zone::parse_origin("a.et.net.").unwrap()]
        );
        let snapshot = store.snapshot();
        assert_eq!(snapshot.zones.len(), 1);
        assert_eq!(
            snapshot.zones[&zone::parse_origin("b.et.net.").unwrap()][0].hostname,
            "peer-b"
        );
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
        data.system_config = Some(Box::new(SystemConfigSpy(calls.clone())));
        data.do_system_config().unwrap();
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
            assert!(zone::configured_zones(Some(&dns)).is_err());
        }
        assert!(zone::configured_zones(None).unwrap().is_empty());
    }
}
