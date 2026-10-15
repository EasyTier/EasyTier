// single-instance server in one machine, every easytier instance that has ip address and tun device will try to create a server instance.

// magic dns client will connect to this server to update the dns records.
// magic dns server will add the dns server ip address to the tun device, and forward the dns request to the dns server

// magic dns client will establish a long live tcp connection to the magic dns server, and when the server stops or crashes,
// all the clients will exit and let the easytier instance to launch a new server instance.

use super::{
    MAGIC_DNS_INSTANCE_SOCKET_ADDR,
    config::{self, ConfiguredRecordStore, GeneralConfigBuilder, RunConfigBuilder},
    server::Server,
    system_config::{OSConfig, SystemConfig},
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
    str::FromStr,
    sync::Arc,
    time::Duration,
};

pub(super) struct MagicDnsServerInstanceData {
    dns_server: Server,
    tun_dev: Option<String>,
    net_ns: NetNS,
    fake_ip: Ipv4Addr,
    manage_fake_ip_route: bool,
    route_store: MagicDnsRecordStore,
    record_apply: tokio::sync::Mutex<()>,
    configured_records: Mutex<ConfiguredRecordStore>,
    default_zone: String,

    system_config: Option<Arc<dyn SystemConfig>>,
}

impl MagicDnsServerInstanceData {
    pub async fn update_dns_records<'a, T: Iterator<Item = &'a MagicDnsRoute>>(
        &self,
        routes: T,
        zone: &str,
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
        {
            let configured = self.configured_records.lock().unwrap();
            for record in configured
                .clients
                .values()
                .filter_map(|zones| zones.get(zone))
                .flatten()
            {
                authority.upsert_mut(record.clone(), 0);
            }
        }

        self.dns_server
            .upsert(
                LowerName::from_str(zone)
                    .with_context(|| "Invalid zone name, expect format like \"et.net.\"")?,
                Arc::new(authority),
            )
            .await;

        tracing::debug!("Updated DNS records for zone {}: {:?}", zone, records);

        Ok(())
    }

    pub async fn update(&self) {
        let snapshot = self.route_store.snapshot();
        let zones: BTreeSet<_> = {
            let configured = self.configured_records.lock().unwrap();
            configured
                .route_zones
                .iter()
                .cloned()
                .chain(
                    configured
                        .clients
                        .values()
                        .flat_map(|zones| zones.keys().cloned()),
                )
                .collect()
        };
        for zone in &zones {
            let routes = snapshot.zones.get(zone).into_iter().flatten();
            if let Err(e) = self.update_dns_records(routes, zone).await {
                tracing::error!("Failed to update DNS records for zone {}: {:?}", zone, e);
            }
        }
    }

    async fn remove_unused_zones(&self, zones: impl IntoIterator<Item = String>) {
        for zone in zones {
            let in_use = {
                let configured = self.configured_records.lock().unwrap();
                configured.route_zones.contains(&zone)
                    || configured
                        .clients
                        .values()
                        .any(|zones| zones.contains_key(&zone))
            };
            if !in_use {
                self.dns_server.remove(&zone.parse().unwrap()).await;
            }
        }
    }

    async fn do_system_config(&self) -> Result<(), anyhow::Error> {
        let Some(configer) = self.system_config.clone() else {
            return Ok(());
        };
        if self.configured_records.lock().unwrap().system_closed {
            return Ok(());
        }
        let domains: BTreeSet<_> = std::iter::once(self.default_zone.clone())
            .chain(
                self.configured_records
                    .lock()
                    .unwrap()
                    .clients
                    .values()
                    .flat_map(|zones| zones.keys().cloned()),
            )
            .collect();
        if self.configured_records.lock().unwrap().applied_domains == domains {
            return Ok(());
        }
        let config = OSConfig {
            nameservers: vec![self.fake_ip.to_string()],
            search_domains: vec![self.default_zone.clone()],
            match_domains: domains.iter().cloned().collect(),
        };
        tokio::task::spawn_blocking(move || configer.set_dns(&config)).await??;
        self.configured_records.lock().unwrap().applied_domains = domains;
        Ok(())
    }

    async fn close_system_config(&self) {
        let _apply = self.record_apply.lock().await;
        self.configured_records.lock().unwrap().system_closed = true;
        if let Some(configer) = &self.system_config
            && let Err(error) = configer.close()
        {
            tracing::error!(?error, "Failed to close system config");
        }
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
        let config = input
            .dns
            .as_deref()
            .map(toml::from_str)
            .transpose()
            .context("invalid DNS configuration")?;
        let zones = config::parse_records(config.as_ref())?;
        let zone = config::dns_origin(&input.zone)?;
        let _apply = self.record_apply.lock().await;
        let remote_addr: url::Url = remote_addr.clone().into();
        let client = remote_addr.to_string();
        let removed = {
            let mut configured = self.configured_records.lock().unwrap();
            configured.route_zones.insert(zone.clone());
            configured
                .clients
                .insert(client.clone(), zones)
                .unwrap_or_default()
        };
        let routes = input
            .routes
            .into_iter()
            .map(|route| MagicDnsRoute {
                hostname: route.hostname,
                ipv4_addr: route.ipv4_addr.unwrap_or_default().address.map(Into::into),
            })
            .collect();
        self.route_store.replace_client_routes(zone, client, routes);

        self.update().await;
        self.remove_unused_zones(removed.into_keys()).await;
        self.do_system_config().await?;
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
            ret.insert(zone, dns_records);
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
        self.route_store.remove_client(remote_addr.as_ref());
        let removed = self
            .configured_records
            .lock()
            .unwrap()
            .clients
            .remove(remote_addr.as_ref())
            .unwrap_or_default();
        self.update().await;
        self.remove_unused_zones(removed.into_keys()).await;
        if let Err(error) = self.do_system_config().await {
            tracing::warn!(
                ?error,
                "failed to update system DNS after client disconnect"
            );
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

        let tld_dns_zone_clone = config::dns_origin(&global_ctx.get_flags().tld_dns_zone)?;
        let configured_records = ConfiguredRecordStore {
            route_zones: BTreeSet::from([tld_dns_zone_clone.clone()]),
            ..Default::default()
        };
        let data = Arc::new(MagicDnsServerInstanceData {
            dns_server,
            tun_dev: tun_dev.clone(),
            net_ns: global_ctx.net_ns.clone(),
            fake_ip,
            manage_fake_ip_route,
            route_store: MagicDnsRecordStore::default(),
            record_apply: tokio::sync::Mutex::new(()),
            configured_records: Mutex::new(configured_records),
            default_zone: tld_dns_zone_clone.clone(),
            system_config: get_system_config(tun_dev.as_deref())?.map(Arc::from),
        });

        rpc_server
            .registry()
            .register(MagicDnsServerRpcServer::new_arc(data.clone()), "");
        rpc_server.set_hook(data.clone());

        {
            let _apply = data.record_apply.lock().await;
            data.update_dns_records(std::iter::empty(), &tld_dns_zone_clone)
                .await
                .context("Failed to initialize DNS zone")?;
            data.do_system_config()
                .await
                .context("Failed to configure system")?;
        }

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
        self.data.close_system_config().await;

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
    use hickory_proto::{
        op::{Message, Query},
        rr::{RData, RecordType},
    };

    #[derive(Default)]
    struct SystemConfigSpy(Mutex<Vec<Vec<String>>>);

    impl SystemConfig for SystemConfigSpy {
        fn set_dns(&self, config: &OSConfig) -> io::Result<()> {
            self.0.lock().unwrap().push(config.match_domains.clone());
            Ok(())
        }

        fn close(&self) -> io::Result<()> {
            self.0.lock().unwrap().push(Vec::new());
            Ok(())
        }
    }

    async fn data() -> MagicDnsServerInstanceData {
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
            configured_records: Mutex::new(ConfiguredRecordStore {
                route_zones: BTreeSet::from(["et.net.".to_owned()]),
                ..Default::default()
            }),
            default_zone: "et.net.".to_owned(),
            system_config: None,
        };
        data.update_dns_records(std::iter::empty(), "et.net.")
            .await
            .unwrap();
        data
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

    fn request(origin: &str, records: &[&str], ip: &str) -> UpdateDnsRecordRequest {
        UpdateDnsRecordRequest {
            zone: "et.net.".to_owned(),
            routes: vec![Route {
                hostname: "node".to_owned(),
                ipv4_addr: Some(Ipv4Inet::from_str(ip).unwrap().into()),
                ..Default::default()
            }],
            dns: Some(
                toml::to_string(&DnsConfig {
                    zone: vec![DnsZoneConfig {
                        origin: origin.to_owned(),
                        ttl: Some(60),
                        records: records.iter().map(|record| (*record).to_owned()).collect(),
                    }],
                })
                .unwrap(),
            ),
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

    #[tokio::test]
    async fn custom_records_survive_route_refresh_and_support_common_types() {
        let data = data().await;
        let records = [
            "nas IN A 10.0.0.8",
            "nas IN AAAA fd00::8",
            "alias IN CNAME nas",
            "info IN TXT \"local record\"",
        ];
        for ip in ["10.0.0.1/24", "10.0.0.2/24"] {
            data.update_dns_record(controller(54001), request("ET.NET", &records, ip))
                .await
                .unwrap();
            assert_eq!(
                a(&data, "nas.et.net.").await,
                vec![Ipv4Addr::new(10, 0, 0, 8)]
            );
            assert!(query(&data, "alias.et.net.", RecordType::A).await.answers().iter()
                .any(|record| matches!(record.data(), RData::CNAME(name) if name.0.to_string() == "nas.et.net.")));
            assert_eq!(
                a(&data, "node.et.net.").await,
                vec![Ipv4Inet::from_str(ip).unwrap().address()]
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
        data.on_client_disconnected(controller(54001).get_tunnel_info().cloned())
            .await;
        assert!(
            query(&data, "nas.et.net.", RecordType::A)
                .await
                .answers()
                .is_empty()
        );
        assert!(
            data.dns_server
                .read_catalog()
                .await
                .contains(&"et.net.".parse().unwrap())
        );
    }

    #[tokio::test]
    async fn custom_records_merge_clients_and_withdraw_only_their_records() {
        let mut data = data().await;
        let system_config = Arc::new(SystemConfigSpy::default());
        data.system_config = Some(system_config.clone());
        let first = controller(54001);
        let second = controller(54002);
        data.update_dns_record(
            first.clone(),
            request("example.test.", &["nas IN A 10.0.0.8"], "10.0.0.1/24"),
        )
        .await
        .unwrap();
        data.update_dns_record(
            second.clone(),
            request("EXAMPLE.TEST", &["nas IN A 10.0.0.9"], "10.0.0.2/24"),
        )
        .await
        .unwrap();
        assert_eq!(
            a(&data, "nas.example.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 8), Ipv4Addr::new(10, 0, 0, 9)]
        );
        data.on_client_disconnected(first.get_tunnel_info().cloned())
            .await;
        assert_eq!(
            a(&data, "nas.example.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 9)]
        );
        // An unrelated route update must keep the surviving client's records.
        data.update_dns_record(
            second.clone(),
            request("example.test.", &["nas IN A 10.0.0.9"], "10.0.0.3/24"),
        )
        .await
        .unwrap();
        assert_eq!(
            a(&data, "nas.example.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 9)]
        );
        assert_eq!(system_config.0.lock().unwrap().len(), 1);
        data.on_client_disconnected(second.get_tunnel_info().cloned())
            .await;
        assert_eq!(
            *system_config.0.lock().unwrap(),
            vec![
                vec!["et.net.".to_owned(), "example.test.".to_owned()],
                vec!["et.net.".to_owned()]
            ]
        );
        let catalog = data.dns_server.read_catalog().await;
        assert!(!catalog.contains(&"example.test.".parse().unwrap()));
        assert!(catalog.contains(&"et.net.".parse().unwrap()));
        drop(catalog);
        data.close_system_config().await;
        data.update_dns_record(
            controller(54003),
            request("late.test.", &["nas IN A 10.0.0.10"], "10.0.0.3/24"),
        )
        .await
        .unwrap();
        assert_eq!(system_config.0.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn custom_records_reject_invalid_replacements_and_allow_clearing() {
        let data = data().await;
        let ctrl = controller(54001);
        data.update_dns_record(
            ctrl.clone(),
            request("example.test.", &["nas IN A 10.0.0.8"], "10.0.0.1/24"),
        )
        .await
        .unwrap();
        assert!(
            data.update_dns_record(
                ctrl.clone(),
                request("example.test.", &["nas IN A invalid"], "10.0.0.2/24")
            )
            .await
            .is_err()
        );
        let mut invalid_toml = request("example.test.", &[], "10.0.0.2/24");
        invalid_toml.dns = Some("zone = [".to_owned());
        assert!(
            data.update_dns_record(ctrl.clone(), invalid_toml)
                .await
                .is_err()
        );
        assert_eq!(
            a(&data, "nas.example.test.").await,
            vec![Ipv4Addr::new(10, 0, 0, 8)]
        );
        assert_eq!(
            a(&data, "node.et.net.").await,
            vec![Ipv4Addr::new(10, 0, 0, 1)]
        );
        let mut clear = request("example.test.", &[], "10.0.0.1/24");
        clear.dns = None;
        data.update_dns_record(ctrl, clear).await.unwrap();
        assert!(
            !data
                .dns_server
                .read_catalog()
                .await
                .contains(&"example.test.".parse().unwrap())
        );
    }
}
