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
};
use crate::{
    common::{
        global_ctx::ArcGlobalCtx,
        ifcfg::{IfConfiger, IfConfiguerTrait},
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
        rpc_impl::standalone::{
            RpcServerHook, RuntimeRpcListener, StandAloneServer, runtime_rpc_listener,
        },
        rpc_types::controller::{BaseController, Controller},
    },
};
use anyhow::Context;
use cidr::Ipv4Inet;
use easytier_core::instance::{CorePacketPlane, MagicDnsResolverRegistration};
use easytier_core::magic_dns::{
    MagicDnsQuery, MagicDnsQueryResolver, MagicDnsRecordStore, MagicDnsRoute,
};
use hickory_proto::rr::LowerName;
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::authority::{MessageRequest, MessageResponse};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use std::sync::Mutex;
use std::{collections::BTreeMap, io, net::Ipv4Addr, str::FromStr, sync::Arc, time::Duration};

pub(super) struct MagicDnsServerInstanceData {
    dns_server: Server,
    tun_dev: Option<String>,
    fake_ip: Ipv4Addr,
    route_store: MagicDnsRecordStore,
    record_apply: tokio::sync::Mutex<()>,

    system_config: Option<Box<dyn SystemConfig>>,
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

        let authority = build_authority(zone, &records)?;

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
        for (zone, routes) in &snapshot.zones {
            if let Err(e) = self.update_dns_records(routes.iter(), zone).await {
                tracing::error!("Failed to update DNS records for zone {}: {:?}", zone, e);
            }
        }
    }

    async fn keep_zone_authoritative(&self, zone: &str) {
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

    fn do_system_config(&self, zone: &str) -> Result<(), anyhow::Error> {
        if let Some(c) = &self.system_config {
            c.set_dns(&OSConfig {
                nameservers: vec![self.fake_ip.to_string()],
                search_domains: vec![zone.to_string()],
                match_domains: vec![zone.to_string()],
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
        let _apply = self.record_apply.lock().await;
        let zone = input.zone.clone();
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

        self.update().await;
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
        for zone in self.route_store.remove_client(&remote_addr.to_string()) {
            self.keep_zone_authoritative(&zone).await;
        }
        self.update().await;
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
    pub(crate) async fn new(
        packet_plane: Arc<CorePacketPlane>,
        global_ctx: ArcGlobalCtx,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
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

        if !tun_inet.contains(&fake_ip)
            && let Some(tun_dev_name) = &tun_dev
        {
            let cost = if cfg!(target_os = "windows") {
                Some(4)
            } else {
                None
            };
            let ifcfg = IfConfiger {};
            ifcfg
                .add_ipv4_route(tun_dev_name, fake_ip, 32, cost)
                .await?;
        }

        let data = Arc::new(MagicDnsServerInstanceData {
            dns_server,
            tun_dev: tun_dev.clone(),
            fake_ip,
            route_store: MagicDnsRecordStore::default(),
            record_apply: tokio::sync::Mutex::new(()),
            system_config: get_system_config(tun_dev.as_deref())?,
        });

        rpc_server
            .registry()
            .register(MagicDnsServerRpcServer::new_arc(data.clone()), "");
        rpc_server.set_hook(data.clone());

        // Use configured tld_dns_zone or fall back to DEFAULT_ET_DNS_ZONE if empty
        let flags = global_ctx.config.get_flags();
        let tld_dns_zone_clone = flags.tld_dns_zone.clone();

        data.update_dns_records(std::iter::empty(), &tld_dns_zone_clone)
            .await
            .context("Failed to initialize DNS zone")?;

        let data_clone = data.clone();
        tokio::task::spawn_blocking(move || data_clone.do_system_config(&tld_dns_zone_clone))
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
            if !self.tun_inet.contains(&self.data.fake_ip)
                && let Some(tun_dev_name) = &self.data.tun_dev
            {
                let ifcfg = IfConfiger {};
                let _ = ifcfg
                    .remove_ipv4_route(tun_dev_name, self.data.fake_ip, 32)
                    .await;
            }
        }

        self.packet_filter.close().await;
    }
}

impl Drop for MagicDnsServerInstance {
    fn drop(&mut self) {
        println!("MagicDnsServerInstance dropped");
    }
}
