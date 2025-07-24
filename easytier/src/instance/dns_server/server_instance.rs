// single-instance server in one machine, every easytier instance that has ip address and tun device will try create a server instance.

// magic dns client will connect to this server to update the dns records.
// magic dns server will add the dns server ip address to the tun device, and forward the dns request to the dns server

// magic dns client will establish a long live tcp connection to the magic dns server, and when the server stops or crashes,
// all the clients will exit and let the easytier instance to launch a new server instance.

use std::{collections::BTreeMap, net::Ipv4Addr, str::FromStr, sync::Arc, time::Duration};

use anyhow::Context;
use cidr::Ipv4Inet;
use dashmap::DashMap;
use hickory_proto::rr::LowerName;
use multimap::MultiMap;
use pnet::packet::{
    icmp::{self, IcmpTypes, MutableIcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{self, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket},
    udp::{self, MutableUdpPacket},
    MutablePacket,
};

use crate::{
    common::{
        ifcfg::{IfConfiger, IfConfiguerTrait},
        PeerId,
    },
    instance::dns_server::{
        config::{Record, RecordBuilder, RecordType},
        server::build_authority,
        DEFAULT_ET_DNS_ZONE,
    },
    peers::{peer_manager::PeerManager, NicPacketFilter},
    proto::{
        cli::Route,
        common::{TunnelInfo, Void},
        magic_dns::{
            dns_record::{self},
            DnsRecord, DnsRecordA, DnsRecordList, GetDnsRecordResponse, HandshakeRequest,
            HandshakeResponse, MagicDnsServerRpc, MagicDnsServerRpcServer, UpdateDnsRecordRequest,
        },
        rpc_impl::standalone::{RpcServerHook, StandAloneServer},
        rpc_types::controller::{BaseController, Controller},
    },
    tunnel::{packet_def::ZCPacket, tcp::TcpTunnelListener},
};

use super::{
    config::{GeneralConfigBuilder, RunConfigBuilder},
    server::Server,
    system_config::{OSConfig, SystemConfig},
    MAGIC_DNS_INSTANCE_ADDR,
};

static NIC_PIPELINE_NAME: &str = "magic_dns_server";

pub(super) struct MagicDnsServerInstanceData {
    dns_server: Server,
    tun_dev: Option<String>,
    tun_ip: Ipv4Addr,
    fake_ip: Ipv4Addr,
    my_peer_id: PeerId,

    // zone -> (tunnel remote addr -> route)
    route_infos: DashMap<String, MultiMap<url::Url, Route>>,

    system_config: Option<Box<dyn SystemConfig>>,
}

impl MagicDnsServerInstanceData {
    pub async fn update_dns_records<'a, T: Iterator<Item = &'a Route>>(
        &self,
        routes: T,
        zone: &str,
    ) -> Result<(), anyhow::Error> {
        let mut records: Vec<Record> = vec![];
        for route in routes {
            if route.hostname.is_empty() {
                continue;
            }

            let Some(ipv4_addr) = route.ipv4_addr.unwrap_or_default().address else {
                continue;
            };

            let record = RecordBuilder::default()
                .rr_type(RecordType::A)
                .name(format!("{}.{}", route.hostname, zone))
                .value(ipv4_addr.to_string())
                .ttl(Duration::from_secs(1))
                .build()?;

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
                    .with_context(|| "Invalid zone name, expect fomat like \"et.net.\"")?,
                Arc::new(authority),
            )
            .await;

        tracing::debug!("Updated DNS records for zone {}: {:?}", zone, records);

        Ok(())
    }

    pub async fn update(&self) {
        for item in self.route_infos.iter() {
            let zone = item.key();
            let route_iter = item.value().flat_iter().map(|x| x.1);
            if let Err(e) = self.update_dns_records(route_iter, zone).await {
                tracing::error!("Failed to update DNS records for zone {}: {:?}", zone, e);
            }
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
        let zone = input.zone.clone();
        self.route_infos
            .entry(zone.clone())
            .or_default()
            .insert_many(remote_addr.clone().into(), input.routes);

        self.update().await;
        Ok(Default::default())
    }

    async fn get_dns_record(
        &self,
        _ctrl: Self::Controller,
        _input: Void,
    ) -> crate::proto::rpc_types::error::Result<GetDnsRecordResponse> {
        let mut ret = BTreeMap::new();
        for item in self.route_infos.iter() {
            let zone = item.key();
            let routes = item.value();
            let mut dns_records = DnsRecordList::default();
            for route in routes.iter().map(|x| x.1) {
                dns_records.records.push(DnsRecord {
                    record: Some(dns_record::Record::A(DnsRecordA {
                        name: format!("{}.{}", route.hostname, zone),
                        value: route.ipv4_addr.unwrap_or_default().address,
                        ttl: 1,
                    })),
                });
            }
            ret.insert(zone.clone(), dns_records);
        }
        Ok(GetDnsRecordResponse { records: ret })
    }

    async fn heartbeat(
        &self,
        _ctrl: Self::Controller,
        _input: Void,
    ) -> crate::proto::rpc_types::error::Result<Void> {
        Ok(Default::default())
    }
}

#[async_trait::async_trait]
impl NicPacketFilter for MagicDnsServerInstanceData {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        let data = zc_packet.mut_payload();
        let mut ip_packet = MutableIpv4Packet::new(data).unwrap();
        if ip_packet.get_version() != 4 || ip_packet.get_destination() != self.fake_ip {
            return false;
        }

        match ip_packet.get_next_level_protocol() {
            IpNextHeaderProtocols::Udp => {
                let Some(dns_udp_addr) = self.dns_server.udp_local_addr() else {
                    return false;
                };

                let Some(mut udp_packet) = MutableUdpPacket::new(ip_packet.payload_mut()) else {
                    return false;
                };
                if udp_packet.get_destination() == 53 {
                    // for dns request
                    udp_packet.set_destination(dns_udp_addr.port());
                } else if udp_packet.get_source() == dns_udp_addr.port() {
                    // for dns response
                    udp_packet.set_source(53);
                } else {
                    return false;
                }
                udp_packet.set_checksum(udp::ipv4_checksum(
                    &udp_packet.to_immutable(),
                    &self.fake_ip,
                    &self.tun_ip,
                ));
            }

            IpNextHeaderProtocols::Tcp => {
                let Some(dns_tcp_addr) = self.dns_server.tcp_local_addr() else {
                    return false;
                };

                let Some(mut tcp_packet) = MutableTcpPacket::new(ip_packet.payload_mut()) else {
                    return false;
                };
                if tcp_packet.get_destination() == 53 {
                    // for dns request
                    tcp_packet.set_destination(dns_tcp_addr.port());
                } else if tcp_packet.get_source() == dns_tcp_addr.port() {
                    // for dns response
                    tcp_packet.set_source(53);
                } else {
                    return false;
                }
                tcp_packet.set_checksum(tcp::ipv4_checksum(
                    &tcp_packet.to_immutable(),
                    &self.fake_ip,
                    &self.tun_ip,
                ));
            }

            IpNextHeaderProtocols::Icmp => {
                let Some(mut icmp_packet) = MutableIcmpPacket::new(ip_packet.payload_mut()) else {
                    return false;
                };
                if icmp_packet.get_icmp_type() != IcmpTypes::EchoRequest {
                    return false;
                }
                icmp_packet.set_icmp_type(IcmpTypes::EchoReply);
                icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));
            }

            _ => {
                return false;
            }
        }

        ip_packet.set_source(self.fake_ip);
        ip_packet.set_destination(self.tun_ip);

        ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));
        zc_packet.mut_peer_manager_header().unwrap().to_peer_id = self.my_peer_id.into();

        true
    }

    fn id(&self) -> String {
        NIC_PIPELINE_NAME.to_string()
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
        let remote_addr = remote_addr.into();
        for mut item in self.route_infos.iter_mut() {
            item.value_mut().remove(&remote_addr);
        }
        self.route_infos.retain(|_, v| !v.is_empty());
        self.update().await;
    }
}

pub struct MagicDnsServerInstance {
    rpc_server: StandAloneServer<TcpTunnelListener>,
    pub(super) data: Arc<MagicDnsServerInstanceData>,
    peer_mgr: Arc<PeerManager>,
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

    #[cfg(target_os = "macos")]
    {
        use super::system_config::darwin::DarwinConfigurator;
        return Ok(Some(Box::new(DarwinConfigurator::new())));
    }

    #[allow(unreachable_code)]
    Ok(None)
}

impl MagicDnsServerInstance {
    pub async fn new(
        peer_mgr: Arc<PeerManager>,
        tun_dev: Option<String>,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Result<Self, anyhow::Error> {
        let tcp_listener = TcpTunnelListener::new(MAGIC_DNS_INSTANCE_ADDR.parse().unwrap());
        let mut rpc_server = StandAloneServer::new(tcp_listener);
        rpc_server.serve().await?;

        let bind_addr = tun_inet.address();

        let dns_config = RunConfigBuilder::default()
            .general(
                GeneralConfigBuilder::default()
                    .listen_udp(format!("{}:0", bind_addr))
                    .listen_tcp(format!("{}:0", bind_addr))
                    .build()
                    .unwrap(),
            )
            .excluded_forward_nameservers(vec![fake_ip.into()])
            .build()
            .unwrap();
        let mut dns_server = Server::new(dns_config);
        dns_server.run().await?;

        if !tun_inet.contains(&fake_ip) && tun_dev.is_some() {
            let cost = if cfg!(target_os = "windows") {
                Some(4)
            } else {
                None
            };
            let ifcfg = IfConfiger {};
            ifcfg
                .add_ipv4_route(tun_dev.as_ref().unwrap(), fake_ip, 32, cost)
                .await?;
        }

        let data = Arc::new(MagicDnsServerInstanceData {
            dns_server,
            tun_dev: tun_dev.clone(),
            tun_ip: tun_inet.address(),
            fake_ip,
            my_peer_id: peer_mgr.my_peer_id(),
            route_infos: DashMap::new(),
            system_config: get_system_config(tun_dev.as_deref())?,
        });

        rpc_server
            .registry()
            .register(MagicDnsServerRpcServer::new(data.clone()), "");
        rpc_server.set_hook(data.clone());

        peer_mgr
            .add_nic_packet_process_pipeline(Box::new(data.clone()))
            .await;

        let data_clone = data.clone();
        tokio::task::spawn_blocking(move || data_clone.do_system_config(DEFAULT_ET_DNS_ZONE))
            .await
            .context("Failed to configure system")??;

        Ok(Self {
            rpc_server,
            data,
            peer_mgr,
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

        if !self.tun_inet.contains(&self.data.fake_ip) && self.data.tun_dev.is_some() {
            let ifcfg = IfConfiger {};
            let _ = ifcfg
                .remove_ipv4_route(&self.data.tun_dev.as_ref().unwrap(), self.data.fake_ip, 32)
                .await;
        }

        let _ = self
            .peer_mgr
            .remove_nic_packet_process_pipeline(NIC_PIPELINE_NAME.to_string())
            .await;
    }
}

impl Drop for MagicDnsServerInstance {
    fn drop(&mut self) {
        println!("MagicDnsServerInstance dropped");
    }
}
