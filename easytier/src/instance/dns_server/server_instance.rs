// single-instance server in one machine, every easytier instance that has ip address and tun device will try to create a server instance.

// magic dns client will connect to this server to update the dns records.
// magic dns server will add the dns server ip address to the tun device, and forward the dns request to the dns server

// magic dns client will establish a long live tcp connection to the magic dns server, and when the server stops or crashes,
// all the clients will exit and let the easytier instance to launch a new server instance.

use super::{
    config::{GeneralConfigBuilder, RunConfigBuilder},
    server::Server,
    system_config::{OSConfig, SystemConfig},
    MAGIC_DNS_INSTANCE_ADDR,
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
        api::instance::Route,
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
use anyhow::Context;
use cidr::Ipv4Inet;
use dashmap::DashMap;
use hickory_proto::rr::LowerName;
use hickory_proto::serialize::binary::{BinDecodable, BinEncoder};
use hickory_server::authority::{MessageRequest, MessageResponse};
use hickory_server::server::{Request, RequestHandler, ResponseHandler, ResponseInfo};
use multimap::MultiMap;
use pnet::packet::icmp::{IcmpTypes, MutableIcmpPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{
    icmp,
    ip::IpNextHeaderProtocols,
    ipv4::{self, MutableIpv4Packet},
    udp::{self, MutableUdpPacket},
    MutablePacket, Packet,
};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Mutex;
use std::{collections::BTreeMap, io, net::Ipv4Addr, str::FromStr, sync::Arc, time::Duration};

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
    /// Replace content of incoming UDP DNS request and ICMP echo request packet with reply data,
    /// and swap source and destination IP addresses to send it back.
    async fn handle_ip_packet(&self, zc_packet: &mut ZCPacket) -> Option<()> {
        let (ip_header_length, ip_protocol, src_ip, dst_ip) = {
            let ip_packet = Ipv4Packet::new(zc_packet.payload())?;

            if ip_packet.get_version() != 4 {
                return None;
            }

            (
                ip_packet.get_header_length() as usize * 4,
                ip_packet.get_next_level_protocol(),
                ip_packet.get_source(),
                ip_packet.get_destination(),
            )
        };

        if dst_ip != self.fake_ip {
            return None;
        }

        match ip_protocol {
            IpNextHeaderProtocols::Udp => {
                self.handle_udp_packet(zc_packet, ip_header_length, src_ip, dst_ip)
                    .await?;
            }
            IpNextHeaderProtocols::Icmp => {
                self.handle_icmp_packet(zc_packet, ip_header_length)?;
            }
            _ => {
                return None;
            }
        }

        let mut ip_packet = MutableIpv4Packet::new(zc_packet.mut_payload())?;
        ip_packet.set_source(dst_ip);
        ip_packet.set_destination(src_ip);

        ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

        zc_packet.mut_peer_manager_header().unwrap().to_peer_id = self.my_peer_id.into();

        Some(())
    }

    /// Extract the DNS request message and send it to the hickory-dns server instance.
    /// Replace the content of the UDP packet with the response message.
    async fn handle_udp_packet(
        &self,
        zc_packet: &mut ZCPacket,
        ip_header_length: usize,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
    ) -> Option<()> {
        let (src_port, dst_port, request, request_length) = {
            let udp_packet = UdpPacket::new(&zc_packet.payload()[ip_header_length..])?;

            let src_port = udp_packet.get_source();
            let dst_port = udp_packet.get_destination();

            // Remove this to support any UDP port
            if dst_port != 53 {
                return None;
            }

            let request_payload = udp_packet.payload();

            (
                src_port,
                dst_port,
                Request::new(
                    MessageRequest::from_bytes(request_payload).ok()?,
                    SocketAddr::from(SocketAddrV4::new(src_ip, src_port)),
                    hickory_proto::xfer::Protocol::Udp,
                ),
                request_payload.len(),
            )
        };

        let response_payload = {
            let response_payload_arc = Arc::new(Mutex::new(Vec::with_capacity(512)));

            self.dns_server
                .read_catalog()
                .await
                .handle_request(
                    &request,
                    ResponseWrapper {
                        response: response_payload_arc.clone(),
                    },
                )
                .await;

            Arc::into_inner(response_payload_arc)?.into_inner().ok()?
        };

        let response_length = response_payload.len();
        let delta_length = response_length as isize - request_length as isize;

        let inner_length = (zc_packet.buf_len() as isize + delta_length) as usize;
        if zc_packet.mut_inner().capacity() < inner_length {
            let header_length = inner_length - response_length;
            zc_packet.mut_inner().truncate(header_length);
        }
        zc_packet.mut_inner().resize(inner_length, 0);

        let mut ip_packet = MutableIpv4Packet::new(zc_packet.mut_payload())?;

        let ip_length = (ip_packet.get_total_length() as isize + delta_length) as u16;
        ip_packet.set_total_length(ip_length);

        let mut udp_packet = MutableUdpPacket::new(ip_packet.payload_mut())?;

        let udp_length = (udp_packet.get_length() as isize + delta_length) as u16;
        udp_packet.set_length(udp_length);

        udp_packet.set_source(dst_port);
        udp_packet.set_destination(src_port);

        udp_packet.payload_mut().copy_from_slice(&response_payload);

        udp_packet.set_checksum(udp::ipv4_checksum(
            &udp_packet.to_immutable(),
            &dst_ip,
            &src_ip,
        ));

        Some(())
    }

    fn handle_icmp_packet(&self, zc_packet: &mut ZCPacket, ip_header_length: usize) -> Option<()> {
        let mut icmp_packet =
            MutableIcmpPacket::new(&mut zc_packet.mut_payload()[ip_header_length..])?;

        if icmp_packet.get_icmp_type() != IcmpTypes::EchoRequest {
            return None;
        }

        icmp_packet.set_icmp_type(IcmpTypes::EchoReply);
        icmp_packet.set_checksum(icmp::checksum(&icmp_packet.to_immutable()));

        Some(())
    }
}

#[async_trait::async_trait]
impl NicPacketFilter for MagicDnsServerInstanceData {
    async fn try_process_packet_from_nic(&self, zc_packet: &mut ZCPacket) -> bool {
        self.handle_ip_packet(zc_packet).await.is_some()
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
        let tcp_listener = TcpTunnelListener::new(MAGIC_DNS_INSTANCE_ADDR.parse()?);
        let mut rpc_server = StandAloneServer::new(tcp_listener);
        rpc_server.serve().await?;

        let dns_config = RunConfigBuilder::default()
            .general(GeneralConfigBuilder::default().build()?)
            .excluded_forward_nameservers(vec![fake_ip.into()])
            .build()?;
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
                .remove_ipv4_route(self.data.tun_dev.as_ref().unwrap(), self.data.fake_ip, 32)
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
