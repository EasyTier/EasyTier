// single-instance server in one machine, every easytier instance that has ip address and tun device will try create a server instance.

// magic dns client will connect to this server to update the dns records.
// magic dns server will add the dns server ip address to the tun device, and forward the dns request to the dns server

// magic dns client will establish a long live tcp connection to the magic dns server, and when the server stops or crashes,
// all the clients will exit and let the easytier instance to launch a new server instance.

use std::{
    net::Ipv4Addr,
    str::FromStr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::Context;
use cidr::Ipv4Inet;
use hickory_proto::rr::LowerName;
use pnet::packet::{
    icmp::{self, IcmpTypes, MutableIcmpPacket},
    ip::IpNextHeaderProtocols,
    ipv4::{self, MutableIpv4Packet},
    tcp::{self, MutableTcpPacket},
    udp::{self, MutableUdpPacket},
    MutablePacket,
};
use tokio::task::JoinSet;

use crate::{
    common::{
        ifcfg::{IfConfiger, IfConfiguerTrait},
        PeerId,
    },
    instance::dns_server::{
        config::{Record, RecordBuilder, RecordType},
        server::build_authority,
    },
    peers::{peer_manager::PeerManager, NicPacketFilter},
    proto::{
        cli::Route,
        common::{TunnelInfo, Void},
        magic_dns::{
            GetDnsRecordResponse, HandshakeRequest, HandshakeResponse, MagicDnsServerRpc,
            UpdateDnsRecordRequest,
        },
        rpc_impl::standalone::{RpcServerHook, StandAloneServer},
        rpc_types::controller::BaseController,
    },
    tunnel::{packet_def::ZCPacket, tcp::TcpTunnelListener},
};

use super::{
    config::{GeneralConfigBuilder, RunConfigBuilder},
    server::Server,
    DEFAULT_ET_DNS_ZONE, MAGIC_DNS_INSTANCE_ADDR,
};

static NIC_PIPELINE_NAME: &str = "magic_dns_server";

pub(super) struct MagicDnsServerInstanceData {
    et_zone: String,
    dns_server: Server,
    tun_dev: String,
    tun_ip: Ipv4Addr,
    fake_ip: Ipv4Addr,
    my_peer_id: PeerId,
}

impl MagicDnsServerInstanceData {
    pub async fn update_dns_records(
        &self,
        routes: &[Route],
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

        tracing::trace!("Updated DNS records for zone {}: {:?}", zone, records);

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
        self.update_dns_records(&input.routes, &input.zone).await?;
        Ok(Default::default())
    }

    async fn get_dns_record(
        &self,
        ctrl: Self::Controller,
        input: Void,
    ) -> crate::proto::rpc_types::error::Result<GetDnsRecordResponse> {
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
    async fn on_new_client(&self, tunnel_info: Option<TunnelInfo>) {
        println!("New client connected: {:?}", tunnel_info);
    }

    async fn on_client_disconnected(&self, tunnel_info: Option<TunnelInfo>) {
        println!("Client disconnected: {:?}", tunnel_info);
    }
}

pub struct MagicDnsServerInstance {
    rpc_server: StandAloneServer<TcpTunnelListener>,
    pub(super) data: Arc<MagicDnsServerInstanceData>,
    peer_mgr: Arc<PeerManager>,
    tun_inet: Ipv4Inet,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl MagicDnsServerInstance {
    pub async fn new(
        peer_mgr: Arc<PeerManager>,
        tun_dev: String,
        tun_inet: Ipv4Inet,
        fake_ip: Ipv4Addr,
    ) -> Result<Self, anyhow::Error> {
        let tcp_listener = TcpTunnelListener::new(MAGIC_DNS_INSTANCE_ADDR.parse().unwrap());
        let mut rpc_server = StandAloneServer::new(tcp_listener);
        rpc_server.serve().await?;

        let dns_config = RunConfigBuilder::default()
            .general(
                GeneralConfigBuilder::default()
                    .listen_udp(format!("{}:0", tun_inet.address()))
                    .listen_tcp(format!("{}:0", tun_inet.address()))
                    .build()
                    .unwrap(),
            )
            .build()
            .unwrap();
        let mut dns_server = Server::new(dns_config);
        dns_server.run().await?;

        if !tun_inet.contains(&fake_ip) {
            let ifcfg = IfConfiger {};
            ifcfg.add_ipv4_route(&tun_dev, fake_ip, 32).await?;
        }

        let data = Arc::new(MagicDnsServerInstanceData {
            et_zone: DEFAULT_ET_DNS_ZONE.to_string(),
            dns_server,
            tun_dev,
            tun_ip: tun_inet.address(),
            fake_ip,
            my_peer_id: peer_mgr.my_peer_id(),
        });
        rpc_server.set_hook(data.clone());

        peer_mgr
            .add_nic_packet_process_pipeline(Box::new(data.clone()))
            .await;

        Ok(Self {
            rpc_server,
            data,
            peer_mgr,
            tun_inet,
            tasks: Arc::new(Mutex::new(JoinSet::new())),
        })
    }

    pub async fn clean_env(&self) {
        if !self.tun_inet.contains(&self.data.fake_ip) {
            let ifcfg = IfConfiger {};
            let _ = ifcfg
                .remove_ipv4_route(&self.data.tun_dev, self.data.fake_ip, 32)
                .await;
        }

        let _ = self
            .peer_mgr
            .remove_nic_packet_process_pipeline(NIC_PIPELINE_NAME.to_string())
            .await;
    }
}
