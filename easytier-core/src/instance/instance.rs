use std::borrow::BorrowMut;
use std::io::Write;
use std::sync::Arc;

use futures::StreamExt;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;

use tokio::{sync::Mutex, task::JoinSet};
use tokio_util::bytes::{Bytes, BytesMut};
use tonic::transport::Server;
use uuid::Uuid;

use crate::common::config_fs::ConfigFs;
use crate::common::error::Error;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtx};
use crate::common::netns::NetNS;
use crate::connector::direct::DirectConnectorManager;
use crate::connector::manual::{ConnectorManagerRpcService, ManualConnectorManager};
use crate::connector::udp_hole_punch::UdpHolePunchConnector;
use crate::gateway::icmp_proxy::IcmpProxy;
use crate::gateway::tcp_proxy::TcpProxy;
use crate::gateway::udp_proxy::UdpProxy;
use crate::peer_center::instance::PeerCenterInstance;
use crate::peers::peer_manager::PeerManager;
use crate::peers::rpc_service::PeerManagerRpcService;
use crate::tunnels::SinkItem;

use tokio_stream::wrappers::ReceiverStream;

use super::listeners::ListenerManager;
use super::virtual_nic;

pub struct InstanceConfigWriter {
    config: ConfigFs,
}

impl InstanceConfigWriter {
    pub fn new(inst_name: &str) -> Self {
        InstanceConfigWriter {
            config: ConfigFs::new(inst_name),
        }
    }

    pub fn set_ns(self, net_ns: Option<String>) -> Self {
        let net_ns_in_conf = if let Some(net_ns) = net_ns {
            net_ns
        } else {
            "".to_string()
        };

        self.config
            .add_file("net_ns")
            .unwrap()
            .write_all(net_ns_in_conf.as_bytes())
            .unwrap();

        self
    }

    pub fn set_addr(self, addr: String) -> Self {
        self.config
            .add_file("ipv4")
            .unwrap()
            .write_all(addr.as_bytes())
            .unwrap();
        self
    }
}

pub struct Instance {
    inst_name: String,

    id: uuid::Uuid,

    virtual_nic: Option<Arc<virtual_nic::VirtualNic>>,
    peer_packet_receiver: Option<ReceiverStream<SinkItem>>,

    tasks: JoinSet<()>,

    peer_manager: Arc<PeerManager>,
    listener_manager: Arc<Mutex<ListenerManager<PeerManager>>>,
    conn_manager: Arc<ManualConnectorManager>,
    direct_conn_manager: Arc<DirectConnectorManager>,
    udp_hole_puncher: Arc<Mutex<UdpHolePunchConnector>>,

    tcp_proxy: Arc<TcpProxy>,
    icmp_proxy: Arc<IcmpProxy>,
    udp_proxy: Arc<UdpProxy>,

    peer_center: Arc<PeerCenterInstance>,

    global_ctx: ArcGlobalCtx,
}

impl Instance {
    pub fn new(inst_name: &str) -> Self {
        let config = ConfigFs::new(inst_name);
        let net_ns_in_conf = config.get_or_default("net_ns", || "".to_string()).unwrap();
        let net_ns = NetNS::new(if net_ns_in_conf.is_empty() {
            None
        } else {
            Some(net_ns_in_conf.clone())
        });

        let addr = config
            .get_or_default("ipv4", || "10.144.144.10".to_string())
            .unwrap();

        log::info!(
            "[INIT] instance creating. inst_name: {}, addr: {}, netns: {}",
            inst_name,
            addr,
            net_ns_in_conf
        );

        let (peer_packet_sender, peer_packet_receiver) = tokio::sync::mpsc::channel(100);

        let global_ctx = Arc::new(GlobalCtx::new(inst_name, config, net_ns.clone()));

        let id = global_ctx.get_id();

        let peer_manager = Arc::new(PeerManager::new(
            global_ctx.clone(),
            peer_packet_sender.clone(),
        ));

        let listener_manager = Arc::new(Mutex::new(ListenerManager::new(
            id,
            net_ns.clone(),
            peer_manager.clone(),
        )));

        let conn_manager = Arc::new(ManualConnectorManager::new(
            id,
            global_ctx.clone(),
            peer_manager.clone(),
        ));

        let mut direct_conn_manager =
            DirectConnectorManager::new(id, global_ctx.clone(), peer_manager.clone());
        direct_conn_manager.run();

        let udp_hole_puncher = UdpHolePunchConnector::new(global_ctx.clone(), peer_manager.clone());

        let arc_tcp_proxy = TcpProxy::new(global_ctx.clone(), peer_manager.clone());
        let arc_icmp_proxy = IcmpProxy::new(global_ctx.clone(), peer_manager.clone()).unwrap();
        let arc_udp_proxy = UdpProxy::new(global_ctx.clone(), peer_manager.clone()).unwrap();

        let peer_center = Arc::new(PeerCenterInstance::new(peer_manager.clone()));

        Instance {
            inst_name: inst_name.to_string(),
            id,

            virtual_nic: None,
            peer_packet_receiver: Some(ReceiverStream::new(peer_packet_receiver)),

            tasks: JoinSet::new(),
            peer_manager,
            listener_manager,
            conn_manager,
            direct_conn_manager: Arc::new(direct_conn_manager),
            udp_hole_puncher: Arc::new(Mutex::new(udp_hole_puncher)),

            tcp_proxy: arc_tcp_proxy,
            icmp_proxy: arc_icmp_proxy,
            udp_proxy: arc_udp_proxy,

            peer_center,

            global_ctx,
        }
    }

    pub fn get_conn_manager(&self) -> Arc<ManualConnectorManager> {
        self.conn_manager.clone()
    }

    async fn do_forward_nic_to_peers_ipv4(ret: BytesMut, mgr: &PeerManager) {
        if let Some(ipv4) = Ipv4Packet::new(&ret) {
            if ipv4.get_version() != 4 {
                tracing::info!("[USER_PACKET] not ipv4 packet: {:?}", ipv4);
            }
            let dst_ipv4 = ipv4.get_destination();
            tracing::trace!(
                ?ret,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );
            let send_ret = mgr.send_msg_ipv4(ret, dst_ipv4).await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg_ipv4 failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv4 packet");
        }
    }

    async fn do_forward_nic_to_peers_ethernet(mut ret: BytesMut, mgr: &PeerManager) {
        if let Some(eth) = EthernetPacket::new(&ret) {
            log::warn!("begin to forward: {:?}, type: {}", eth, eth.get_ethertype());
            Self::do_forward_nic_to_peers_ipv4(ret.split_off(14), mgr).await;
        } else {
            log::warn!("not ipv4 packet: {:?}", ret);
        }
    }

    fn do_forward_nic_to_peers(&mut self) -> Result<(), Error> {
        // read from nic and write to corresponding tunnel
        let nic = self.virtual_nic.as_ref().unwrap();
        let nic = nic.clone();
        let mgr = self.peer_manager.clone();

        self.tasks.spawn(async move {
            let mut stream = nic.pin_recv_stream();
            while let Some(ret) = stream.next().await {
                if ret.is_err() {
                    log::error!("read from nic failed: {:?}", ret);
                    break;
                }
                Self::do_forward_nic_to_peers_ipv4(ret.unwrap(), mgr.as_ref()).await;
                // Self::do_forward_nic_to_peers_ethernet(ret.into(), mgr.as_ref()).await;
            }
        });

        Ok(())
    }

    fn do_forward_peers_to_nic(
        tasks: &mut JoinSet<()>,
        nic: Arc<virtual_nic::VirtualNic>,
        channel: Option<ReceiverStream<Bytes>>,
    ) {
        tasks.spawn(async move {
            let send = nic.pin_send_stream();
            let channel = channel.unwrap();
            let ret = channel
                .map(|packet| {
                    log::trace!(
                        "[USER_PACKET] forward packet from peers to nic. packet: {:?}",
                        packet
                    );
                    Ok(packet)
                })
                .forward(send)
                .await;
            if ret.is_err() {
                panic!("do_forward_tunnel_to_nic");
            }
        });
    }

    pub async fn run(&mut self) -> Result<(), Error> {
        let ipv4_addr = self.global_ctx.get_ipv4().unwrap();

        let mut nic = virtual_nic::VirtualNic::new(self.get_global_ctx())
            .create_dev()
            .await?
            .link_up()
            .await?
            .remove_ip(None)
            .await?
            .add_ip(ipv4_addr, 24)
            .await?;

        if cfg!(target_os = "macos") {
            nic = nic.add_route(ipv4_addr, 24).await?;
        }

        self.virtual_nic = Some(Arc::new(nic));

        self.do_forward_nic_to_peers().unwrap();
        Self::do_forward_peers_to_nic(
            self.tasks.borrow_mut(),
            self.virtual_nic.as_ref().unwrap().clone(),
            self.peer_packet_receiver.take(),
        );

        self.listener_manager
            .lock()
            .await
            .prepare_listeners()
            .await?;
        self.listener_manager.lock().await.run().await?;
        self.peer_manager.run().await?;

        self.run_rpc_server().unwrap();

        self.tcp_proxy.start().await.unwrap();
        self.icmp_proxy.start().await.unwrap();
        self.udp_proxy.start().await.unwrap();
        self.run_proxy_cidrs_route_updater();

        self.udp_hole_puncher.lock().await.run().await?;

        self.peer_center.init().await;

        Ok(())
    }

    pub fn get_peer_manager(&self) -> Arc<PeerManager> {
        self.peer_manager.clone()
    }

    pub async fn close_peer_conn(&mut self, peer_id: &Uuid, conn_id: &Uuid) -> Result<(), Error> {
        self.peer_manager
            .get_peer_map()
            .close_peer_conn(peer_id, conn_id)
            .await?;
        Ok(())
    }

    pub async fn wait(&mut self) {
        while let Some(ret) = self.tasks.join_next().await {
            log::info!("task finished: {:?}", ret);
            ret.unwrap();
        }
    }

    pub fn id(&self) -> uuid::Uuid {
        self.id
    }

    fn run_rpc_server(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let addr = "0.0.0.0:15888".parse()?;
        let peer_mgr = self.peer_manager.clone();
        let conn_manager = self.conn_manager.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let peer_center = self.peer_center.clone();

        self.tasks.spawn(async move {
            let _g = net_ns.guard();
            log::info!("[INIT RPC] start rpc server. addr: {}", addr);
            Server::builder()
                .add_service(
                    crate::rpc::peer_manage_rpc_server::PeerManageRpcServer::new(
                        PeerManagerRpcService::new(peer_mgr),
                    ),
                )
                .add_service(
                    crate::rpc::connector_manage_rpc_server::ConnectorManageRpcServer::new(
                        ConnectorManagerRpcService(conn_manager.clone()),
                    ),
                )
                .add_service(
                    crate::rpc::peer_center_rpc_server::PeerCenterRpcServer::new(
                        peer_center.get_rpc_service(),
                    ),
                )
                .serve(addr)
                .await
                .unwrap();
        });
        Ok(())
    }

    fn run_proxy_cidrs_route_updater(&mut self) {
        let peer_mgr = self.peer_manager.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.virtual_nic.as_ref().unwrap().clone();

        self.tasks.spawn(async move {
            let mut cur_proxy_cidrs = vec![];
            loop {
                let mut proxy_cidrs = vec![];
                let routes = peer_mgr.list_routes().await;
                for r in routes {
                    for cidr in r.proxy_cidrs {
                        let Ok(cidr) = cidr.parse::<cidr::Ipv4Cidr>() else {
                            continue;
                        };
                        proxy_cidrs.push(cidr);
                    }
                }

                // if route is in cur_proxy_cidrs but not in proxy_cidrs, delete it.
                for cidr in cur_proxy_cidrs.iter() {
                    if proxy_cidrs.contains(cidr) {
                        continue;
                    }

                    let _g = net_ns.guard();
                    let ret = nic
                        .get_ifcfg()
                        .remove_ipv4_route(
                            nic.ifname(),
                            cidr.first_address(),
                            cidr.network_length(),
                        )
                        .await;

                    if ret.is_err() {
                        tracing::trace!(
                            cidr = ?cidr,
                            err = ?ret,
                            "remove route failed.",
                        );
                    }
                }

                for cidr in proxy_cidrs.iter() {
                    if cur_proxy_cidrs.contains(cidr) {
                        continue;
                    }
                    let _g = net_ns.guard();
                    let ret = nic
                        .get_ifcfg()
                        .add_ipv4_route(nic.ifname(), cidr.first_address(), cidr.network_length())
                        .await;

                    if ret.is_err() {
                        tracing::trace!(
                            cidr = ?cidr,
                            err = ?ret,
                            "add route failed.",
                        );
                    }
                }

                cur_proxy_cidrs = proxy_cidrs;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    pub fn get_global_ctx(&self) -> ArcGlobalCtx {
        self.global_ctx.clone()
    }
}
