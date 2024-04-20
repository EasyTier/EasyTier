use std::sync::{atomic::AtomicU32, Arc};

use bytes::BytesMut;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use prost::Message;

use tarpc::{server::Channel, transport::channel::UnboundedChannel};
use tokio::{
    sync::mpsc::{self, UnboundedSender},
    task::JoinSet,
};

use tracing::Instrument;

use crate::{
    common::{error::Error, PeerId},
    rpc::TaRpcPacket,
    tunnel::packet_def::{PacketType, ZCPacket},
};



type PeerRpcServiceId = u32;
type PeerRpcTransactId = u32;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Arc)]
pub trait PeerRpcManagerTransport: Send + Sync + 'static {
    fn my_peer_id(&self) -> PeerId;
    async fn send(&self, msg: ZCPacket, dst_peer_id: PeerId) -> Result<(), Error>;
    async fn recv(&self) -> Result<ZCPacket, Error>;
}

type PacketSender = UnboundedSender<ZCPacket>;

struct PeerRpcEndPoint {
    peer_id: PeerId,
    packet_sender: PacketSender,
    tasks: JoinSet<()>,
}

type PeerRpcEndPointCreator = Box<dyn Fn(PeerId) -> PeerRpcEndPoint + Send + Sync + 'static>;
#[derive(Hash, Eq, PartialEq, Clone)]
struct PeerRpcClientCtxKey(PeerId, PeerRpcServiceId, PeerRpcTransactId);

// handle rpc request from one peer
pub struct PeerRpcManager {
    service_map: Arc<DashMap<PeerRpcServiceId, PacketSender>>,
    tasks: JoinSet<()>,
    tspt: Arc<Box<dyn PeerRpcManagerTransport>>,

    service_registry: Arc<DashMap<PeerRpcServiceId, PeerRpcEndPointCreator>>,
    peer_rpc_endpoints: Arc<DashMap<(PeerId, PeerRpcServiceId), PeerRpcEndPoint>>,

    client_resp_receivers: Arc<DashMap<PeerRpcClientCtxKey, PacketSender>>,

    transact_id: AtomicU32,
}

impl std::fmt::Debug for PeerRpcManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRpcManager")
            .field("node_id", &self.tspt.my_peer_id())
            .finish()
    }
}

impl PeerRpcManager {
    pub fn new(tspt: impl PeerRpcManagerTransport) -> Self {
        Self {
            service_map: Arc::new(DashMap::new()),
            tasks: JoinSet::new(),
            tspt: Arc::new(Box::new(tspt)),

            service_registry: Arc::new(DashMap::new()),
            peer_rpc_endpoints: Arc::new(DashMap::new()),

            client_resp_receivers: Arc::new(DashMap::new()),

            transact_id: AtomicU32::new(0),
        }
    }

    pub fn run_service<S, Req>(self: &Self, service_id: PeerRpcServiceId, s: S) -> ()
    where
        S: tarpc::server::Serve<Req> + Clone + Send + Sync + 'static,
        Req: Send + 'static + serde::Serialize + for<'a> serde::Deserialize<'a>,
        S::Resp:
            Send + std::fmt::Debug + 'static + serde::Serialize + for<'a> serde::Deserialize<'a>,
        S::Fut: Send + 'static,
    {
        let tspt = self.tspt.clone();
        let creator = Box::new(move |peer_id: PeerId| {
            let mut tasks = JoinSet::new();
            let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
            let (mut client_transport, server_transport) = tarpc::transport::channel::unbounded();
            let server = tarpc::server::BaseChannel::with_defaults(server_transport);

            let my_peer_id_clone = tspt.my_peer_id();
            let peer_id_clone = peer_id.clone();

            let o = server.execute(s.clone());
            tasks.spawn(o);

            let tspt = tspt.clone();
            tasks.spawn(async move {
                let mut cur_req_peer_id = None;
                let mut cur_transact_id = 0;
                loop {
                    tokio::select! {
                        Some(resp) = client_transport.next() => {
                            let Some(cur_req_peer_id)  = cur_req_peer_id.take() else {
                                tracing::error!("[PEER RPC MGR] cur_req_peer_id is none, ignore this resp");
                                continue;
                            };

                            tracing::trace!(resp = ?resp, "recv packet from client");
                            if resp.is_err() {
                                tracing::warn!(err = ?resp.err(),
                                    "[PEER RPC MGR] client_transport in server side got channel error, ignore it.");
                                continue;
                            }
                            let resp = resp.unwrap();

                            let serialized_resp = postcard::to_allocvec(&resp);
                            if serialized_resp.is_err() {
                                tracing::error!(error = ?serialized_resp.err(), "serialize resp failed");
                                continue;
                            }

                            let msg = Self::build_rpc_packet(
                                tspt.my_peer_id(),
                                cur_req_peer_id,
                                service_id,
                                cur_transact_id,
                                false,
                                serialized_resp.unwrap(),
                            );

                            if let Err(e) = tspt.send(msg, peer_id).await {
                                tracing::error!(error = ?e, peer_id = ?peer_id, service_id = ?service_id, "send resp to peer failed");
                            }
                        }
                        Some(packet) = packet_receiver.recv() => {
                            let info = Self::parse_rpc_packet(&packet);
                            if let Err(e) = info {
                                tracing::error!(error = ?e, packet = ?packet, "parse rpc packet failed");
                                continue;
                            }
                            let info = info.unwrap();

                            if info.from_peer != peer_id {
                                tracing::warn!("recv packet from peer, but peer_id not match, ignore it");
                                continue;
                            }

                            if cur_req_peer_id.is_some() {
                                tracing::warn!("cur_req_peer_id is not none, ignore this packet");
                                continue;
                            }

                            assert_eq!(info.service_id, service_id);
                            cur_req_peer_id = Some(info.from_peer);
                            cur_transact_id = info.transact_id;

                            tracing::trace!("recv packet from peer, packet: {:?}", packet);

                            let decoded_ret = postcard::from_bytes(&info.content.as_slice());
                            if let Err(e) = decoded_ret {
                                tracing::error!(error = ?e, "decode rpc packet failed");
                                continue;
                            }
                            let decoded: tarpc::ClientMessage<Req> = decoded_ret.unwrap();

                            if let Err(e) = client_transport.send(decoded).await {
                                tracing::error!(error = ?e, "send to req to client transport failed");
                            }
                        }
                        else => {
                            tracing::warn!("[PEER RPC MGR] service runner destroy, peer_id: {}, service_id: {}", peer_id, service_id);
                        }
                    }
                }
            }.instrument(tracing::info_span!("service_runner", my_id = ?my_peer_id_clone, peer_id = ?peer_id_clone, service_id = ?service_id)));

            tracing::info!(
                "[PEER RPC MGR] create new service endpoint for peer {}, service {}",
                peer_id,
                service_id
            );

            return PeerRpcEndPoint {
                peer_id,
                packet_sender,
                tasks,
            };
            // let resp = client_transport.next().await;
        });

        if let Some(_) = self.service_registry.insert(service_id, creator) {
            panic!(
                "[PEER RPC MGR] service {} is already registered",
                service_id
            );
        }

        log::info!(
            "[PEER RPC MGR] register service {} succeed, my_node_id {}",
            service_id,
            self.tspt.my_peer_id()
        )
    }

    fn parse_rpc_packet(packet: &ZCPacket) -> Result<TaRpcPacket, Error> {
        let payload = packet.payload();
        TaRpcPacket::decode(payload).map_err(|e| Error::MessageDecodeError(e.to_string()))
    }

    fn build_rpc_packet(
        from_peer: PeerId,
        to_peer: PeerId,
        service_id: PeerRpcServiceId,
        transact_id: PeerRpcTransactId,
        is_req: bool,
        content: Vec<u8>,
    ) -> ZCPacket {
        let packet = TaRpcPacket {
            from_peer,
            to_peer,
            service_id,
            transact_id,
            is_req,
            content,
        };
        let mut buf = Vec::new();
        packet.encode(&mut buf).unwrap();

        let mut b = BytesMut::new();
        b.extend_from_slice(&buf);
        let mut zc_packet = ZCPacket::new_with_payload(b);
        zc_packet.fill_peer_manager_hdr(from_peer, to_peer, PacketType::TaRpc as u8);
        zc_packet
    }

    pub fn run(&self) {
        let tspt = self.tspt.clone();
        let service_registry = self.service_registry.clone();
        let peer_rpc_endpoints = self.peer_rpc_endpoints.clone();
        let client_resp_receivers = self.client_resp_receivers.clone();
        tokio::spawn(async move {
            loop {
                let Ok(o) = tspt.recv().await else {
                    tracing::warn!("peer rpc transport read aborted, exiting");
                    break;
                };

                let info = Self::parse_rpc_packet(&o).unwrap();

                if info.is_req {
                    if !service_registry.contains_key(&info.service_id) {
                        log::warn!(
                            "service {} not found, my_node_id: {}",
                            info.service_id,
                            tspt.my_peer_id()
                        );
                        continue;
                    }

                    let endpoint = peer_rpc_endpoints
                        .entry((info.from_peer, info.service_id))
                        .or_insert_with(|| {
                            service_registry.get(&info.service_id).unwrap()(info.from_peer)
                        });

                    endpoint.packet_sender.send(o).unwrap();
                } else {
                    if let Some(a) = client_resp_receivers.get(&PeerRpcClientCtxKey(
                        info.from_peer,
                        info.service_id,
                        info.transact_id,
                    )) {
                        tracing::trace!("recv resp: {:?}", info);
                        if let Err(e) = a.send(o) {
                            tracing::error!(error = ?e, "send resp to client failed");
                        }
                    } else {
                        log::warn!("client resp receiver not found, info: {:?}", info);
                    }
                }
            }
        });
    }

    #[tracing::instrument(skip(f))]
    pub async fn do_client_rpc_scoped<CM, Req, RpcRet, Fut>(
        &self,
        service_id: PeerRpcServiceId,
        dst_peer_id: PeerId,
        f: impl FnOnce(UnboundedChannel<CM, Req>) -> Fut,
    ) -> RpcRet
    where
        CM: serde::Serialize + for<'a> serde::Deserialize<'a> + Send + Sync + 'static,
        Req: serde::Serialize + for<'a> serde::Deserialize<'a> + Send + Sync + 'static,
        Fut: std::future::Future<Output = RpcRet>,
    {
        let mut tasks = JoinSet::new();
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();

        let (client_transport, server_transport) =
            tarpc::transport::channel::unbounded::<CM, Req>();

        let (mut server_s, mut server_r) = server_transport.split();

        let transact_id = self
            .transact_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let tspt = self.tspt.clone();
        tasks.spawn(async move {
            while let Some(a) = server_r.next().await {
                if a.is_err() {
                    tracing::error!(error = ?a.err(), "channel error");
                    continue;
                }

                let a = postcard::to_allocvec(&a.unwrap());
                if a.is_err() {
                    tracing::error!(error = ?a.err(), "bincode serialize failed");
                    continue;
                }

                let packet = Self::build_rpc_packet(
                    tspt.my_peer_id(),
                    dst_peer_id,
                    service_id,
                    transact_id,
                    true,
                    a.unwrap(),
                );

                if let Err(e) = tspt.send(packet, dst_peer_id).await {
                    tracing::error!(error = ?e, dst_peer_id = ?dst_peer_id, "send to peer failed");
                }
            }

            tracing::warn!("[PEER RPC MGR] server trasport read aborted");
        });

        tasks.spawn(async move {
            while let Some(packet) = packet_receiver.recv().await {
                tracing::trace!("tunnel recv: {:?}", packet);

                let info = Self::parse_rpc_packet(&packet);
                if let Err(e) = info {
                    tracing::error!(error = ?e, "parse rpc packet failed");
                    continue;
                }

                let decoded = postcard::from_bytes(&info.unwrap().content.as_slice());
                if let Err(e) = decoded {
                    tracing::error!(error = ?e, "decode rpc packet failed");
                    continue;
                }

                if let Err(e) = server_s.send(decoded.unwrap()).await {
                    tracing::error!(error = ?e, "send to rpc server channel failed");
                }
            }

            tracing::warn!("[PEER RPC MGR] server packet read aborted");
        });

        let key = PeerRpcClientCtxKey(dst_peer_id, service_id, transact_id);
        let _insert_ret = self
            .client_resp_receivers
            .insert(key.clone(), packet_sender);

        let ret = f(client_transport).await;

        self.client_resp_receivers.remove(&key);

        ret
    }

    pub fn my_peer_id(&self) -> PeerId {
        self.tspt.my_peer_id()
    }
}

#[cfg(test)]
mod tests {
    use std::{pin::Pin, sync::Arc};

    use futures::{SinkExt, StreamExt};
    use tokio::sync::Mutex;
    

    use crate::{
        common::{error::Error, new_peer_id, PeerId},
        peers::{
            peer_rpc::PeerRpcManager,
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        tunnel::{
            packet_def::ZCPacket, ring::create_ring_tunnel_pair, Tunnel, ZCPacketSink,
            ZCPacketStream,
        },
    };

    use super::PeerRpcManagerTransport;

    #[tarpc::service]
    pub trait TestRpcService {
        async fn hello(s: String) -> String;
    }

    #[derive(Clone)]
    struct MockService {
        prefix: String,
    }

    #[tarpc::server]
    impl TestRpcService for MockService {
        async fn hello(self, _: tarpc::context::Context, s: String) -> String {
            format!("{} {}", self.prefix, s)
        }
    }

    #[tokio::test]
    async fn peer_rpc_basic_test() {
        struct MockTransport {
            sink: Arc<Mutex<Pin<Box<dyn ZCPacketSink>>>>,
            stream: Arc<Mutex<Pin<Box<dyn ZCPacketStream>>>>,
            my_peer_id: PeerId,
        }

        #[async_trait::async_trait]
        impl PeerRpcManagerTransport for MockTransport {
            fn my_peer_id(&self) -> PeerId {
                self.my_peer_id
            }
            async fn send(&self, msg: ZCPacket, _dst_peer_id: PeerId) -> Result<(), Error> {
                println!("rpc mgr send: {:?}", msg);
                self.sink.lock().await.send(msg).await.unwrap();
                Ok(())
            }
            async fn recv(&self) -> Result<ZCPacket, Error> {
                let ret = self.stream.lock().await.next().await.unwrap();
                println!("rpc mgr recv: {:?}", ret);
                return ret.map_err(|e| e.into());
            }
        }

        let (ct, st) = create_ring_tunnel_pair();
        let (cts, ctsr) = ct.split();
        let (sts, stsr) = st.split();

        let server_rpc_mgr = PeerRpcManager::new(MockTransport {
            sink: Arc::new(Mutex::new(ctsr)),
            stream: Arc::new(Mutex::new(cts)),
            my_peer_id: new_peer_id(),
        });
        server_rpc_mgr.run();
        let s = MockService {
            prefix: "hello".to_owned(),
        };
        server_rpc_mgr.run_service(1, s.serve());

        let client_rpc_mgr = PeerRpcManager::new(MockTransport {
            sink: Arc::new(Mutex::new(stsr)),
            stream: Arc::new(Mutex::new(sts)),
            my_peer_id: new_peer_id(),
        });
        client_rpc_mgr.run();

        let ret = client_rpc_mgr
            .do_client_rpc_scoped(1, server_rpc_mgr.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), "abc".to_owned()).await;
                ret
            })
            .await;

        println!("ret: {:?}", ret);
        assert_eq!(ret.unwrap(), "hello abc");
    }

    #[tokio::test]
    async fn test_rpc_with_peer_manager() {
        let peer_mgr_a = create_mock_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager().await;
        let peer_mgr_c = create_mock_peer_manager().await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        connect_peer_manager(peer_mgr_b.clone(), peer_mgr_c.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_c.clone())
            .await
            .unwrap();

        assert_eq!(peer_mgr_a.get_peer_map().list_peers().await.len(), 1);
        assert_eq!(
            peer_mgr_a.get_peer_map().list_peers().await[0],
            peer_mgr_b.my_peer_id()
        );

        assert_eq!(peer_mgr_c.get_peer_map().list_peers().await.len(), 1);
        assert_eq!(
            peer_mgr_c.get_peer_map().list_peers().await[0],
            peer_mgr_b.my_peer_id()
        );

        let s = MockService {
            prefix: "hello".to_owned(),
        };
        peer_mgr_b.get_peer_rpc_mgr().run_service(1, s.serve());

        let ip_list = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), "abc".to_owned()).await;
                ret
            })
            .await;
        println!("ip_list: {:?}", ip_list);
        assert_eq!(ip_list.as_ref().unwrap(), "hello abc");

        // call again
        let ip_list = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), "abcd".to_owned()).await;
                ret
            })
            .await;
        println!("ip_list: {:?}", ip_list);
        assert_eq!(ip_list.as_ref().unwrap(), "hello abcd");

        let ip_list = peer_mgr_c
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), "bcd".to_owned()).await;
                ret
            })
            .await;
        println!("ip_list: {:?}", ip_list);
        assert_eq!(ip_list.as_ref().unwrap(), "hello bcd");
    }

    #[tokio::test]
    async fn test_multi_service_with_peer_manager() {
        let peer_mgr_a = create_mock_peer_manager().await;
        let peer_mgr_b = create_mock_peer_manager().await;
        connect_peer_manager(peer_mgr_a.clone(), peer_mgr_b.clone()).await;
        wait_route_appear(peer_mgr_a.clone(), peer_mgr_b.clone())
            .await
            .unwrap();

        assert_eq!(peer_mgr_a.get_peer_map().list_peers().await.len(), 1);
        assert_eq!(
            peer_mgr_a.get_peer_map().list_peers().await[0],
            peer_mgr_b.my_peer_id()
        );

        let s = MockService {
            prefix: "hello_a".to_owned(),
        };
        peer_mgr_b.get_peer_rpc_mgr().run_service(1, s.serve());
        let b = MockService {
            prefix: "hello_b".to_owned(),
        };
        peer_mgr_b.get_peer_rpc_mgr().run_service(2, b.serve());

        let ip_list = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), "abc".to_owned()).await;
                ret
            })
            .await;

        assert_eq!(ip_list.as_ref().unwrap(), "hello_a abc");

        let ip_list = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(2, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), "abc".to_owned()).await;
                ret
            })
            .await;

        assert_eq!(ip_list.as_ref().unwrap(), "hello_b abc");
    }
}
