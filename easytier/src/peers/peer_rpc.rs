use std::{
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
    time::Instant,
};

use crossbeam::atomic::AtomicCell;
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
    proto::rpc_impl,
    rpc::TaRpcPacket,
    tunnel::packet_def::{PacketType, ZCPacket},
};

const RPC_PACKET_CONTENT_MTU: usize = 1300;

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
    create_time: AtomicCell<Instant>,
    finished: Arc<AtomicBool>,
    tasks: JoinSet<()>,
}

type PeerRpcEndPointCreator =
    Box<dyn Fn(PeerId, PeerRpcTransactId) -> PeerRpcEndPoint + Send + Sync + 'static>;
#[derive(Hash, Eq, PartialEq, Clone)]
struct PeerRpcClientCtxKey(PeerId, PeerRpcServiceId, PeerRpcTransactId);

// handle rpc request from one peer
pub struct PeerRpcManager {
    service_map: Arc<DashMap<PeerRpcServiceId, PacketSender>>,
    tasks: JoinSet<()>,
    tspt: Arc<Box<dyn PeerRpcManagerTransport>>,

    service_registry: Arc<DashMap<PeerRpcServiceId, PeerRpcEndPointCreator>>,

    peer_rpc_endpoints: Arc<DashMap<PeerRpcClientCtxKey, PeerRpcEndPoint>>,
    client_resp_receivers: Arc<DashMap<PeerRpcClientCtxKey, PacketSender>>,

    transact_id: AtomicU32,

    rpc_client: rpc_impl::client::Client,
    rpc_server: rpc_impl::server::Server,
}

impl std::fmt::Debug for PeerRpcManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerRpcManager")
            .field("node_id", &self.tspt.my_peer_id())
            .finish()
    }
}

struct PacketMerger {
    first_piece: Option<TaRpcPacket>,
    pieces: Vec<TaRpcPacket>,
}

impl PacketMerger {
    fn new() -> Self {
        Self {
            first_piece: None,
            pieces: Vec::new(),
        }
    }

    fn try_merge_pieces(&self) -> Option<TaRpcPacket> {
        if self.first_piece.is_none() || self.pieces.is_empty() {
            return None;
        }

        for p in &self.pieces {
            // some piece is missing
            if p.total_pieces == 0 {
                return None;
            }
        }

        // all pieces are received
        let mut content = Vec::new();
        for p in &self.pieces {
            content.extend_from_slice(&p.content);
        }

        let mut tmpl_packet = self.first_piece.as_ref().unwrap().clone();
        tmpl_packet.total_pieces = 1;
        tmpl_packet.piece_idx = 0;
        tmpl_packet.content = content;

        Some(tmpl_packet)
    }

    fn feed(
        &mut self,
        packet: ZCPacket,
        expected_tid: Option<PeerRpcTransactId>,
    ) -> Result<Option<TaRpcPacket>, Error> {
        let payload = packet.payload();
        let rpc_packet =
            TaRpcPacket::decode(payload).map_err(|e| Error::MessageDecodeError(e.to_string()))?;

        if expected_tid.is_some() && rpc_packet.transact_id != expected_tid.unwrap() {
            return Ok(None);
        }

        let total_pieces = rpc_packet.total_pieces;
        let piece_idx = rpc_packet.piece_idx;

        // for compatibility with old version
        if total_pieces == 0 && piece_idx == 0 {
            return Ok(Some(rpc_packet));
        }

        if total_pieces > 100 || total_pieces == 0 {
            return Err(Error::MessageDecodeError(format!(
                "total_pieces is invalid: {}",
                total_pieces
            )));
        }

        if piece_idx >= total_pieces {
            return Err(Error::MessageDecodeError(
                "piece_idx >= total_pieces".to_owned(),
            ));
        }

        if self.first_piece.is_none()
            || self.first_piece.as_ref().unwrap().transact_id != rpc_packet.transact_id
            || self.first_piece.as_ref().unwrap().from_peer != rpc_packet.from_peer
        {
            self.first_piece = Some(rpc_packet.clone());
            self.pieces.clear();
        }

        self.pieces
            .resize(total_pieces as usize, Default::default());
        self.pieces[piece_idx as usize] = rpc_packet;

        Ok(self.try_merge_pieces())
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

            rpc_client: rpc_impl::client::Client::new(),
            rpc_server: rpc_impl::server::Server::new(),
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
        let creator = Box::new(move |peer_id: PeerId, transact_id: PeerRpcTransactId| {
            let mut tasks = JoinSet::new();
            let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();
            let (mut client_transport, server_transport) = tarpc::transport::channel::unbounded();
            let server = tarpc::server::BaseChannel::with_defaults(server_transport);
            let finished = Arc::new(AtomicBool::new(false));

            let my_peer_id_clone = tspt.my_peer_id();
            let peer_id_clone = peer_id.clone();

            let o = server.execute(s.clone());
            tasks.spawn(o);

            let tspt = tspt.clone();
            let finished_clone = finished.clone();
            tasks.spawn(async move {
                let mut packet_merger = PacketMerger::new();
                loop {
                    tokio::select! {
                        Some(resp) = client_transport.next() => {
                            tracing::debug!(resp = ?resp, ?transact_id, ?peer_id, "server recv packet from service provider");
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

                            let msgs = Self::build_rpc_packet(
                                tspt.my_peer_id(),
                                peer_id,
                                service_id,
                                transact_id,
                                false,
                                serialized_resp.as_ref().unwrap(),
                            );

                            for msg in msgs {
                                if let Err(e) = tspt.send(msg, peer_id).await {
                                    tracing::error!(error = ?e, peer_id = ?peer_id, service_id = ?service_id, "send resp to peer failed");
                                    break;
                                }
                            }

                            finished_clone.store(true, Ordering::Relaxed);
                        }
                        Some(packet) = packet_receiver.recv() => {
                            tracing::trace!("recv packet from peer, packet: {:?}", packet);

                            let info = match packet_merger.feed(packet, None) {
                                Err(e) => {
                                    tracing::error!(error = ?e, "feed packet to merger failed");
                                    continue;
                                },
                                Ok(None) => {
                                    continue;
                                },
                                Ok(Some(info)) => {
                                    info
                                }
                            };

                            assert_eq!(info.service_id, service_id);
                            assert_eq!(info.from_peer, peer_id);
                            assert_eq!(info.transact_id, transact_id);

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
                create_time: AtomicCell::new(Instant::now()),
                finished,
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

        tracing::info!(
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
        content: &Vec<u8>,
    ) -> Vec<ZCPacket> {
        let mut ret = Vec::new();
        let content_mtu = RPC_PACKET_CONTENT_MTU;
        let total_pieces = (content.len() + content_mtu - 1) / content_mtu;
        let mut cur_offset = 0;
        while cur_offset < content.len() {
            let mut cur_len = content_mtu;
            if cur_offset + cur_len > content.len() {
                cur_len = content.len() - cur_offset;
            }

            let mut cur_content = Vec::new();
            cur_content.extend_from_slice(&content[cur_offset..cur_offset + cur_len]);

            let cur_packet = TaRpcPacket {
                from_peer,
                to_peer,
                service_id,
                transact_id,
                is_req,
                total_pieces: total_pieces as u32,
                piece_idx: (cur_offset / content_mtu) as u32,
                content: cur_content,
            };
            cur_offset += cur_len;

            let mut buf = Vec::new();
            cur_packet.encode(&mut buf).unwrap();
            let mut zc_packet = ZCPacket::new_with_payload(&buf);
            zc_packet.fill_peer_manager_hdr(from_peer, to_peer, PacketType::TaRpc as u8);
            ret.push(zc_packet);
        }

        ret
    }

    pub fn run(&self) {
        let tspt = self.tspt.clone();
        let service_registry = self.service_registry.clone();
        let peer_rpc_endpoints = self.peer_rpc_endpoints.clone();
        let client_resp_receivers = self.client_resp_receivers.clone();

        self.rpc_client.run();
        self.rpc_server.run();

        let mut server_t = self.rpc_server.get_transport().unwrap();
        let mut client_t = self.rpc_client.get_transport().unwrap();

        let (server_tx, mut server_rx) = (server_t.get_sink(), server_t.get_stream());
        let (client_tx, mut client_rx) = (client_t.get_sink(), client_t.get_stream());

        tokio::spawn(async move {
            loop {
                let packet = tokio::select! {
                    Some(Ok(packet)) = server_rx.next() => {
                        tracing::trace!(?packet, "recv rpc packet from server");
                        packet
                    }
                    Some(Ok(packet)) = client_rx.next() => {
                        tracing::trace!(?packet, "recv rpc packet from client");
                        packet
                    }
                    else => {
                        tracing::warn!("rpc transport read aborted, exiting");
                        break;
                    }
                };

                let dst_peer_id = packet.peer_manager_header().unwrap().to_peer_id.into();
                if let Err(e) = tspt.send(packet, dst_peer_id).await {
                    tracing::error!(error = ?e, dst_peer_id = ?dst_peer_id, "send to peer failed");
                }
            }
        });

        let tspt = self.tspt.clone();
        tokio::spawn(async move {
            loop {
                let Ok(o) = tspt.recv().await else {
                    tracing::warn!("peer rpc transport read aborted, exiting");
                    break;
                };

                if o.peer_manager_header().unwrap().packet_type == PacketType::RpcReq as u8 {
                    server_tx.send(o).await.unwrap();
                    continue;
                } else if o.peer_manager_header().unwrap().packet_type == PacketType::RpcResp as u8
                {
                    client_tx.send(o).await.unwrap();
                    continue;
                }

                let info = Self::parse_rpc_packet(&o).unwrap();
                tracing::debug!(?info, "recv rpc packet from peer");

                if info.is_req {
                    if !service_registry.contains_key(&info.service_id) {
                        tracing::warn!(
                            "service {} not found, my_node_id: {}",
                            info.service_id,
                            tspt.my_peer_id()
                        );
                        continue;
                    }

                    let endpoint = peer_rpc_endpoints
                        .entry(PeerRpcClientCtxKey(
                            info.from_peer,
                            info.service_id,
                            info.transact_id,
                        ))
                        .or_insert_with(|| {
                            service_registry.get(&info.service_id).unwrap()(
                                info.from_peer,
                                info.transact_id,
                            )
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
                        tracing::warn!("client resp receiver not found, info: {:?}", info);
                    }
                }
            }
        });

        let peer_rpc_endpoints = self.peer_rpc_endpoints.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                peer_rpc_endpoints.retain(|_, v| {
                    v.create_time.load().elapsed().as_secs() < 30
                        && !v.finished.load(Ordering::Relaxed)
                });
            }
        });
    }

    pub fn rpc_client(&self) -> &rpc_impl::client::Client {
        &self.rpc_client
    }

    pub fn rpc_server(&self) -> &rpc_impl::server::Server {
        &self.rpc_server
    }

    #[tracing::instrument(skip(f))]
    pub async fn do_client_rpc_scoped<Resp, Req, RpcRet, Fut>(
        &self,
        service_id: PeerRpcServiceId,
        dst_peer_id: PeerId,
        f: impl FnOnce(UnboundedChannel<Resp, Req>) -> Fut,
    ) -> RpcRet
    where
        Resp: serde::Serialize
            + for<'a> serde::Deserialize<'a>
            + Send
            + Sync
            + std::fmt::Debug
            + 'static,
        Req: serde::Serialize
            + for<'a> serde::Deserialize<'a>
            + Send
            + Sync
            + std::fmt::Debug
            + 'static,
        Fut: std::future::Future<Output = RpcRet>,
    {
        let mut tasks = JoinSet::new();
        let (packet_sender, mut packet_receiver) = mpsc::unbounded_channel();

        let (client_transport, server_transport) =
            tarpc::transport::channel::unbounded::<Resp, Req>();

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

                let req = postcard::to_allocvec(&a.unwrap());
                if req.is_err() {
                    tracing::error!(error = ?req.err(), "bincode serialize failed");
                    continue;
                }

                let packets = Self::build_rpc_packet(
                    tspt.my_peer_id(),
                    dst_peer_id,
                    service_id,
                    transact_id,
                    true,
                    req.as_ref().unwrap(),
                );

                tracing::debug!(?packets, ?req, ?transact_id, "client send rpc packet to peer");

                for packet in packets {
                    if let Err(e) = tspt.send(packet, dst_peer_id).await {
                        tracing::error!(error = ?e, dst_peer_id = ?dst_peer_id, "send to peer failed");
                        break;
                    }
                }
            }

            tracing::warn!("[PEER RPC MGR] server trasport read aborted");
        });

        tasks.spawn(async move {
            let mut packet_merger = PacketMerger::new();
            while let Some(packet) = packet_receiver.recv().await {
                tracing::trace!("tunnel recv: {:?}", packet);

                let info = match packet_merger.feed(packet, Some(transact_id)) {
                    Err(e) => {
                        tracing::error!(error = ?e, "feed packet to merger failed");
                        continue;
                    }
                    Ok(None) => {
                        continue;
                    }
                    Ok(Some(info)) => info,
                };

                let decoded = postcard::from_bytes(&info.content.as_slice());

                tracing::debug!(?info, ?decoded, "client recv rpc packet from peer");
                assert_eq!(info.transact_id, transact_id);

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
pub mod tests {
    use std::{pin::Pin, sync::Arc, time::Duration};

    use futures::{SinkExt, StreamExt};
    use tokio::sync::Mutex;

    use crate::{
        common::{error::Error, new_peer_id, PeerId},
        peers::{
            peer_rpc::PeerRpcManager,
            tests::{connect_peer_manager, create_mock_peer_manager, wait_route_appear},
        },
        tunnel::{
            common::tests::wait_for_condition, packet_def::ZCPacket, ring::create_ring_tunnel_pair,
            Tunnel, ZCPacketSink, ZCPacketStream,
        },
    };

    use super::PeerRpcManagerTransport;

    #[tarpc::service]
    pub trait TestRpcService {
        async fn hello(s: String) -> String;
    }

    #[derive(Clone)]
    pub struct MockService {
        pub prefix: String,
    }

    #[tarpc::server]
    impl TestRpcService for MockService {
        async fn hello(self, _: tarpc::context::Context, s: String) -> String {
            format!("{} {}", self.prefix, s)
        }
    }

    fn random_string(len: usize) -> String {
        use rand::distributions::Alphanumeric;
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let s: Vec<u8> = std::iter::repeat(())
            .map(|()| rng.sample(Alphanumeric))
            .take(len)
            .collect();
        String::from_utf8(s).unwrap()
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

        let msg = random_string(8192);
        let ret = client_rpc_mgr
            .do_client_rpc_scoped(1, server_rpc_mgr.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), msg.clone()).await;
                ret
            })
            .await;

        println!("ret: {:?}", ret);
        assert_eq!(ret.unwrap(), format!("hello {}", msg));

        let msg = random_string(10);
        let ret = client_rpc_mgr
            .do_client_rpc_scoped(1, server_rpc_mgr.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), msg.clone()).await;
                ret
            })
            .await;

        println!("ret: {:?}", ret);
        assert_eq!(ret.unwrap(), format!("hello {}", msg));

        wait_for_condition(
            || async { server_rpc_mgr.peer_rpc_endpoints.is_empty() },
            Duration::from_secs(10),
        )
        .await;
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

        let msg = random_string(16 * 1024);
        let ip_list = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), msg.clone()).await;
                ret
            })
            .await;
        println!("ip_list: {:?}", ip_list);
        assert_eq!(ip_list.unwrap(), format!("hello {}", msg));

        // call again
        let msg = random_string(16 * 1024);
        let ip_list = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), msg.clone()).await;
                ret
            })
            .await;
        println!("ip_list: {:?}", ip_list);
        assert_eq!(ip_list.unwrap(), format!("hello {}", msg));

        let msg = random_string(16 * 1024);
        let ip_list = peer_mgr_c
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), msg.clone()).await;
                ret
            })
            .await;
        println!("ip_list: {:?}", ip_list);
        assert_eq!(ip_list.unwrap(), format!("hello {}", msg));
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

        let msg = random_string(16 * 1024);
        let ip_list = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(1, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), msg.clone()).await;
                ret
            })
            .await;
        assert_eq!(ip_list.unwrap(), format!("hello_a {}", msg));

        let msg = random_string(16 * 1024);
        let ip_list = peer_mgr_a
            .get_peer_rpc_mgr()
            .do_client_rpc_scoped(2, peer_mgr_b.my_peer_id(), |c| async {
                let c = TestRpcServiceClient::new(tarpc::client::Config::default(), c).spawn();
                let ret = c.hello(tarpc::context::current(), msg.clone()).await;
                ret
            })
            .await;

        assert_eq!(ip_list.unwrap(), format!("hello_b {}", msg));

        wait_for_condition(
            || async { peer_mgr_b.get_peer_rpc_mgr().peer_rpc_endpoints.is_empty() },
            Duration::from_secs(10),
        )
        .await;
    }
}
