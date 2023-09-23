use std::{pin::Pin, sync::Arc};

use easytier_rpc::{PeerConnInfo, PeerConnStats};
use futures::{SinkExt, StreamExt};
use pnet::datalink::NetworkInterface;

use tokio::{
    sync::{broadcast, mpsc},
    task::JoinSet,
    time::{timeout, Duration},
};

use tokio_util::{
    bytes::{Bytes, BytesMut},
    sync::PollSender,
};
use tracing::Instrument;

use crate::{
    common::global_ctx::ArcGlobalCtx,
    define_tunnel_filter_chain,
    tunnels::{
        stats::{Throughput, WindowLatency},
        tunnel_filter::StatsRecorderTunnelFilter,
        DatagramSink, Tunnel, TunnelError,
    },
};

use super::packet::{self, ArchivedCtrlPacketBody, ArchivedHandShake, Packet};

pub type PacketRecvChan = mpsc::Sender<Bytes>;

macro_rules! wait_response {
    ($stream: ident, $out_var:ident, $pattern:pat_param => $value:expr) => {
        let rsp_vec = timeout(Duration::from_secs(1), $stream.next()).await;
        if rsp_vec.is_err() {
            return Err(TunnelError::WaitRespError(
                "wait handshake response timeout".to_owned(),
            ));
        }
        let rsp_vec = rsp_vec.unwrap().unwrap()?;

        let $out_var;
        let rsp_bytes = Packet::decode(&rsp_vec);
        match &rsp_bytes.body {
            $pattern => $out_var = $value,
            _ => {
                log::error!(
                    "unexpected packet: {:?}, pattern: {:?}",
                    rsp_bytes,
                    stringify!($pattern)
                );
                return Err(TunnelError::WaitRespError("unexpected packet".to_owned()));
            }
        }
    };
}

pub struct PeerInfo {
    magic: u32,
    pub my_peer_id: uuid::Uuid,
    version: u32,
    pub features: Vec<String>,
    pub interfaces: Vec<NetworkInterface>,
}

impl<'a> From<&ArchivedHandShake> for PeerInfo {
    fn from(hs: &ArchivedHandShake) -> Self {
        PeerInfo {
            magic: hs.magic.into(),
            my_peer_id: hs.my_peer_id.to_uuid(),
            version: hs.version.into(),
            features: hs.features.iter().map(|x| x.to_string()).collect(),
            interfaces: Vec::new(),
        }
    }
}

define_tunnel_filter_chain!(PeerConnTunnel, stats = StatsRecorderTunnelFilter);

pub struct PeerConn {
    conn_id: uuid::Uuid,

    my_node_id: uuid::Uuid,
    global_ctx: ArcGlobalCtx,

    sink: Pin<Box<dyn DatagramSink>>,
    tunnel: Box<dyn Tunnel>,

    tasks: JoinSet<Result<(), TunnelError>>,

    info: Option<PeerInfo>,

    close_event_sender: Option<mpsc::Sender<uuid::Uuid>>,

    ctrl_resp_sender: broadcast::Sender<Bytes>,

    latency_stats: Arc<WindowLatency>,
    throughput: Arc<Throughput>,
}

enum PeerConnPacketType {
    Data(Bytes),
    CtrlReq(Bytes),
    CtrlResp(Bytes),
}

static CTRL_REQ_PACKET_PREFIX: &[u8] = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
static CTRL_RESP_PACKET_PREFIX: &[u8] = &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf1];

impl PeerConn {
    pub fn new(node_id: uuid::Uuid, global_ctx: ArcGlobalCtx, tunnel: Box<dyn Tunnel>) -> Self {
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(100);
        let peer_conn_tunnel = PeerConnTunnel::new();
        let tunnel = peer_conn_tunnel.wrap_tunnel(tunnel);

        PeerConn {
            conn_id: uuid::Uuid::new_v4(),

            my_node_id: node_id,
            global_ctx,

            sink: tunnel.pin_sink(),
            tunnel: Box::new(tunnel),

            tasks: JoinSet::new(),

            info: None,
            close_event_sender: None,

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput: peer_conn_tunnel.stats.get_throughput().clone(),
        }
    }

    pub fn get_conn_id(&self) -> uuid::Uuid {
        self.conn_id
    }

    pub async fn do_handshake_as_server(&mut self) -> Result<(), TunnelError> {
        let mut stream = self.tunnel.pin_stream();
        let mut sink = self.tunnel.pin_sink();

        wait_response!(stream, hs_req, packet::ArchivedPacketBody::Ctrl(ArchivedCtrlPacketBody::HandShake(x)) => x);
        self.info = Some(PeerInfo::from(hs_req));
        log::info!("handshake request: {:?}", hs_req);

        let hs_req = self
            .global_ctx
            .net_ns
            .run(|| packet::Packet::new_handshake(self.my_node_id));
        sink.send(hs_req.into()).await?;

        Ok(())
    }

    pub async fn do_handshake_as_client(&mut self) -> Result<(), TunnelError> {
        let mut stream = self.tunnel.pin_stream();
        let mut sink = self.tunnel.pin_sink();

        let hs_req = self
            .global_ctx
            .net_ns
            .run(|| packet::Packet::new_handshake(self.my_node_id));
        sink.send(hs_req.into()).await?;

        wait_response!(stream, hs_rsp, packet::ArchivedPacketBody::Ctrl(ArchivedCtrlPacketBody::HandShake(x)) => x);
        self.info = Some(PeerInfo::from(hs_rsp));
        log::info!("handshake response: {:?}", hs_rsp);

        Ok(())
    }

    pub fn handshake_done(&self) -> bool {
        self.info.is_some()
    }

    async fn do_pingpong_once(
        my_node_id: uuid::Uuid,
        peer_id: uuid::Uuid,
        sink: &mut Pin<Box<dyn DatagramSink>>,
        receiver: &mut broadcast::Receiver<Bytes>,
    ) -> Result<u128, TunnelError> {
        // should add seq here. so latency can be calculated more accurately
        let req = Self::build_ctrl_msg(
            packet::Packet::new_ping_packet(my_node_id, peer_id).into(),
            true,
        );
        log::trace!("send ping packet: {:?}", req);
        sink.send(req).await?;

        let now = std::time::Instant::now();

        // wait until we get a pong packet in ctrl_resp_receiver
        let resp = timeout(Duration::from_secs(4), async {
            loop {
                match receiver.recv().await {
                    Ok(p) => {
                        if let packet::ArchivedPacketBody::Ctrl(
                            packet::ArchivedCtrlPacketBody::Pong,
                        ) = &Packet::decode(&p).body
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        log::warn!("recv pong resp error: {:?}", e);
                        return Err(TunnelError::WaitRespError(
                            "recv pong resp error".to_owned(),
                        ));
                    }
                }
            }
            Ok(())
        })
        .await;

        if resp.is_err() {
            return Err(TunnelError::WaitRespError(
                "wait ping response timeout".to_owned(),
            ));
        }

        if resp.as_ref().unwrap().is_err() {
            return Err(resp.unwrap().err().unwrap());
        }

        Ok(now.elapsed().as_micros())
    }

    fn start_pingpong(&mut self) {
        let mut sink = self.tunnel.pin_sink();
        let my_node_id = self.my_node_id;
        let peer_id = self.get_peer_id();
        let receiver = self.ctrl_resp_sender.subscribe();
        let close_event_sender = self.close_event_sender.clone().unwrap();
        let conn_id = self.conn_id;
        let latency_stats = self.latency_stats.clone();

        self.tasks.spawn(async move {
            //sleep 1s
            tokio::time::sleep(Duration::from_secs(1)).await;
            loop {
                let mut receiver = receiver.resubscribe();
                if let Ok(lat) =
                    Self::do_pingpong_once(my_node_id, peer_id, &mut sink, &mut receiver).await
                {
                    log::trace!(
                        "pingpong latency: {}us, my_node_id: {}, peer_id: {}",
                        lat,
                        my_node_id,
                        peer_id
                    );
                    latency_stats.record_latency(lat as u64);

                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    break;
                }
            }

            log::warn!(
                "pingpong task exit, my_node_id: {}, peer_id: {}",
                my_node_id,
                peer_id,
            );

            if let Err(e) = close_event_sender.send(conn_id).await {
                log::warn!("close event sender error: {:?}", e);
            }

            Ok(())
        });
    }

    fn get_packet_type(mut bytes_item: Bytes) -> PeerConnPacketType {
        if bytes_item.starts_with(CTRL_REQ_PACKET_PREFIX) {
            PeerConnPacketType::CtrlReq(bytes_item.split_off(CTRL_REQ_PACKET_PREFIX.len()))
        } else if bytes_item.starts_with(CTRL_RESP_PACKET_PREFIX) {
            PeerConnPacketType::CtrlResp(bytes_item.split_off(CTRL_RESP_PACKET_PREFIX.len()))
        } else {
            PeerConnPacketType::Data(bytes_item)
        }
    }

    fn handle_ctrl_req_packet(
        bytes_item: Bytes,
        conn_info: &PeerConnInfo,
    ) -> Result<Bytes, TunnelError> {
        let packet = Packet::decode(&bytes_item);
        match packet.body {
            packet::ArchivedPacketBody::Ctrl(packet::ArchivedCtrlPacketBody::Ping) => {
                log::trace!("recv ping packet: {:?}", packet);
                Ok(Self::build_ctrl_msg(
                    packet::Packet::new_pong_packet(
                        conn_info.my_node_id.parse().unwrap(),
                        conn_info.peer_id.parse().unwrap(),
                    )
                    .into(),
                    false,
                ))
            }
            _ => {
                log::error!("unexpected packet: {:?}", packet);
                Err(TunnelError::CommonError("unexpected packet".to_owned()))
            }
        }
    }

    pub fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let mut stream = self.tunnel.pin_stream();
        let mut sink = self.tunnel.pin_sink();
        let mut sender = PollSender::new(packet_recv_chan.clone());
        let close_event_sender = self.close_event_sender.clone().unwrap();
        let conn_id = self.conn_id;
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let conn_info = self.get_conn_info();
        let conn_info_for_instrument = self.get_conn_info();

        self.tasks.spawn(
            async move {
                tracing::info!("start recving peer conn packet");
                while let Some(ret) = stream.next().await {
                    if ret.is_err() {
                        tracing::error!(error = ?ret, "peer conn recv error");
                        if let Err(close_ret) = sink.close().await {
                            tracing::error!(error = ?close_ret, "peer conn sink close error, ignore it");
                        }
                        if let Err(e) = close_event_sender.send(conn_id).await {
                            tracing::error!(error = ?e, "peer conn close event send error");
                        }
                        return Err(ret.err().unwrap());
                    }

                    match Self::get_packet_type(ret.unwrap().into()) {
                        PeerConnPacketType::Data(item) => sender.send(item).await.unwrap(),
                        PeerConnPacketType::CtrlReq(item) => {
                            let ret = Self::handle_ctrl_req_packet(item, &conn_info).unwrap();
                            if let Err(e) = sink.send(ret).await {
                                tracing::error!(?e, "peer conn send req error");
                            }
                        }
                        PeerConnPacketType::CtrlResp(item) => {
                            if let Err(e) = ctrl_sender.send(item) {
                                tracing::error!(?e, "peer conn send ctrl resp error");
                            }
                        }
                    }
                }
                tracing::info!("end recving peer conn packet");
                Ok(())
            }
            .instrument(
                tracing::info_span!("peer conn recv loop", conn_info = ?conn_info_for_instrument),
            ),
        );

        self.start_pingpong();
    }

    pub async fn send_msg(&mut self, msg: Bytes) -> Result<(), TunnelError> {
        self.sink.send(msg).await
    }

    fn build_ctrl_msg(msg: Bytes, is_req: bool) -> Bytes {
        let prefix: &'static [u8] = if is_req {
            CTRL_REQ_PACKET_PREFIX
        } else {
            CTRL_RESP_PACKET_PREFIX
        };
        let mut new_msg = BytesMut::new();
        new_msg.reserve(prefix.len() + msg.len());
        new_msg.extend_from_slice(prefix);
        new_msg.extend_from_slice(&msg);
        new_msg.into()
    }

    pub fn get_peer_id(&self) -> uuid::Uuid {
        self.info.as_ref().unwrap().my_peer_id
    }

    pub fn set_close_event_sender(&mut self, sender: mpsc::Sender<uuid::Uuid>) {
        self.close_event_sender = Some(sender);
    }

    pub fn get_stats(&self) -> PeerConnStats {
        PeerConnStats {
            latency_us: self.latency_stats.get_latency_us(),

            tx_bytes: self.throughput.tx_bytes(),
            rx_bytes: self.throughput.rx_bytes(),

            tx_packets: self.throughput.tx_packets(),
            rx_packets: self.throughput.rx_packets(),
        }
    }

    pub fn get_conn_info(&self) -> PeerConnInfo {
        PeerConnInfo {
            conn_id: self.conn_id.to_string(),
            my_node_id: self.my_node_id.to_string(),
            peer_id: self.get_peer_id().to_string(),
            features: self.info.as_ref().unwrap().features.clone(),
            tunnel: self.tunnel.info(),
            stats: Some(self.get_stats()),
        }
    }
}

impl Drop for PeerConn {
    fn drop(&mut self) {
        let mut sink = self.tunnel.pin_sink();
        tokio::spawn(async move {
            let ret = sink.close().await;
            tracing::info!(error = ?ret, "peer conn tunnel closed.");
        });
        log::info!("peer conn {:?} drop", self.conn_id);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::common::config_fs::ConfigFs;
    use crate::common::global_ctx::GlobalCtx;
    use crate::common::netns::NetNS;
    use crate::tunnels::tunnel_filter::{PacketRecorderTunnelFilter, TunnelWithFilter};

    #[tokio::test]
    async fn peer_conn_handshake() {
        use crate::tunnels::ring_tunnel::create_ring_tunnel_pair;
        let (c, s) = create_ring_tunnel_pair();

        let c_recorder = Arc::new(PacketRecorderTunnelFilter::new());
        let s_recorder = Arc::new(PacketRecorderTunnelFilter::new());

        let c = TunnelWithFilter::new(c, c_recorder.clone());
        let s = TunnelWithFilter::new(s, s_recorder.clone());

        let c_uuid = uuid::Uuid::new_v4();
        let s_uuid = uuid::Uuid::new_v4();

        let mut c_peer = PeerConn::new(
            c_uuid,
            Arc::new(GlobalCtx::new(
                "c",
                ConfigFs::new_with_dir("c", "/tmp"),
                NetNS::new(None),
            )),
            Box::new(c),
        );

        let mut s_peer = PeerConn::new(
            s_uuid,
            Arc::new(GlobalCtx::new(
                "c",
                ConfigFs::new_with_dir("c", "/tmp"),
                NetNS::new(None),
            )),
            Box::new(s),
        );

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        c_ret.unwrap();
        s_ret.unwrap();

        assert_eq!(c_recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(c_recorder.received.lock().unwrap().len(), 1);

        assert_eq!(s_recorder.sent.lock().unwrap().len(), 1);
        assert_eq!(s_recorder.received.lock().unwrap().len(), 1);

        assert_eq!(c_peer.get_peer_id(), s_uuid);
        assert_eq!(s_peer.get_peer_id(), c_uuid);
    }
}
