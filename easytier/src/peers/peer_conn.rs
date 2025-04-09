use std::{
    any::Any,
    fmt::Debug,
    pin::Pin,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use futures::{StreamExt, TryFutureExt};

use prost::Message;

use tokio::{
    sync::{broadcast, Mutex},
    task::JoinSet,
    time::{timeout, Duration},
};

use tracing::Instrument;
use zerocopy::AsBytes;

use crate::{
    common::{
        config::{NetworkIdentity, NetworkSecretDigest},
        defer,
        error::Error,
        global_ctx::ArcGlobalCtx,
        PeerId,
    },
    proto::{
        cli::{PeerConnInfo, PeerConnStats},
        common::TunnelInfo,
        peer_rpc::HandshakeRequest,
    },
    tunnel::{
        filter::{StatsRecorderTunnelFilter, TunnelFilter, TunnelWithFilter},
        mpsc::{MpscTunnel, MpscTunnelSender},
        packet_def::{PacketType, ZCPacket},
        stats::{Throughput, WindowLatency},
        Tunnel, TunnelError, ZCPacketStream,
    },
};

use super::{peer_conn_ping::PeerConnPinger, PacketRecvChan};

pub type PeerConnId = uuid::Uuid;

const MAGIC: u32 = 0xd1e1a5e1;
const VERSION: u32 = 1;

pub struct PeerConnCloseNotify {
    conn_id: PeerConnId,
    sender: Arc<std::sync::Mutex<Option<broadcast::Sender<()>>>>,
}

impl PeerConnCloseNotify {
    fn new(conn_id: PeerConnId) -> Self {
        let (sender, _) = broadcast::channel(1);
        Self {
            conn_id,
            sender: Arc::new(std::sync::Mutex::new(Some(sender))),
        }
    }

    fn notify_close(&self) {
        self.sender.lock().unwrap().take();
    }

    pub async fn get_waiter(&self) -> Option<broadcast::Receiver<()>> {
        if let Some(sender) = self.sender.lock().unwrap().as_mut() {
            let receiver = sender.subscribe();
            return Some(receiver);
        }
        None
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    pub fn is_closed(&self) -> bool {
        self.sender.lock().unwrap().is_none()
    }
}

pub struct PeerConn {
    conn_id: PeerConnId,

    my_peer_id: PeerId,
    global_ctx: ArcGlobalCtx,

    tunnel: Arc<Mutex<Box<dyn Any + Send + 'static>>>,
    sink: MpscTunnelSender,
    recv: Arc<Mutex<Option<Pin<Box<dyn ZCPacketStream>>>>>,
    tunnel_info: Option<TunnelInfo>,

    tasks: JoinSet<Result<(), TunnelError>>,

    info: Option<HandshakeRequest>,
    is_client: Option<bool>,

    close_event_notifier: Arc<PeerConnCloseNotify>,

    ctrl_resp_sender: broadcast::Sender<ZCPacket>,

    latency_stats: Arc<WindowLatency>,
    throughput: Arc<Throughput>,
    loss_rate_stats: Arc<AtomicU32>,
}

impl Debug for PeerConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerConn")
            .field("conn_id", &self.conn_id)
            .field("my_peer_id", &self.my_peer_id)
            .field("info", &self.info)
            .finish()
    }
}

impl PeerConn {
    pub fn new(my_peer_id: PeerId, global_ctx: ArcGlobalCtx, tunnel: Box<dyn Tunnel>) -> Self {
        let tunnel_info = tunnel.info();
        let (ctrl_sender, _ctrl_receiver) = broadcast::channel(8);

        let peer_conn_tunnel_filter = StatsRecorderTunnelFilter::new();
        let throughput = peer_conn_tunnel_filter.filter_output();
        let peer_conn_tunnel = TunnelWithFilter::new(tunnel, peer_conn_tunnel_filter);
        let mut mpsc_tunnel = MpscTunnel::new(peer_conn_tunnel, Some(Duration::from_secs(7)));

        let (recv, sink) = (mpsc_tunnel.get_stream(), mpsc_tunnel.get_sink());

        let conn_id = PeerConnId::new_v4();

        PeerConn {
            conn_id: conn_id.clone(),

            my_peer_id,
            global_ctx,

            tunnel: Arc::new(Mutex::new(Box::new(defer::Defer::new(move || {
                mpsc_tunnel.close()
            })))),
            sink,
            recv: Arc::new(Mutex::new(Some(recv))),
            tunnel_info,

            tasks: JoinSet::new(),

            info: None,
            is_client: None,

            close_event_notifier: Arc::new(PeerConnCloseNotify::new(conn_id)),

            ctrl_resp_sender: ctrl_sender,

            latency_stats: Arc::new(WindowLatency::new(15)),
            throughput,
            loss_rate_stats: Arc::new(AtomicU32::new(0)),
        }
    }

    pub fn get_conn_id(&self) -> PeerConnId {
        self.conn_id
    }

    async fn wait_handshake(&mut self, need_retry: &mut bool) -> Result<HandshakeRequest, Error> {
        *need_retry = false;

        let mut locked = self.recv.lock().await;
        let recv = locked.as_mut().unwrap();
        let rsp = match recv.next().await {
            Some(Ok(rsp)) => rsp,
            Some(Err(e)) => {
                return Err(Error::WaitRespError(format!(
                    "conn recv error during wait handshake response, err: {:?}",
                    e
                )))
            }
            None => {
                return Err(Error::WaitRespError(
                    "conn closed during wait handshake response".to_owned(),
                ))
            }
        };

        *need_retry = true;

        let Some(peer_mgr_hdr) = rsp.peer_manager_header() else {
            return Err(Error::WaitRespError(format!(
                "unexpected packet: {:?}, cannot decode peer manager hdr",
                rsp
            )));
        };

        if peer_mgr_hdr.packet_type != PacketType::HandShake as u8 {
            return Err(Error::WaitRespError(format!(
                "unexpected packet type: {:?}",
                peer_mgr_hdr.packet_type
            )));
        }

        let rsp = HandshakeRequest::decode(rsp.payload()).map_err(|e| {
            Error::WaitRespError(format!("decode handshake response error: {:?}", e))
        })?;

        if rsp.network_secret_digrest.len() != std::mem::size_of::<NetworkSecretDigest>() {
            return Err(Error::WaitRespError(
                "invalid network secret digest".to_owned(),
            ));
        }

        return Ok(rsp);
    }

    async fn wait_handshake_loop(&mut self) -> Result<HandshakeRequest, Error> {
        timeout(Duration::from_secs(5), async move {
            loop {
                let mut need_retry = true;
                match self.wait_handshake(&mut need_retry).await {
                    Ok(rsp) => return Ok(rsp),
                    Err(e) => {
                        tracing::warn!("wait handshake error: {:?}", e);
                        if !need_retry {
                            return Err(e);
                        }
                    }
                }
            }
        })
        .map_err(|e| Error::WaitRespError(format!("wait handshake timeout: {:?}", e)))
        .await?
    }

    async fn send_handshake(&mut self) -> Result<(), Error> {
        let network = self.global_ctx.get_network_identity();
        let mut req = HandshakeRequest {
            magic: MAGIC,
            my_peer_id: self.my_peer_id,
            version: VERSION,
            features: Vec::new(),
            network_name: network.network_name.clone(),
            ..Default::default()
        };
        req.network_secret_digrest
            .extend_from_slice(&network.network_secret_digest.unwrap_or_default());

        let hs_req = req.encode_to_vec();
        let mut zc_packet = ZCPacket::new_with_payload(hs_req.as_bytes());
        zc_packet.fill_peer_manager_hdr(
            self.my_peer_id,
            PeerId::default(),
            PacketType::HandShake as u8,
        );

        self.sink.send(zc_packet).await.map_err(|e| {
            tracing::warn!("send handshake request error: {:?}", e);
            Error::WaitRespError("send handshake request error".to_owned())
        })?;

        // yield to send the response packet
        tokio::task::yield_now().await;

        Ok(())
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_server(&mut self) -> Result<(), Error> {
        let rsp = self.wait_handshake_loop().await?;
        tracing::info!("handshake request: {:?}", rsp);
        self.info = Some(rsp);
        self.is_client = Some(false);
        self.send_handshake().await?;

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError("peer id conflict".to_owned()))
        } else {
            Ok(())
        }
    }

    #[tracing::instrument]
    pub async fn do_handshake_as_client(&mut self) -> Result<(), Error> {
        self.send_handshake().await?;
        tracing::info!("waiting for handshake request from server");
        let rsp = self.wait_handshake_loop().await?;
        tracing::info!("handshake response: {:?}", rsp);
        self.info = Some(rsp);
        self.is_client = Some(true);

        if self.get_peer_id() == self.my_peer_id {
            Err(Error::WaitRespError("peer id conflict".to_owned()))
        } else {
            Ok(())
        }
    }

    pub fn handshake_done(&self) -> bool {
        self.info.is_some()
    }

    pub async fn start_recv_loop(&mut self, packet_recv_chan: PacketRecvChan) {
        let mut stream = self.recv.lock().await.take().unwrap();
        let sink = self.sink.clone();
        let sender = packet_recv_chan.clone();
        let close_event_notifier = self.close_event_notifier.clone();
        let ctrl_sender = self.ctrl_resp_sender.clone();
        let conn_info_for_instrument = self.get_conn_info();

        self.tasks.spawn(
            async move {
                tracing::info!("start recving peer conn packet");
                let mut task_ret = Ok(());
                while let Some(ret) = stream.next().await {
                    if ret.is_err() {
                        tracing::error!(error = ?ret, "peer conn recv error");
                        task_ret = Err(ret.err().unwrap());
                        break;
                    }

                    let mut zc_packet = ret.unwrap();
                    let Some(peer_mgr_hdr) = zc_packet.mut_peer_manager_header() else {
                        tracing::error!(
                            "unexpected packet: {:?}, cannot decode peer manager hdr",
                            zc_packet
                        );
                        continue;
                    };

                    if peer_mgr_hdr.packet_type == PacketType::Ping as u8 {
                        peer_mgr_hdr.packet_type = PacketType::Pong as u8;
                        if let Err(e) = sink.send(zc_packet).await {
                            tracing::error!(?e, "peer conn send req error");
                        }
                    } else if peer_mgr_hdr.packet_type == PacketType::Pong as u8 {
                        if let Err(e) = ctrl_sender.send(zc_packet) {
                            tracing::error!(?e, "peer conn send ctrl resp error");
                        }
                    } else {
                        if sender.send(zc_packet).await.is_err() {
                            break;
                        }
                    }
                }

                tracing::info!("end recving peer conn packet");

                drop(sink);
                close_event_notifier.notify_close();

                task_ret
            }
            .instrument(
                tracing::info_span!("peer conn recv loop", conn_info = ?conn_info_for_instrument),
            ),
        );
    }

    pub fn start_pingpong(&mut self) {
        let mut pingpong = PeerConnPinger::new(
            self.my_peer_id,
            self.get_peer_id(),
            self.sink.clone(),
            self.ctrl_resp_sender.clone(),
            self.latency_stats.clone(),
            self.loss_rate_stats.clone(),
            self.throughput.clone(),
        );

        let close_event_notifier = self.close_event_notifier.clone();

        self.tasks.spawn(async move {
            pingpong.pingpong().await;

            tracing::warn!(?pingpong, "pingpong task exit");

            close_event_notifier.notify_close();

            Ok(())
        });
    }

    pub async fn send_msg(&self, msg: ZCPacket) -> Result<(), Error> {
        Ok(self.sink.send(msg).await?)
    }

    pub fn get_peer_id(&self) -> PeerId {
        self.info.as_ref().unwrap().my_peer_id
    }

    pub fn get_network_identity(&self) -> NetworkIdentity {
        let info = self.info.as_ref().unwrap();
        let mut ret = NetworkIdentity {
            network_name: info.network_name.clone(),
            ..Default::default()
        };
        ret.network_secret_digest = Some([0u8; 32]);
        ret.network_secret_digest
            .as_mut()
            .unwrap()
            .copy_from_slice(&info.network_secret_digrest);
        ret
    }

    pub fn get_close_notifier(&self) -> Arc<PeerConnCloseNotify> {
        self.close_event_notifier.clone()
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
        let info = self.info.as_ref().unwrap();
        PeerConnInfo {
            conn_id: self.conn_id.to_string(),
            my_peer_id: self.my_peer_id,
            peer_id: self.get_peer_id(),
            features: info.features.clone(),
            tunnel: self.tunnel_info.clone(),
            stats: Some(self.get_stats()),
            loss_rate: (f64::from(self.loss_rate_stats.load(Ordering::Relaxed)) / 100.0) as f32,
            is_client: self.is_client.unwrap_or_default(),
            network_name: info.network_name.clone(),
        }
    }
}

impl Drop for PeerConn {
    fn drop(&mut self) {
        // if someone drop a conn manually, the notifier is not called.
        self.close_event_notifier.notify_close();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::common::global_ctx::tests::get_mock_global_ctx;
    use crate::common::new_peer_id;
    use crate::common::scoped_task::ScopedTask;
    use crate::peers::create_packet_recv_chan;
    use crate::tunnel::filter::tests::DropSendTunnelFilter;
    use crate::tunnel::filter::PacketRecorderTunnelFilter;
    use crate::tunnel::ring::create_ring_tunnel_pair;

    #[tokio::test]
    async fn peer_conn_handshake_same_id() {
        let (c, s) = create_ring_tunnel_pair();
        let c_peer_id = new_peer_id();
        let s_peer_id = c_peer_id;

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s));

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        assert!(c_ret.is_err());
        assert!(s_ret.is_err());
    }

    #[tokio::test]
    async fn peer_conn_handshake() {
        let (c, s) = create_ring_tunnel_pair();

        let c_recorder = Arc::new(PacketRecorderTunnelFilter::new());
        let s_recorder = Arc::new(PacketRecorderTunnelFilter::new());

        let c = TunnelWithFilter::new(c, c_recorder.clone());
        let s = TunnelWithFilter::new(s, s_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c));

        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s));

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

        assert_eq!(c_peer.get_peer_id(), s_peer_id);
        assert_eq!(s_peer.get_peer_id(), c_peer_id);
        assert_eq!(c_peer.get_network_identity(), s_peer.get_network_identity());
        assert_eq!(c_peer.get_network_identity(), NetworkIdentity::default());
    }

    async fn peer_conn_pingpong_test_common(
        drop_start: u32,
        drop_end: u32,
        conn_closed: bool,
        drop_both: bool,
    ) {
        let (c, s) = create_ring_tunnel_pair();

        // drop 1-3 packets should not affect pingpong
        let c_recorder = Arc::new(DropSendTunnelFilter::new(drop_start, drop_end));
        let c = TunnelWithFilter::new(c, c_recorder.clone());

        let c_peer_id = new_peer_id();
        let s_peer_id = new_peer_id();

        let mut c_peer = PeerConn::new(c_peer_id, get_mock_global_ctx(), Box::new(c));
        let mut s_peer = PeerConn::new(s_peer_id, get_mock_global_ctx(), Box::new(s));

        let (c_ret, s_ret) = tokio::join!(
            c_peer.do_handshake_as_client(),
            s_peer.do_handshake_as_server()
        );

        s_peer.start_recv_loop(create_packet_recv_chan().0).await;
        // do not start ping for s, s only reponde to ping from c

        assert!(c_ret.is_ok());
        assert!(s_ret.is_ok());

        let close_notifier = c_peer.get_close_notifier();
        c_peer.start_pingpong();
        c_peer.start_recv_loop(create_packet_recv_chan().0).await;

        let throughput = c_peer.throughput.clone();
        let _t = ScopedTask::from(tokio::spawn(async move {
            // if not drop both, we mock some rx traffic for client peer to test pinger
            while !drop_both {
                tokio::time::sleep(Duration::from_millis(100)).await;
                throughput.record_rx_bytes(3);
            }
        }));

        tokio::time::sleep(Duration::from_secs(15)).await;

        if conn_closed {
            assert!(close_notifier.is_closed());
        } else {
            assert!(!close_notifier.is_closed());
        }
    }

    #[tokio::test]
    async fn peer_conn_pingpong_timeout_not_close() {
        peer_conn_pingpong_test_common(3, 5, false, false).await;
    }

    #[tokio::test]
    async fn peer_conn_pingpong_oneside_timeout() {
        peer_conn_pingpong_test_common(4, 12, false, false).await;
    }

    #[tokio::test]
    async fn peer_conn_pingpong_bothside_timeout() {
        peer_conn_pingpong_test_common(3, 14, true, true).await;
    }

    #[tokio::test]
    async fn close_tunnel_during_handshake() {
        let (c, s) = create_ring_tunnel_pair();
        let mut c_peer = PeerConn::new(new_peer_id(), get_mock_global_ctx(), Box::new(c));
        let j = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(1)).await;
            drop(s);
        });
        timeout(Duration::from_millis(1500), c_peer.do_handshake_as_client())
            .await
            .unwrap()
            .unwrap_err();
        let _ = tokio::join!(j);
    }
}
