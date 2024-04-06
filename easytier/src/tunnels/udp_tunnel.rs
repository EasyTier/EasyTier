use std::{fmt::Debug, pin::Pin, sync::Arc};

use async_trait::async_trait;
use dashmap::DashMap;
use futures::{stream::FuturesUnordered, SinkExt, StreamExt};
use rkyv::{Archive, Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::{net::UdpSocket, sync::Mutex, task::JoinSet};
use tokio_util::{
    bytes::{Buf, Bytes, BytesMut},
    udp::UdpFramed,
};
use tracing::Instrument;

use crate::{
    common::{
        join_joinset_background,
        rkyv_util::{self, encode_to_bytes, vec_to_string},
    },
    rpc::TunnelInfo,
    tunnels::{build_url_from_socket_addr, close_tunnel, TunnelConnCounter, TunnelConnector},
};

use super::{
    codec::BytesCodec,
    common::{
        setup_sokcet2, setup_sokcet2_ext, wait_for_connect_futures, FramedTunnel,
        TunnelWithCustomInfo,
    },
    ring_tunnel::create_ring_tunnel_pair,
    DatagramSink, DatagramStream, Tunnel, TunnelListener, TunnelUrl,
};

pub const UDP_DATA_MTU: usize = 65000;

#[derive(Archive, Deserialize, Serialize)]
#[archive(compare(PartialEq), check_bytes)]
// Derives can be passed through to the generated type:
pub enum UdpPacketPayload {
    Syn,
    Sack,
    HolePunch(String),
    Data(String),
}

impl std::fmt::Debug for UdpPacketPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut tmp = f.debug_struct("ArchivedUdpPacketPayload");
        match self {
            UdpPacketPayload::Syn => tmp.field("Syn", &"").finish(),
            UdpPacketPayload::Sack => tmp.field("Sack", &"").finish(),
            UdpPacketPayload::HolePunch(s) => tmp.field("HolePunch", &s.as_bytes()).finish(),
            UdpPacketPayload::Data(s) => tmp.field("Data", &s.as_bytes()).finish(),
        }
    }
}

#[derive(Archive, Deserialize, Serialize, Debug)]
#[archive(compare(PartialEq), check_bytes)]
#[archive_attr(derive(Debug))]
pub struct UdpPacket {
    pub conn_id: u32,
    pub magic: u32,
    pub payload: UdpPacketPayload,
}

const UDP_PACKET_MAGIC: u32 = 0x19941126;

impl std::fmt::Debug for ArchivedUdpPacketPayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut tmp = f.debug_struct("ArchivedUdpPacketPayload");
        match self {
            ArchivedUdpPacketPayload::Syn => tmp.field("Syn", &"").finish(),
            ArchivedUdpPacketPayload::Sack => tmp.field("Sack", &"").finish(),
            ArchivedUdpPacketPayload::HolePunch(s) => {
                tmp.field("HolePunch", &s.as_bytes()).finish()
            }
            ArchivedUdpPacketPayload::Data(s) => tmp.field("Data", &s.as_bytes()).finish(),
        }
    }
}

impl UdpPacket {
    pub fn new_data_packet(conn_id: u32, data: Vec<u8>) -> Self {
        Self {
            conn_id,
            magic: UDP_PACKET_MAGIC,
            payload: UdpPacketPayload::Data(vec_to_string(data)),
        }
    }

    pub fn new_hole_punch_packet(data: Vec<u8>) -> Self {
        Self {
            conn_id: 0,
            magic: UDP_PACKET_MAGIC,
            payload: UdpPacketPayload::HolePunch(vec_to_string(data)),
        }
    }

    pub fn new_syn_packet(conn_id: u32) -> Self {
        Self {
            conn_id,
            magic: UDP_PACKET_MAGIC,
            payload: UdpPacketPayload::Syn,
        }
    }

    pub fn new_sack_packet(conn_id: u32) -> Self {
        Self {
            conn_id,
            magic: UDP_PACKET_MAGIC,
            payload: UdpPacketPayload::Sack,
        }
    }
}

fn try_get_data_payload(mut buf: BytesMut, conn_id: u32) -> Option<BytesMut> {
    let Ok(udp_packet) = rkyv_util::decode_from_bytes::<UdpPacket>(&buf) else {
        tracing::warn!(?buf, "udp decode error");
        return None;
    };

    if udp_packet.conn_id != conn_id.clone() {
        tracing::warn!(?udp_packet, ?conn_id, "udp conn id not match");
        return None;
    }

    if udp_packet.magic != UDP_PACKET_MAGIC {
        tracing::trace!(?udp_packet, "udp magic not match");
        return None;
    }

    let ArchivedUdpPacketPayload::Data(payload) = &udp_packet.payload else {
        tracing::warn!(?udp_packet, "udp payload not data");
        return None;
    };

    let offset = payload.as_ptr() as usize - buf.as_ptr() as usize;
    let len = payload.len();
    if offset + len > buf.len() {
        tracing::warn!(?offset, ?len, ?buf, "udp payload data out of range");
        return None;
    }

    buf.advance(offset);
    buf.truncate(len);
    tracing::trace!(?offset, ?len, ?buf, "udp payload data");

    Some(buf)
}

fn get_tunnel_from_socket(
    socket: Arc<UdpSocket>,
    addr: SocketAddr,
    conn_id: u32,
) -> Box<dyn super::Tunnel> {
    let udp = UdpFramed::new(socket.clone(), BytesCodec::new(UDP_DATA_MTU));
    let (sink, stream) = udp.split();

    let recv_addr = addr;
    let stream = stream.filter_map(move |v| async move {
        tracing::trace!(?v, "udp stream recv something");
        if v.is_err() {
            tracing::warn!(?v, "udp stream error");
            return Some(Err(super::TunnelError::CommonError(
                "udp stream error".to_owned(),
            )));
        }

        let (buf, addr) = v.unwrap();
        if recv_addr != addr {
            tracing::warn!(?addr, ?recv_addr, "udp recv addr not match");
            return None;
        }

        Some(Ok(try_get_data_payload(buf, conn_id.clone())?))
    });
    let stream = Box::pin(stream);

    let sender_addr = addr;
    let sink = Box::pin(sink.with(move |v: Bytes| async move {
        if false {
            return Err(super::TunnelError::CommonError("udp sink error".to_owned()));
        }

        // TODO: two copy here, how to avoid?
        let udp_packet = UdpPacket::new_data_packet(conn_id, v.to_vec());
        let v = encode_to_bytes::<_, UDP_DATA_MTU>(&udp_packet);
        tracing::trace!(?udp_packet, ?v, "udp send packet");

        Ok((v, sender_addr))
    }));

    FramedTunnel::new_tunnel_with_info(
        stream,
        sink,
        // TODO: this remote addr is not a url
        super::TunnelInfo {
            tunnel_type: "udp".to_owned(),
            local_addr: super::build_url_from_socket_addr(
                &socket.local_addr().unwrap().to_string(),
                "udp",
            )
            .into(),
            remote_addr: super::build_url_from_socket_addr(&addr.to_string(), "udp").into(),
        },
    )
}

pub(crate) struct StreamSinkPair(
    pub Pin<Box<dyn DatagramStream>>,
    pub Pin<Box<dyn DatagramSink>>,
    pub u32,
);
pub(crate) type ArcStreamSinkPair = Arc<Mutex<StreamSinkPair>>;

pub struct UdpTunnelListener {
    addr: url::Url,
    socket: Option<Arc<UdpSocket>>,

    sock_map: Arc<DashMap<SocketAddr, ArcStreamSinkPair>>,
    forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,

    conn_recv: tokio::sync::mpsc::Receiver<Box<dyn Tunnel>>,
    conn_send: Option<tokio::sync::mpsc::Sender<Box<dyn Tunnel>>>,
}

impl UdpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        let (conn_send, conn_recv) = tokio::sync::mpsc::channel(100);
        Self {
            addr,
            socket: None,
            sock_map: Arc::new(DashMap::new()),
            forward_tasks: Arc::new(std::sync::Mutex::new(JoinSet::new())),
            conn_recv,
            conn_send: Some(conn_send),
        }
    }

    async fn try_forward_packet(
        sock_map: &DashMap<SocketAddr, ArcStreamSinkPair>,
        buf: BytesMut,
        addr: SocketAddr,
    ) -> Result<(), super::TunnelError> {
        let entry = sock_map.get_mut(&addr);
        if entry.is_none() {
            log::warn!("udp forward packet: {:?}, {:?}, no entry", addr, buf);
            return Ok(());
        }

        log::trace!("udp forward packet: {:?}, {:?}", addr, buf);
        let entry = entry.unwrap();
        let pair = entry.value().clone();
        drop(entry);

        let Some(buf) = try_get_data_payload(buf, pair.lock().await.2) else {
            return Ok(());
        };
        pair.lock().await.1.send(buf.freeze()).await?;
        Ok(())
    }

    async fn handle_connect(
        socket: Arc<UdpSocket>,
        addr: SocketAddr,
        forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
        sock_map: Arc<DashMap<SocketAddr, ArcStreamSinkPair>>,
        local_url: url::Url,
        conn_id: u32,
    ) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        tracing::info!(?conn_id, ?addr, "udp connection accept handling",);

        let udp_packet = UdpPacket::new_sack_packet(conn_id);
        let sack_buf = encode_to_bytes::<_, UDP_DATA_MTU>(&udp_packet);
        socket.send_to(&sack_buf, addr).await?;

        let (ctunnel, stunnel) = create_ring_tunnel_pair();
        let udp_tunnel = get_tunnel_from_socket(socket.clone(), addr, conn_id);
        let ss_pair = StreamSinkPair(ctunnel.pin_stream(), ctunnel.pin_sink(), conn_id);
        let addr_copy = addr.clone();
        sock_map.insert(addr, Arc::new(Mutex::new(ss_pair)));
        let ctunnel_stream = ctunnel.pin_stream();
        forward_tasks.lock().unwrap().spawn(async move {
            let ret = ctunnel_stream
                .map(|v| {
                    tracing::trace!(?v, "udp stream recv something in forward task");
                    if v.is_err() {
                        return Err(super::TunnelError::CommonError(
                            "udp stream error".to_owned(),
                        ));
                    }
                    Ok(v.unwrap().freeze())
                })
                .forward(udp_tunnel.pin_sink())
                .await;
            if let None = sock_map.remove(&addr_copy) {
                log::warn!("udp forward packet: {:?}, no entry", addr_copy);
            }
            close_tunnel(&ctunnel).await.unwrap();
            log::warn!("udp connection forward done: {:?}, {:?}", addr_copy, ret);
        });

        Ok(Box::new(TunnelWithCustomInfo::new(
            stunnel,
            TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: local_url.into(),
                remote_addr: build_url_from_socket_addr(&addr.to_string(), "udp").into(),
            },
        )))
    }

    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        self.socket.clone()
    }
}

#[async_trait]
impl TunnelListener for UdpTunnelListener {
    async fn listen(&mut self) -> Result<(), super::TunnelError> {
        let addr = super::check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "udp")?;

        let socket2_socket = socket2::Socket::new(
            socket2::Domain::for_address(addr),
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;

        let tunnel_url: TunnelUrl = self.addr.clone().into();
        if let Some(bind_dev) = tunnel_url.bind_dev() {
            setup_sokcet2_ext(&socket2_socket, &addr, Some(bind_dev))?;
        } else {
            setup_sokcet2(&socket2_socket, &addr)?;
        }

        self.socket = Some(Arc::new(UdpSocket::from_std(socket2_socket.into())?));

        let socket = self.socket.as_ref().unwrap().clone();
        let forward_tasks = self.forward_tasks.clone();
        let sock_map = self.sock_map.clone();
        let conn_send = self.conn_send.take().unwrap();
        let local_url = self.local_url().clone();
        self.forward_tasks.lock().unwrap().spawn(
            async move {
                loop {
                    let mut buf = BytesMut::new();
                    buf.resize(UDP_DATA_MTU, 0);
                    let (_size, addr) = socket.recv_from(&mut buf).await.unwrap();
                    let _ = buf.split_off(_size);
                    log::trace!(
                        "udp recv packet: {:?}, buf: {:?}, size: {}",
                        addr,
                        buf,
                        _size
                    );

                    let Ok(udp_packet) = rkyv_util::decode_from_bytes::<UdpPacket>(&buf) else {
                        tracing::warn!(?buf, "udp decode error in forward task");
                        continue;
                    };

                    if udp_packet.magic != UDP_PACKET_MAGIC {
                        tracing::trace!(?udp_packet, "udp magic not match");
                        continue;
                    }

                    if matches!(udp_packet.payload, ArchivedUdpPacketPayload::Syn) {
                        let Ok(conn) = Self::handle_connect(
                            socket.clone(),
                            addr,
                            forward_tasks.clone(),
                            sock_map.clone(),
                            local_url.clone(),
                            udp_packet.conn_id.into(),
                        )
                        .await
                        else {
                            tracing::error!(?addr, "udp handle connect error");
                            continue;
                        };
                        if let Err(e) = conn_send.send(conn).await {
                            tracing::warn!(?e, "udp send conn to accept channel error");
                        }
                    } else {
                        Self::try_forward_packet(sock_map.as_ref(), buf, addr)
                            .await
                            .unwrap();
                    }
                }
            }
            .instrument(tracing::info_span!("udp forward task", ?self.socket)),
        );

        join_joinset_background(self.forward_tasks.clone(), "UdpTunnelListener".to_owned());

        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        log::info!("start udp accept: {:?}", self.addr);
        while let Some(conn) = self.conn_recv.recv().await {
            return Ok(conn);
        }
        return Err(super::TunnelError::CommonError(
            "udp accept error".to_owned(),
        ));
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn get_conn_counter(&self) -> Arc<Box<dyn TunnelConnCounter>> {
        struct UdpTunnelConnCounter {
            sock_map: Arc<DashMap<SocketAddr, ArcStreamSinkPair>>,
        }

        impl Debug for UdpTunnelConnCounter {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.debug_struct("UdpTunnelConnCounter")
                    .field("sock_map_len", &self.sock_map.len())
                    .finish()
            }
        }

        impl TunnelConnCounter for UdpTunnelConnCounter {
            fn get(&self) -> u32 {
                self.sock_map.len() as u32
            }
        }

        Arc::new(Box::new(UdpTunnelConnCounter {
            sock_map: self.sock_map.clone(),
        }))
    }
}

pub struct UdpTunnelConnector {
    addr: url::Url,
    bind_addrs: Vec<SocketAddr>,
}

impl UdpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        Self {
            addr,
            bind_addrs: vec![],
        }
    }

    async fn wait_sack(
        socket: &UdpSocket,
        addr: SocketAddr,
        conn_id: u32,
    ) -> Result<(), super::TunnelError> {
        let mut buf = BytesMut::new();
        buf.resize(128, 0);

        let (usize, recv_addr) = tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            socket.recv_from(&mut buf),
        )
        .await??;

        if recv_addr != addr {
            return Err(super::TunnelError::ConnectError(format!(
                "udp connect error, unexpected sack addr: {:?}, {:?}",
                recv_addr, addr
            )));
        }

        let _ = buf.split_off(usize);

        let Ok(udp_packet) = rkyv_util::decode_from_bytes::<UdpPacket>(&buf) else {
            tracing::warn!(?buf, "udp decode error in wait sack");
            return Err(super::TunnelError::ConnectError(format!(
                "udp connect error, decode error. buf: {:?}",
                buf
            )));
        };

        if udp_packet.magic != UDP_PACKET_MAGIC {
            tracing::trace!(?udp_packet, "udp magic not match");
            return Err(super::TunnelError::ConnectError(format!(
                "udp connect error, magic not match. magic: {:?}",
                udp_packet.magic
            )));
        }

        if conn_id != udp_packet.conn_id {
            return Err(super::TunnelError::ConnectError(format!(
                "udp connect error, conn id not match. conn_id: {:?}, {:?}",
                conn_id, udp_packet.conn_id
            )));
        }

        if !matches!(udp_packet.payload, ArchivedUdpPacketPayload::Sack) {
            return Err(super::TunnelError::ConnectError(format!(
                "udp connect error, unexpected payload. payload: {:?}",
                udp_packet.payload
            )));
        }

        Ok(())
    }

    async fn wait_sack_loop(
        socket: &UdpSocket,
        addr: SocketAddr,
        conn_id: u32,
    ) -> Result<(), super::TunnelError> {
        while let Err(err) = Self::wait_sack(socket, addr, conn_id).await {
            tracing::warn!(?err, "udp wait sack error");
        }
        Ok(())
    }

    pub async fn try_connect_with_socket(
        &self,
        socket: UdpSocket,
    ) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        let addr = super::check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "udp")?;
        log::warn!("udp connect: {:?}", self.addr);

        #[cfg(target_os = "windows")]
        crate::arch::windows::disable_connection_reset(&socket)?;

        // send syn
        let conn_id = rand::random();
        let udp_packet = UdpPacket::new_syn_packet(conn_id);
        let b = encode_to_bytes::<_, UDP_DATA_MTU>(&udp_packet);
        let ret = socket.send_to(&b, &addr).await?;
        tracing::warn!(?udp_packet, ?ret, "udp send syn");

        // wait sack
        tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            Self::wait_sack_loop(&socket, addr, conn_id),
        )
        .await??;

        // sack done
        let local_addr = socket.local_addr().unwrap().to_string();
        Ok(Box::new(TunnelWithCustomInfo::new(
            get_tunnel_from_socket(Arc::new(socket), addr, conn_id),
            TunnelInfo {
                tunnel_type: "udp".to_owned(),
                local_addr: super::build_url_from_socket_addr(&local_addr, "udp").into(),
                remote_addr: self.remote_url().into(),
            },
        )))
    }

    async fn connect_with_default_bind(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        return self.try_connect_with_socket(socket).await;
    }

    async fn connect_with_custom_bind(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let futures = FuturesUnordered::new();

        for bind_addr in self.bind_addrs.iter() {
            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(*bind_addr),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )?;
            setup_sokcet2(&socket2_socket, &bind_addr)?;
            let socket = UdpSocket::from_std(socket2_socket.into())?;
            futures.push(self.try_connect_with_socket(socket));
        }
        wait_for_connect_futures(futures).await
    }
}

#[async_trait]
impl super::TunnelConnector for UdpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn super::Tunnel>, super::TunnelError> {
        if self.bind_addrs.is_empty() {
            self.connect_with_default_bind().await
        } else {
            self.connect_with_custom_bind().await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }

    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rand::Rng;
    use tokio::time::timeout;

    use crate::{
        common::global_ctx::tests::get_mock_global_ctx,
        tunnels::{
            check_scheme_and_get_socket_addr,
            common::{
                get_interface_name_by_ip, setup_sokcet2_ext,
                tests::{_tunnel_bench, _tunnel_echo_server, _tunnel_pingpong},
            },
        },
    };

    use super::*;

    #[tokio::test]
    async fn udp_pingpong() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5556".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5556".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn udp_bench() {
        let listener = UdpTunnelListener::new("udp://0.0.0.0:5555".parse().unwrap());
        let connector = UdpTunnelConnector::new("udp://127.0.0.1:5555".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn udp_bench_with_bind() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5554".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5554".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn udp_bench_with_bind_fail() {
        let listener = UdpTunnelListener::new("udp://127.0.0.1:5553".parse().unwrap());
        let mut connector = UdpTunnelConnector::new("udp://127.0.0.1:5553".parse().unwrap());
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    async fn send_random_data_to_socket(remote_url: url::Url) {
        let socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        socket
            .connect(format!(
                "{}:{}",
                remote_url.host().unwrap(),
                remote_url.port().unwrap()
            ))
            .await
            .unwrap();

        // get a random 100-len buf
        loop {
            let mut buf = vec![0u8; 100];
            rand::thread_rng().fill(&mut buf[..]);
            socket.send(&buf).await.unwrap();
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        }
    }

    #[tokio::test]
    async fn udp_multiple_conns() {
        let mut listener = UdpTunnelListener::new("udp://0.0.0.0:5557".parse().unwrap());
        listener.listen().await.unwrap();

        let _lis = tokio::spawn(async move {
            loop {
                let ret = listener.accept().await.unwrap();
                assert_eq!(
                    ret.info().unwrap().local_addr,
                    listener.local_url().to_string()
                );
                tokio::spawn(async move { _tunnel_echo_server(ret, false).await });
            }
        });

        let mut connector1 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());
        let mut connector2 = UdpTunnelConnector::new("udp://127.0.0.1:5557".parse().unwrap());

        let t1 = connector1.connect().await.unwrap();
        let t2 = connector2.connect().await.unwrap();

        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t1.info().unwrap().local_addr.parse().unwrap()),
        ));
        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t1.info().unwrap().remote_addr.parse().unwrap()),
        ));
        tokio::spawn(timeout(
            Duration::from_secs(2),
            send_random_data_to_socket(t2.info().unwrap().remote_addr.parse().unwrap()),
        ));

        let sender1 = tokio::spawn(async move {
            let mut sink = t1.pin_sink();
            let mut stream = t1.pin_stream();

            for i in 0..10 {
                sink.send(Bytes::from("hello1")).await.unwrap();
                let recv = stream.next().await.unwrap().unwrap();
                println!("t1 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv, Bytes::from("hello1"));
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let sender2 = tokio::spawn(async move {
            let mut sink = t2.pin_sink();
            let mut stream = t2.pin_stream();

            for i in 0..10 {
                sink.send(Bytes::from("hello2")).await.unwrap();
                let recv = stream.next().await.unwrap().unwrap();
                println!("t2 recv: {:?}, {:?}", recv, i);
                assert_eq!(recv, Bytes::from("hello2"));
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        });

        let _ = tokio::join!(sender1, sender2);
    }

    #[tokio::test]
    async fn udp_packet_print() {
        let udp_packet = UdpPacket::new_data_packet(1, vec![1, 2, 3, 4, 5]);
        let b = encode_to_bytes::<_, UDP_DATA_MTU>(&udp_packet);
        let a_udp_packet = rkyv_util::decode_from_bytes::<UdpPacket>(&b).unwrap();
        println!("{:?}, {:?}", udp_packet, a_udp_packet);
    }

    #[tokio::test]
    async fn bind_multi_ip_to_same_dev() {
        let global_ctx = get_mock_global_ctx();
        let ips = global_ctx
            .get_ip_collector()
            .collect_ip_addrs()
            .await
            .interface_ipv4s;
        if ips.is_empty() {
            return;
        }
        let bind_dev = get_interface_name_by_ip(&ips[0].parse().unwrap());

        for ip in ips {
            println!("bind to ip: {:?}, {:?}", ip, bind_dev);
            let addr = check_scheme_and_get_socket_addr::<SocketAddr>(
                &format!("udp://{}:11111", ip).parse().unwrap(),
                "udp",
            )
            .unwrap();
            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(addr),
                socket2::Type::DGRAM,
                Some(socket2::Protocol::UDP),
            )
            .unwrap();
            setup_sokcet2_ext(&socket2_socket, &addr, bind_dev.clone()).unwrap();
        }
    }
}
