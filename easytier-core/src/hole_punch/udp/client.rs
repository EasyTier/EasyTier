use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use guarden::defer;
use quanta::Instant;
use rand::Rng;
use tokio::sync::RwLock;
use tokio_util::task::AbortOnDropHandle;

use crate::{config::PeerId, tunnel::Tunnel};

use super::{
    HOLE_PUNCH_PACKET_BODY_LEN, SelectPunchListener, SendPunchPacketCone, SendPunchPacketEasySym,
    SendPunchPacketHardSym, UdpHolePunchRuntime, UdpHolePunchSignalError, UdpHolePunchSignaling,
    UdpNatType, UdpSocketArray, new_hole_punch_packet,
};

#[derive(Debug, thiserror::Error)]
pub enum UdpHolePunchClientError {
    #[error("signaling: {0}")]
    Signaling(#[from] UdpHolePunchSignalError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type UdpHolePunchClientResult<T> = Result<T, UdpHolePunchClientError>;

const UDP_ARRAY_SIZE_FOR_HARD_SYM: usize = 84;

#[tracing::instrument(skip(runtime, signaling), fields(dst_peer_id), err)]
pub async fn punch_cone_to_cone<R, S>(
    runtime: Arc<R>,
    signaling: Arc<S>,
    dst_peer_id: PeerId,
) -> UdpHolePunchClientResult<Option<Box<dyn Tunnel>>>
where
    R: UdpHolePunchRuntime,
    S: UdpHolePunchSignaling + 'static,
{
    tracing::info!(?dst_peer_id, "start hole punching");
    let tid = rand::random();

    let udp_array = UdpSocketArray::new(1, runtime.clone());

    let resp = signaling
        .select_punch_listener(
            dst_peer_id,
            SelectPunchListener {
                force_new: false,
                prefer_port_mapping: true,
            },
        )
        .await?;
    let remote_mapped_addr = resp.listener_mapped_addr;

    let local_socket = runtime.bind_udp(None).await?;
    let resolved = runtime
        .resolve_udp_public_addr(local_socket.clone())
        .await?;
    let local_mapped_addr = resolved.mapped_addr;
    let _local_port_mapping_lease = resolved.port_mapping_lease;

    tracing::debug!(
        ?local_mapped_addr,
        ?remote_mapped_addr,
        "hole punch got remote listener"
    );

    udp_array.add_new_socket(local_socket).await?;
    udp_array.add_intreast_tid(tid);
    let punch_packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();

    send_from_local(&udp_array, &punch_packet, remote_mapped_addr).await?;

    let signaling_for_task = signaling.clone();
    let punch_task = AbortOnDropHandle::new(tokio::spawn(async move {
        if let Err(e) = signaling_for_task
            .send_punch_packet_cone(
                dst_peer_id,
                SendPunchPacketCone {
                    listener_mapped_addr: remote_mapped_addr,
                    dest_addr: local_mapped_addr,
                    transaction_id: tid,
                    packet_count_per_batch: 2,
                    packet_batch_count: 5,
                    packet_interval_ms: 400,
                },
            )
            .await
        {
            tracing::error!(?e, "failed to call remote send punch packet");
        }
    }));

    let mut finish_time: Option<Instant> = None;
    while finish_time.is_none() || finish_time.as_ref().unwrap().elapsed().as_millis() < 1000 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        if finish_time.is_none() && punch_task.is_finished() {
            finish_time = Some(Instant::now());
        }

        let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
            tracing::debug!("no punched socket found, send some more hole punch packets");
            send_from_local(&udp_array, &punch_packet, remote_mapped_addr).await?;
            continue;
        };

        tracing::debug!(?socket, ?tid, "punched socket found, try connect with it");

        for _ in 0..2 {
            match runtime
                .connect_with_socket(socket.socket.clone(), remote_mapped_addr)
                .await
            {
                Ok(tunnel) => {
                    tracing::info!(?tunnel, "hole punched");
                    return Ok(Some(tunnel));
                }
                Err(e) => {
                    tracing::error!(?e, "failed to connect with socket");
                }
            }
        }
    }

    Ok(None)
}

async fn send_from_local<R>(
    udp_array: &UdpSocketArray<R>,
    punch_packet: &[u8],
    remote_mapped_addr: SocketAddr,
) -> UdpHolePunchClientResult<()>
where
    R: super::UdpPunchSocketFactory,
{
    udp_array
        .send_with_all(punch_packet, remote_mapped_addr)
        .await
        .map_err(anyhow::Error::from)?;
    Ok(())
}

pub struct UdpSymToConePunchClient<R, S>
where
    R: UdpHolePunchRuntime,
    S: UdpHolePunchSignaling + 'static,
{
    runtime: Arc<R>,
    signaling: Arc<S>,
    udp_array: RwLock<Option<Arc<UdpSocketArray<R>>>>,
    try_direct_connect: AtomicBool,
    punch_predictably: AtomicBool,
}

impl<R, S> UdpSymToConePunchClient<R, S>
where
    R: UdpHolePunchRuntime,
    S: UdpHolePunchSignaling + 'static,
{
    pub fn new(runtime: Arc<R>, signaling: Arc<S>) -> Self {
        Self {
            runtime,
            signaling,
            udp_array: RwLock::new(None),
            try_direct_connect: AtomicBool::new(true),
            punch_predictably: AtomicBool::new(true),
        }
    }

    pub fn set_try_direct_connect(&self, enabled: bool) {
        self.try_direct_connect.store(enabled, Ordering::Relaxed);
    }

    pub fn set_punch_predictably(&self, enabled: bool) {
        self.punch_predictably.store(enabled, Ordering::Relaxed);
    }

    pub async fn has_udp_array(&self) -> bool {
        self.udp_array.read().await.is_some()
    }

    pub async fn clear_udp_array(&self) {
        let mut wlocked = self.udp_array.write().await;
        wlocked.take();
    }

    async fn prepare_udp_array(&self) -> anyhow::Result<Arc<UdpSocketArray<R>>> {
        let rlocked = self.udp_array.read().await;
        if let Some(udp_array) = rlocked.clone() {
            return Ok(udp_array);
        }

        drop(rlocked);
        let mut wlocked = self.udp_array.write().await;
        if let Some(udp_array) = wlocked.clone() {
            return Ok(udp_array);
        }

        let udp_array = Arc::new(UdpSocketArray::new(
            UDP_ARRAY_SIZE_FOR_HARD_SYM,
            self.runtime.clone(),
        ));
        udp_array.start().await?;
        wlocked.replace(udp_array.clone());
        Ok(udp_array)
    }

    async fn get_base_port_for_easy_sym(&self, my_nat_info: UdpNatType) -> Option<u16> {
        if my_nat_info.is_easy_sym() {
            match self.runtime.get_udp_port_mapping(0).await {
                Ok(addr) => Some(addr.port()),
                ret => {
                    tracing::warn!(?ret, "failed to get udp port mapping for easy sym");
                    None
                }
            }
        } else {
            None
        }
    }

    async fn remote_send_hole_punch_packet_predictable(
        signaling: Arc<S>,
        dst_peer_id: PeerId,
        base_port_for_easy_sym: Option<u16>,
        my_nat_info: UdpNatType,
        remote_mapped_addr: SocketAddr,
        public_ips: Vec<Ipv4Addr>,
        tid: u32,
    ) {
        let Some(inc) = my_nat_info.get_inc_of_easy_sym() else {
            return;
        };
        let req = SendPunchPacketEasySym {
            listener_mapped_addr: remote_mapped_addr,
            public_ips,
            transaction_id: tid,
            base_port_num: base_port_for_easy_sym.unwrap() as u32,
            max_port_num: 50,
            is_incremental: inc,
        };
        tracing::debug!(?req, "send punch packet for easy sym start");
        let ret = signaling.send_punch_packet_easy_sym(dst_peer_id, req).await;
        tracing::debug!(?ret, "send punch packet for easy sym return");
    }

    async fn remote_send_hole_punch_packet_random(
        signaling: Arc<S>,
        dst_peer_id: PeerId,
        remote_mapped_addr: SocketAddr,
        public_ips: Vec<Ipv4Addr>,
        tid: u32,
        round: u32,
        port_index: u32,
    ) -> Option<u32> {
        let req = SendPunchPacketHardSym {
            listener_mapped_addr: remote_mapped_addr,
            public_ips,
            transaction_id: tid,
            round,
            port_index,
        };
        tracing::debug!(?req, "send punch packet for hard sym start");
        match signaling.send_punch_packet_hard_sym(dst_peer_id, req).await {
            Err(e) => {
                tracing::error!(?e, "failed to send punch packet for hard sym");
                None
            }
            Ok(resp) => Some(resp.next_port_index),
        }
    }

    async fn check_hole_punch_result<T>(
        &self,
        udp_array: &Arc<UdpSocketArray<R>>,
        packet: &[u8],
        tid: u32,
        remote_mapped_addr: SocketAddr,
        punch_task: &AbortOnDropHandle<T>,
    ) -> anyhow::Result<Option<Box<dyn Tunnel>>> {
        let mut ret_tunnel: Option<Box<dyn Tunnel>> = None;
        let mut finish_time: Option<Instant> = None;
        while finish_time.is_none() || finish_time.as_ref().unwrap().elapsed().as_millis() < 1000 {
            udp_array.send_with_all(packet, remote_mapped_addr).await?;

            tokio::time::sleep(std::time::Duration::from_millis(200)).await;

            if finish_time.is_none() && punch_task.is_finished() {
                finish_time = Some(Instant::now());
            }

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::debug!("no punched socket found, wait for more time");
                continue;
            };

            match self
                .runtime
                .connect_with_socket(socket.socket.clone(), remote_mapped_addr)
                .await
            {
                Ok(tunnel) => {
                    ret_tunnel.replace(tunnel);
                    break;
                }
                Err(e) => {
                    tracing::error!(?e, "failed to connect with socket");
                    udp_array.add_new_socket(socket.socket).await?;
                    continue;
                }
            }
        }

        Ok(ret_tunnel)
    }

    #[tracing::instrument(err(level = tracing::Level::ERROR), skip(self))]
    pub async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
        round: u32,
        last_port_idx: &mut usize,
        my_nat_info: UdpNatType,
    ) -> UdpHolePunchClientResult<Option<Box<dyn Tunnel>>> {
        let udp_array = self.prepare_udp_array().await?;

        let resp = self
            .signaling
            .select_punch_listener(
                dst_peer_id,
                SelectPunchListener {
                    force_new: false,
                    prefer_port_mapping: true,
                },
            )
            .await?;

        let remote_mapped_addr = resp.listener_mapped_addr;

        if self.try_direct_connect.load(Ordering::Relaxed) {
            let socket = self.runtime.bind_udp(None).await?;
            if let Ok(tunnel) = self
                .runtime
                .connect_with_socket(socket, remote_mapped_addr)
                .await
            {
                return Ok(Some(tunnel));
            }
        }

        let stun_info = self.runtime.stun_info();
        let public_ips: Vec<Ipv4Addr> = stun_info
            .public_ip
            .iter()
            .filter_map(|x| x.parse().ok())
            .collect();
        if public_ips.is_empty() {
            return Err(anyhow::anyhow!("failed to get public ips").into());
        }

        let tid = rand::thread_rng().r#gen();
        let packet = new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes();
        udp_array.add_intreast_tid(tid);
        defer! { udp_array.remove_intreast_tid(tid); }

        let port_index = *last_port_idx as u32;
        let base_port_for_easy_sym = self.get_base_port_for_easy_sym(my_nat_info).await;
        udp_array.send_with_all(&packet, remote_mapped_addr).await?;

        if self.punch_predictably.load(Ordering::Relaxed) && base_port_for_easy_sym.is_some() {
            let signaling = self.signaling.clone();
            let punch_task = AbortOnDropHandle::new(tokio::spawn(
                Self::remote_send_hole_punch_packet_predictable(
                    signaling,
                    dst_peer_id,
                    base_port_for_easy_sym,
                    my_nat_info,
                    remote_mapped_addr,
                    public_ips.clone(),
                    tid,
                ),
            ));
            let ret_tunnel = self
                .check_hole_punch_result(&udp_array, &packet, tid, remote_mapped_addr, &punch_task)
                .await?;

            let task_ret = punch_task.await;
            tracing::debug!(?ret_tunnel, ?task_ret, "predictable punch task got result");
            if let Some(tunnel) = ret_tunnel {
                return Ok(Some(tunnel));
            }
        }

        let signaling = self.signaling.clone();
        let punch_task =
            AbortOnDropHandle::new(tokio::spawn(Self::remote_send_hole_punch_packet_random(
                signaling,
                dst_peer_id,
                remote_mapped_addr,
                public_ips.clone(),
                tid,
                round,
                port_index,
            )));
        let ret_tunnel = self
            .check_hole_punch_result(&udp_array, &packet, tid, remote_mapped_addr, &punch_task)
            .await?;

        let punch_task_result = punch_task.await;
        tracing::debug!(?punch_task_result, ?ret_tunnel, "punch task got result");

        if let Ok(Some(next_port_idx)) = punch_task_result {
            *last_port_idx = next_port_idx as usize;
        } else {
            *last_port_idx = rand::random();
        }

        Ok(ret_tunnel)
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_trait::async_trait;

    use super::*;
    use crate::{
        proto::common::{NatType, StunInfo},
        tunnel::Tunnel,
    };

    struct MockSocket {
        local_addr: SocketAddr,
    }

    #[async_trait]
    impl super::super::UdpPunchSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(self.local_addr)
        }

        async fn send_to(&self, _data: &[u8], _addr: SocketAddr) -> io::Result<usize> {
            Ok(0)
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    struct MockRuntime {
        bind_count: AtomicUsize,
        resolve_count: AtomicUsize,
        port_mapping_count: AtomicUsize,
    }

    impl MockRuntime {
        fn new() -> Self {
            Self {
                bind_count: AtomicUsize::new(0),
                resolve_count: AtomicUsize::new(0),
                port_mapping_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl UdpHolePunchRuntime for MockRuntime {
        type Socket = MockSocket;

        fn stun_info(&self) -> StunInfo {
            StunInfo {
                public_ip: vec!["127.0.0.1".to_string()],
                ..Default::default()
            }
        }

        async fn bind_udp(&self, _port: Option<u16>) -> anyhow::Result<Arc<Self::Socket>> {
            let bind_idx = self.bind_count.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(MockSocket {
                local_addr: SocketAddr::from(([127, 0, 0, 1], 10000 + bind_idx as u16)),
            }))
        }

        async fn resolve_udp_public_addr(
            &self,
            _socket: Arc<Self::Socket>,
        ) -> anyhow::Result<super::super::UdpResolvedPublicAddr> {
            self.resolve_count.fetch_add(1, Ordering::Relaxed);
            Ok(super::super::UdpResolvedPublicAddr {
                mapped_addr: SocketAddr::from(([203, 0, 113, 1], 10000)),
                port_mapping_lease: None,
            })
        }

        async fn get_udp_port_mapping(&self, _port: u16) -> anyhow::Result<SocketAddr> {
            self.port_mapping_count.fetch_add(1, Ordering::Relaxed);
            Ok(SocketAddr::from(([203, 0, 113, 1], 10000)))
        }

        async fn create_listener(
            &self,
            _prefer_port_mapping: bool,
        ) -> anyhow::Result<super::super::UdpPunchListener<Self::Socket>> {
            unimplemented!("not used by cone client tests")
        }

        async fn create_port_bound_listener(
            &self,
            _port: u16,
        ) -> anyhow::Result<super::super::UdpPunchListener<Self::Socket>> {
            unimplemented!("not used by cone client tests")
        }

        async fn connect_with_socket(
            &self,
            _socket: Arc<Self::Socket>,
            _remote: SocketAddr,
        ) -> anyhow::Result<Box<dyn Tunnel>> {
            unimplemented!("not used by cone client tests")
        }
    }

    struct RejectingSignaling;

    #[async_trait]
    impl UdpHolePunchSignaling for RejectingSignaling {
        async fn select_punch_listener(
            &self,
            _dst_peer_id: PeerId,
            _request: SelectPunchListener,
        ) -> Result<super::super::SelectPunchListenerResponse, UdpHolePunchSignalError> {
            Err(UdpHolePunchSignalError::InvalidServiceKey)
        }

        async fn send_punch_packet_cone(
            &self,
            _dst_peer_id: PeerId,
            _request: SendPunchPacketCone,
        ) -> Result<(), UdpHolePunchSignalError> {
            Ok(())
        }

        async fn send_punch_packet_hard_sym(
            &self,
            _dst_peer_id: PeerId,
            _request: super::super::SendPunchPacketHardSym,
        ) -> Result<super::super::SendPunchPacketHardSymResponse, UdpHolePunchSignalError> {
            unimplemented!("not used by cone client tests")
        }

        async fn send_punch_packet_easy_sym(
            &self,
            _dst_peer_id: PeerId,
            _request: super::super::SendPunchPacketEasySym,
        ) -> Result<(), UdpHolePunchSignalError> {
            unimplemented!("not used by cone client tests")
        }

        async fn send_punch_packet_both_easy_sym(
            &self,
            _dst_peer_id: PeerId,
            _request: super::super::SendPunchPacketBothEasySym,
        ) -> Result<super::super::SendPunchPacketBothEasySymResponse, UdpHolePunchSignalError>
        {
            unimplemented!("not used by cone client tests")
        }
    }

    #[tokio::test]
    async fn cone_punch_does_not_bind_or_resolve_before_listener_rpc_succeeds() {
        let runtime = Arc::new(MockRuntime::new());
        let signaling = Arc::new(RejectingSignaling);

        let err = punch_cone_to_cone(runtime.clone(), signaling, 2)
            .await
            .unwrap_err();

        assert!(matches!(
            err,
            UdpHolePunchClientError::Signaling(UdpHolePunchSignalError::InvalidServiceKey)
        ));
        assert_eq!(runtime.bind_count.load(Ordering::Relaxed), 0);
        assert_eq!(runtime.resolve_count.load(Ordering::Relaxed), 0);
    }

    struct RecordingSignaling {
        easy_requests: tokio::sync::Mutex<Vec<SendPunchPacketEasySym>>,
        hard_requests: tokio::sync::Mutex<Vec<SendPunchPacketHardSym>>,
        next_port_index: u32,
    }

    impl RecordingSignaling {
        fn new(next_port_index: u32) -> Self {
            Self {
                easy_requests: tokio::sync::Mutex::new(Vec::new()),
                hard_requests: tokio::sync::Mutex::new(Vec::new()),
                next_port_index,
            }
        }
    }

    #[async_trait]
    impl UdpHolePunchSignaling for RecordingSignaling {
        async fn select_punch_listener(
            &self,
            _dst_peer_id: PeerId,
            _request: SelectPunchListener,
        ) -> Result<super::super::SelectPunchListenerResponse, UdpHolePunchSignalError> {
            Ok(super::super::SelectPunchListenerResponse {
                listener_mapped_addr: SocketAddr::from(([127, 0, 0, 1], 30000)),
            })
        }

        async fn send_punch_packet_cone(
            &self,
            _dst_peer_id: PeerId,
            _request: SendPunchPacketCone,
        ) -> Result<(), UdpHolePunchSignalError> {
            Ok(())
        }

        async fn send_punch_packet_hard_sym(
            &self,
            _dst_peer_id: PeerId,
            request: SendPunchPacketHardSym,
        ) -> Result<super::super::SendPunchPacketHardSymResponse, UdpHolePunchSignalError> {
            self.hard_requests.lock().await.push(request);
            Ok(super::super::SendPunchPacketHardSymResponse {
                next_port_index: self.next_port_index,
            })
        }

        async fn send_punch_packet_easy_sym(
            &self,
            _dst_peer_id: PeerId,
            request: SendPunchPacketEasySym,
        ) -> Result<(), UdpHolePunchSignalError> {
            self.easy_requests.lock().await.push(request);
            Ok(())
        }

        async fn send_punch_packet_both_easy_sym(
            &self,
            _dst_peer_id: PeerId,
            _request: super::super::SendPunchPacketBothEasySym,
        ) -> Result<super::super::SendPunchPacketBothEasySymResponse, UdpHolePunchSignalError>
        {
            unimplemented!("not used by sym-to-cone client tests")
        }
    }

    #[tokio::test]
    async fn sym_to_cone_easy_sym_uses_port_mapping_in_predictable_request() {
        let runtime = Arc::new(MockRuntime::new());
        let signaling = Arc::new(RecordingSignaling::new(42));
        let client = UdpSymToConePunchClient::new(runtime.clone(), signaling.clone());
        client.set_try_direct_connect(false);

        let mut last_port_idx = 7;
        let ret = client
            .do_hole_punching(2, 3, &mut last_port_idx, NatType::SymmetricEasyInc.into())
            .await
            .unwrap();

        assert!(ret.is_none());
        assert_eq!(runtime.port_mapping_count.load(Ordering::Relaxed), 1);

        let easy_requests = signaling.easy_requests.lock().await;
        assert_eq!(easy_requests.len(), 1);
        let req = &easy_requests[0];
        assert_eq!(
            req.listener_mapped_addr,
            SocketAddr::from(([127, 0, 0, 1], 30000))
        );
        assert_eq!(req.public_ips, vec![Ipv4Addr::new(127, 0, 0, 1)]);
        assert_eq!(req.base_port_num, 10000);
        assert_eq!(req.max_port_num, 50);
        assert!(req.is_incremental);

        let hard_requests = signaling.hard_requests.lock().await;
        assert_eq!(hard_requests.len(), 1);
        assert_eq!(last_port_idx, 42);
    }

    #[tokio::test]
    async fn sym_to_cone_hard_sym_sends_random_request_and_updates_port_index() {
        let runtime = Arc::new(MockRuntime::new());
        let signaling = Arc::new(RecordingSignaling::new(321));
        let client = UdpSymToConePunchClient::new(runtime.clone(), signaling.clone());
        client.set_try_direct_connect(false);

        let mut last_port_idx = 123;
        let ret = client
            .do_hole_punching(2, 4, &mut last_port_idx, NatType::Symmetric.into())
            .await
            .unwrap();

        assert!(ret.is_none());
        assert_eq!(runtime.port_mapping_count.load(Ordering::Relaxed), 0);
        assert!(signaling.easy_requests.lock().await.is_empty());

        let hard_requests = signaling.hard_requests.lock().await;
        assert_eq!(hard_requests.len(), 1);
        let req = &hard_requests[0];
        assert_eq!(
            req.listener_mapped_addr,
            SocketAddr::from(([127, 0, 0, 1], 30000))
        );
        assert_eq!(req.public_ips, vec![Ipv4Addr::new(127, 0, 0, 1)]);
        assert_eq!(req.round, 4);
        assert_eq!(req.port_index, 123);
        assert_eq!(last_port_idx, 321);
    }
}
