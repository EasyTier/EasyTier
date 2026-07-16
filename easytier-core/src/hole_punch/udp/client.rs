use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
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

use crate::{
    config::PeerId,
    socket::udp::{UdpBindOptions, VirtualUdpSocketFactory},
    stun::StunInfoProvider,
};

use super::{
    HOLE_PUNCH_PACKET_BODY_LEN, SelectPunchListener, SendPunchPacketBothEasySym,
    SendPunchPacketCone, SendPunchPacketEasySym, SendPunchPacketHardSym, UdpHolePunchRuntime,
    UdpHolePunchSignalError, UdpHolePunchSignaling, UdpNatType, UdpPunchSocket, UdpSocketArray,
    new_hole_punch_packet,
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
const UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM: usize = 25;
const DST_PORT_OFFSET: u16 = 20;
const REMOTE_WAIT_TIME_MS: u64 = 5000;

pub fn apply_peer_easy_sym_port_offset(base_port: u16, peer_is_incremental: bool) -> u16 {
    let port = if peer_is_incremental {
        (base_port as u32).saturating_add(DST_PORT_OFFSET as u32)
    } else {
        (base_port as u32).saturating_sub(DST_PORT_OFFSET as u32)
    };
    port as u16
}

#[tracing::instrument(skip(runtime, signaling), fields(dst_peer_id), err)]
pub async fn punch_cone_to_cone<R, S>(
    runtime: Arc<R>,
    signaling: Arc<S>,
    dst_peer_id: PeerId,
) -> UdpHolePunchClientResult<Option<UdpPunchSocket>>
where
    R: UdpHolePunchRuntime,
    S: UdpHolePunchSignaling + 'static,
{
    tracing::info!(?dst_peer_id, "start hole punching");
    let tid = rand::random();

    let udp_array = UdpSocketArray::new_with_context(1, runtime.clone(), runtime.socket_context());

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

    let local_socket = UdpHolePunchRuntime::bind_udp(
        runtime.as_ref(),
        UdpBindOptions::hole_punch_control().with_context(
            runtime
                .socket_context()
                .with_ip_version(crate::socket::IpVersion::V4),
        ),
    )
    .await?;
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
        crate::runtime_time::sleep(std::time::Duration::from_millis(200)).await;

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
                Ok(socket) => {
                    tracing::info!(?socket, "hole punched");
                    return Ok(Some(socket));
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
    R: VirtualUdpSocketFactory,
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
    stun: Arc<dyn StunInfoProvider>,
    udp_array: RwLock<Option<Arc<UdpSocketArray<R>>>>,
    try_direct_connect: AtomicBool,
    punch_predictably: AtomicBool,
}

impl<R, S> UdpSymToConePunchClient<R, S>
where
    R: UdpHolePunchRuntime,
    S: UdpHolePunchSignaling + 'static,
{
    pub fn new(runtime: Arc<R>, signaling: Arc<S>, stun: Arc<dyn StunInfoProvider>) -> Self {
        Self {
            runtime,
            signaling,
            stun,
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

        let udp_array = Arc::new(UdpSocketArray::new_with_context(
            UDP_ARRAY_SIZE_FOR_HARD_SYM,
            self.runtime.clone(),
            self.runtime.socket_context(),
        ));
        udp_array.start().await?;
        wlocked.replace(udp_array.clone());
        Ok(udp_array)
    }

    async fn get_base_port_for_easy_sym(&self, my_nat_info: UdpNatType) -> Option<u16> {
        if my_nat_info.is_easy_sym() {
            match self.stun.get_udp_port_mapping(0).await {
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
    ) -> anyhow::Result<Option<UdpPunchSocket>> {
        let mut ret_socket = None;
        let mut finish_time: Option<Instant> = None;
        while finish_time.is_none() || finish_time.as_ref().unwrap().elapsed().as_millis() < 1000 {
            udp_array.send_with_all(packet, remote_mapped_addr).await?;

            crate::runtime_time::sleep(std::time::Duration::from_millis(200)).await;

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
                Ok(socket) => {
                    ret_socket.replace(socket);
                    break;
                }
                Err(e) => {
                    tracing::error!(?e, "failed to connect with socket");
                    udp_array.add_new_socket(socket.socket).await?;
                    continue;
                }
            }
        }

        Ok(ret_socket)
    }

    #[tracing::instrument(err(level = tracing::Level::ERROR), skip(self))]
    pub async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
        round: u32,
        last_port_idx: &mut usize,
        my_nat_info: UdpNatType,
    ) -> UdpHolePunchClientResult<Option<UdpPunchSocket>> {
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
            let socket = self.runtime.bind_direct_connect_udp().await?;
            if let Ok(socket) = self
                .runtime
                .connect_with_socket(socket, remote_mapped_addr)
                .await
            {
                return Ok(Some(socket));
            }
        }

        let stun_info = self.stun.get_stun_info();
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
            let ret_socket = self
                .check_hole_punch_result(&udp_array, &packet, tid, remote_mapped_addr, &punch_task)
                .await?;

            let task_ret = punch_task.await;
            tracing::debug!(?ret_socket, ?task_ret, "predictable punch task got result");
            if let Some(socket) = ret_socket {
                return Ok(Some(socket));
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
        let ret_socket = self
            .check_hole_punch_result(&udp_array, &packet, tid, remote_mapped_addr, &punch_task)
            .await?;

        let punch_task_result = punch_task.await;
        tracing::debug!(?punch_task_result, ?ret_socket, "punch task got result");

        if let Ok(Some(next_port_idx)) = punch_task_result {
            *last_port_idx = next_port_idx as usize;
        } else {
            *last_port_idx = rand::random();
        }

        Ok(ret_socket)
    }
}

pub struct UdpBothEasySymPunchClient<R, S>
where
    R: UdpHolePunchRuntime,
    S: UdpHolePunchSignaling + 'static,
{
    runtime: Arc<R>,
    signaling: Arc<S>,
    stun: Arc<dyn StunInfoProvider>,
}

impl<R, S> UdpBothEasySymPunchClient<R, S>
where
    R: UdpHolePunchRuntime,
    S: UdpHolePunchSignaling + 'static,
{
    pub fn new(runtime: Arc<R>, signaling: Arc<S>, stun: Arc<dyn StunInfoProvider>) -> Self {
        Self {
            runtime,
            signaling,
            stun,
        }
    }

    #[tracing::instrument(ret, skip(self))]
    pub async fn do_hole_punching(
        &self,
        dst_peer_id: PeerId,
        my_nat_info: UdpNatType,
        peer_nat_info: UdpNatType,
        is_busy: &mut bool,
    ) -> UdpHolePunchClientResult<Option<UdpPunchSocket>> {
        *is_busy = false;

        let udp_array = UdpSocketArray::new_with_context(
            UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM,
            self.runtime.clone(),
            self.runtime.socket_context(),
        );
        udp_array.start().await?;

        let cur_mapped_addr = self.stun.get_udp_port_mapping(0).await?;
        let my_public_ip = match cur_mapped_addr.ip() {
            IpAddr::V4(v4) => v4,
            _ => {
                return Err(anyhow::anyhow!("ipv6 is not supported").into());
            }
        };
        let me_is_incremental = my_nat_info
            .get_inc_of_easy_sym()
            .ok_or(anyhow::anyhow!("me_is_incremental is required"))?;
        let peer_is_incremental = peer_nat_info
            .get_inc_of_easy_sym()
            .ok_or(anyhow::anyhow!("peer_is_incremental is required"))?;

        let tid = rand::random();
        udp_array.add_intreast_tid(tid);

        let remote_ret = self
            .signaling
            .send_punch_packet_both_easy_sym(
                dst_peer_id,
                SendPunchPacketBothEasySym {
                    transaction_id: tid,
                    public_ip: my_public_ip,
                    dst_port_num: if me_is_incremental {
                        cur_mapped_addr.port().saturating_add(DST_PORT_OFFSET)
                    } else {
                        cur_mapped_addr.port().saturating_sub(DST_PORT_OFFSET)
                    } as u32,
                    udp_socket_count: UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM as u32,
                    wait_time_ms: REMOTE_WAIT_TIME_MS as u32,
                },
            )
            .await?;

        if remote_ret.is_busy {
            *is_busy = true;
            return Err(anyhow::anyhow!("remote is busy").into());
        }

        let mut remote_mapped_addr = remote_ret
            .base_mapped_addr
            .ok_or(anyhow::anyhow!("remote_mapped_addr is required"))?;

        let now = Instant::now();
        remote_mapped_addr.set_port(apply_peer_easy_sym_port_offset(
            remote_mapped_addr.port(),
            peer_is_incremental,
        ));
        tracing::debug!(
            ?remote_mapped_addr,
            ?remote_ret,
            "start send hole punch packet for both easy sym"
        );

        while now.elapsed().as_millis() < (REMOTE_WAIT_TIME_MS + 1000).into() {
            udp_array
                .send_with_all(
                    &new_hole_punch_packet(tid, HOLE_PUNCH_PACKET_BODY_LEN).into_bytes(),
                    remote_mapped_addr,
                )
                .await?;

            crate::runtime_time::sleep(std::time::Duration::from_millis(100)).await;

            let Some(socket) = udp_array.try_fetch_punched_socket(tid) else {
                tracing::trace!(
                    ?remote_mapped_addr,
                    ?tid,
                    "no punched socket found, send some more hole punch packets"
                );
                continue;
            };

            tracing::info!(
                ?socket,
                ?remote_mapped_addr,
                ?tid,
                "got punched socket in both easy sym"
            );

            for _ in 0..2 {
                match self
                    .runtime
                    .connect_with_socket(socket.socket.clone(), remote_mapped_addr)
                    .await
                {
                    Ok(socket) => {
                        return Ok(Some(socket));
                    }
                    Err(e) => {
                        tracing::error!(?e, "failed to connect with socket");
                        continue;
                    }
                }
            }
            udp_array.add_new_socket(socket.socket).await?;
        }

        Ok(None)
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
        socket::udp::VirtualUdpSocket,
    };

    struct MockSocket {
        local_addr: SocketAddr,
    }

    #[async_trait]
    impl VirtualUdpSocket for MockSocket {
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
        bind_options: tokio::sync::Mutex<Vec<UdpBindOptions>>,
    }

    impl MockRuntime {
        fn new() -> Self {
            Self {
                bind_count: AtomicUsize::new(0),
                resolve_count: AtomicUsize::new(0),
                bind_options: tokio::sync::Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl UdpHolePunchRuntime for MockRuntime {
        type Socket = MockSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.bind_options.lock().await.push(options);
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
        ) -> anyhow::Result<UdpPunchSocket> {
            unimplemented!("not used by cone client tests")
        }
    }

    #[derive(Default)]
    struct MockStunInfoProvider {
        port_mapping_count: AtomicUsize,
    }

    #[async_trait]
    impl StunInfoProvider for MockStunInfoProvider {
        fn get_stun_info(&self) -> StunInfo {
            StunInfo {
                public_ip: vec!["127.0.0.1".to_string()],
                ..Default::default()
            }
        }

        async fn get_udp_port_mapping(&self, _port: u16) -> anyhow::Result<SocketAddr> {
            self.port_mapping_count.fetch_add(1, Ordering::Relaxed);
            Ok(SocketAddr::from(([203, 0, 113, 1], 10000)))
        }

        async fn get_tcp_port_mapping(&self, _port: u16) -> anyhow::Result<SocketAddr> {
            unreachable!("TCP mapping is not used by UDP hole-punch tests")
        }

        fn update_stun_info(&self) {}
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

    #[tokio::test]
    async fn default_direct_connect_bind_uses_direct_connect_purpose() {
        let runtime = MockRuntime::new();

        let socket = runtime.bind_direct_connect_udp().await.unwrap();

        assert_eq!(socket.local_addr().unwrap().port(), 10000);
        let bind_options = runtime.bind_options.lock().await;
        assert_eq!(
            bind_options.as_slice(),
            &[UdpBindOptions::direct_connect().with_ip_version(crate::socket::IpVersion::V4)]
        );
    }

    struct RecordingSignaling {
        easy_requests: tokio::sync::Mutex<Vec<SendPunchPacketEasySym>>,
        hard_requests: tokio::sync::Mutex<Vec<SendPunchPacketHardSym>>,
        both_requests: tokio::sync::Mutex<Vec<SendPunchPacketBothEasySym>>,
        both_response: super::super::SendPunchPacketBothEasySymResponse,
        next_port_index: u32,
    }

    impl RecordingSignaling {
        fn new(next_port_index: u32) -> Self {
            Self {
                easy_requests: tokio::sync::Mutex::new(Vec::new()),
                hard_requests: tokio::sync::Mutex::new(Vec::new()),
                both_requests: tokio::sync::Mutex::new(Vec::new()),
                both_response: super::super::SendPunchPacketBothEasySymResponse {
                    is_busy: false,
                    base_mapped_addr: Some(SocketAddr::from(([127, 0, 0, 1], 40144))),
                },
                next_port_index,
            }
        }

        fn with_both_response(
            mut self,
            both_response: super::super::SendPunchPacketBothEasySymResponse,
        ) -> Self {
            self.both_response = both_response;
            self
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
            request: SendPunchPacketBothEasySym,
        ) -> Result<super::super::SendPunchPacketBothEasySymResponse, UdpHolePunchSignalError>
        {
            self.both_requests.lock().await.push(request);
            Ok(self.both_response.clone())
        }
    }

    #[tokio::test]
    async fn sym_to_cone_easy_sym_uses_port_mapping_in_predictable_request() {
        let runtime = Arc::new(MockRuntime::new());
        let signaling = Arc::new(RecordingSignaling::new(42));
        let stun = Arc::new(MockStunInfoProvider::default());
        let client = UdpSymToConePunchClient::new(runtime.clone(), signaling.clone(), stun.clone());
        client.set_try_direct_connect(false);

        let mut last_port_idx = 7;
        let ret = client
            .do_hole_punching(2, 3, &mut last_port_idx, NatType::SymmetricEasyInc.into())
            .await
            .unwrap();

        assert!(ret.is_none());
        assert_eq!(stun.port_mapping_count.load(Ordering::Relaxed), 1);

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
        let stun = Arc::new(MockStunInfoProvider::default());
        let client = UdpSymToConePunchClient::new(runtime.clone(), signaling.clone(), stun.clone());
        client.set_try_direct_connect(false);

        let mut last_port_idx = 123;
        let ret = client
            .do_hole_punching(2, 4, &mut last_port_idx, NatType::Symmetric.into())
            .await
            .unwrap();

        assert!(ret.is_none());
        assert_eq!(stun.port_mapping_count.load(Ordering::Relaxed), 0);
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

    #[test]
    fn both_easy_sym_port_offset_preserves_old_proto_cast_semantics() {
        assert_eq!(apply_peer_easy_sym_port_offset(65530, true), 14);
        assert_eq!(apply_peer_easy_sym_port_offset(10, false), 0);
    }

    #[tokio::test]
    async fn both_easy_sym_sends_remote_request_and_reports_busy() {
        let runtime = Arc::new(MockRuntime::new());
        let stun = Arc::new(MockStunInfoProvider::default());
        let signaling = Arc::new(RecordingSignaling::new(0).with_both_response(
            super::super::SendPunchPacketBothEasySymResponse {
                is_busy: true,
                base_mapped_addr: None,
            },
        ));
        let client =
            UdpBothEasySymPunchClient::new(runtime.clone(), signaling.clone(), stun.clone());

        let mut is_busy = false;
        let err = client
            .do_hole_punching(
                2,
                NatType::SymmetricEasyInc.into(),
                NatType::SymmetricEasyDec.into(),
                &mut is_busy,
            )
            .await
            .unwrap_err();

        assert!(is_busy);
        assert!(err.to_string().contains("remote is busy"));
        assert_eq!(stun.port_mapping_count.load(Ordering::Relaxed), 1);
        assert_eq!(
            runtime.bind_count.load(Ordering::Relaxed),
            UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM
        );

        let both_requests = signaling.both_requests.lock().await;
        assert_eq!(both_requests.len(), 1);
        let req = &both_requests[0];
        assert_eq!(req.public_ip, Ipv4Addr::new(203, 0, 113, 1));
        assert_eq!(req.dst_port_num, 10020);
        assert_eq!(
            req.udp_socket_count,
            UDP_ARRAY_SIZE_FOR_BOTH_EASY_SYM as u32
        );
        assert_eq!(req.wait_time_ms, REMOTE_WAIT_TIME_MS as u32);
    }
}
