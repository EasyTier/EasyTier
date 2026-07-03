use std::{net::SocketAddr, sync::Arc};

use quanta::Instant;
use tokio_util::task::AbortOnDropHandle;

use crate::{config::PeerId, tunnel::Tunnel};

use super::{
    HOLE_PUNCH_PACKET_BODY_LEN, SelectPunchListener, SendPunchPacketCone, UdpHolePunchRuntime,
    UdpHolePunchSignalError, UdpHolePunchSignaling, UdpSocketArray, new_hole_punch_packet,
};

#[derive(Debug, thiserror::Error)]
pub enum UdpHolePunchClientError {
    #[error("signaling: {0}")]
    Signaling(#[from] UdpHolePunchSignalError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type UdpHolePunchClientResult<T> = Result<T, UdpHolePunchClientError>;

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
    use crate::{proto::common::StunInfo, tunnel::Tunnel};

    #[derive(Default)]
    struct MockSocket;

    #[async_trait]
    impl super::super::UdpPunchSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 10000)))
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
    }

    impl MockRuntime {
        fn new() -> Self {
            Self {
                bind_count: AtomicUsize::new(0),
                resolve_count: AtomicUsize::new(0),
            }
        }
    }

    #[async_trait]
    impl UdpHolePunchRuntime for MockRuntime {
        type Socket = MockSocket;

        fn stun_info(&self) -> StunInfo {
            StunInfo::default()
        }

        async fn bind_udp(&self, _port: Option<u16>) -> anyhow::Result<Arc<Self::Socket>> {
            self.bind_count.fetch_add(1, Ordering::Relaxed);
            Ok(Arc::new(MockSocket))
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
}
