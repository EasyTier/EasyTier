//! smoltcp stack generation and its peer-packet bridge.

use std::{
    net::IpAddr,
    sync::{Arc, Weak},
};

use pnet_packet::ipv4::Ipv4Packet;
use tokio::{
    sync::{Mutex, mpsc},
    task::JoinSet,
};

use crate::{
    foundation::task::reap_joinset_background,
    gateway::smoltcp::{BufferSize, Net, NetConfig, channel_device},
    packet::ZCPacket,
    peers::peer_manager::PeerManagerCore,
};

use super::{DataPlaneErrorKind, DataPlaneIoGuard};

pub(super) struct SmoltcpPlane {
    pub(super) ipv4_addr: cidr::Ipv4Inet,
    pub(super) net: Arc<Net>,
    generation: DataPlaneIoGuard,
    _forward_tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl SmoltcpPlane {
    pub(super) fn new(
        ipv4_addr: cidr::Ipv4Inet,
        peer_manager: Weak<PeerManagerCore>,
        packet_recv: Arc<Mutex<mpsc::Receiver<ZCPacket>>>,
    ) -> Self {
        let mut forward_tasks = JoinSet::new();
        let mut capabilities = smoltcp::phy::DeviceCapabilities::default();
        // Fragment offsets are expressed in eight-byte units.
        capabilities.max_transmission_unit = 1284;
        capabilities.medium = smoltcp::phy::Medium::Ip;
        let (device, stack_sink, mut stack_stream) =
            channel_device::ChannelDevice::new(capabilities);

        forward_tasks.spawn(async move {
            let mut packet_recv = packet_recv.lock().await;
            while let Some(packet) = packet_recv.recv().await {
                tracing::trace!(?packet, "deliver peer packet to smoltcp");
                if let Err(error) = stack_sink.send(Ok(packet.payload().to_vec())).await {
                    tracing::error!(?error, "deliver peer packet to smoltcp failed");
                }
            }
            tracing::debug!("peer-to-smoltcp bridge stopped");
        });

        forward_tasks.spawn(async move {
            while let Some(data) = stack_stream.recv().await {
                let Some(ipv4) = Ipv4Packet::new(&data) else {
                    tracing::error!(?data, "smoltcp emitted a non-IPv4 packet");
                    continue;
                };
                let destination = ipv4.get_destination();
                let Some(peer_manager) = peer_manager.upgrade() else {
                    tracing::debug!("smoltcp-to-peer bridge lost PeerManager");
                    return;
                };
                if let Err(error) = peer_manager
                    .send_msg_by_ip(
                        ZCPacket::new_with_payload(&data),
                        IpAddr::V4(destination),
                        false,
                    )
                    .await
                {
                    tracing::error!(?error, "deliver smoltcp packet to peer failed");
                }
            }
            tracing::debug!("smoltcp-to-peer bridge stopped");
        });

        let interface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let net = Net::new(
            device,
            NetConfig::new(
                interface_config,
                format!("{}/{}", ipv4_addr.address(), ipv4_addr.network_length())
                    .parse()
                    .expect("validated IPv4 prefix"),
                vec![
                    ipv4_addr
                        .address()
                        .to_string()
                        .parse()
                        .expect("validated IPv4 address"),
                ],
                Some(BufferSize {
                    tcp_rx_size: 1024 * 128,
                    tcp_tx_size: 1024 * 128,
                    ..Default::default()
                }),
            ),
        );

        let forward_tasks = Arc::new(std::sync::Mutex::new(forward_tasks));
        forward_tasks.lock().unwrap().spawn(reap_joinset_background(
            forward_tasks.clone(),
            "SmoltcpPlane",
        ));

        Self {
            ipv4_addr,
            net: Arc::new(net),
            generation: DataPlaneIoGuard::new(),
            _forward_tasks: forward_tasks,
        }
    }

    pub(super) fn lease(&self) -> DataPlaneIoGuard {
        self.generation.clone()
    }

    pub(super) fn close(&self, kind: DataPlaneErrorKind) {
        self.generation.close(kind);
    }
}

impl Drop for SmoltcpPlane {
    fn drop(&mut self) {
        self.close(DataPlaneErrorKind::HandleClosed);
    }
}
