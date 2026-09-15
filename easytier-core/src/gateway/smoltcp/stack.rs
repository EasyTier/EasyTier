use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;

use crate::packet::ZCPacket;

use super::tokio_smoltcp::{BufferSize, Net, NetConfig, TcpListener, channel_device};
use crate::gateway::proxy::traits::TcpProxyStream;

pub struct SmolTcpStack {
    ingress_tx: mpsc::Sender<ZCPacket>,
    output_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    listener: Mutex<TcpListener>,
    _net: Net,
    tasks: Arc<std::sync::Mutex<JoinSet<()>>>,
}

impl SmolTcpStack {
    pub async fn new(local_ip: Ipv4Addr) -> anyhow::Result<Arc<Self>> {
        let tasks = Arc::new(std::sync::Mutex::new(JoinSet::new()));
        let mut cap = smoltcp::phy::DeviceCapabilities::default();
        cap.max_transmission_unit = 1280;
        cap.medium = smoltcp::phy::Medium::Ip;
        let (dev, stack_sink, stack_stream) = channel_device::ChannelDevice::new(cap);

        let (ingress_tx, mut ingress_rx) = mpsc::channel::<ZCPacket>(1000);
        tasks.lock().unwrap().spawn(async move {
            while let Some(packet) = ingress_rx.recv().await {
                tracing::trace!(
                    target: "easytier_core::gateway::stack",
                    ?packet,
                    "receive from peer send to smoltcp packet"
                );
                if let Err(err) = stack_sink.send(Ok(packet.payload().to_vec())).await {
                    tracing::error!(
                        target: "easytier_core::gateway::stack",
                        ?err,
                        "send to smoltcp stack failed"
                    );
                }
            }
            tracing::error!(
                target: "easytier_core::gateway::stack",
                "smoltcp stack sink exited"
            );
        });

        let interface_config = smoltcp::iface::Config::new(smoltcp::wire::HardwareAddress::Ip);
        let net = Net::new(
            dev,
            NetConfig::new(
                interface_config,
                format!("{local_ip}/24").parse().unwrap(),
                vec![format!("{local_ip}").parse().unwrap()],
                Some(BufferSize {
                    tcp_rx_size: 1024 * 16,
                    tcp_tx_size: 1024 * 16,
                    ..Default::default()
                }),
            ),
        );
        net.set_any_ip(true);
        let listener = net
            .tcp_bind("0.0.0.0:8899".parse().unwrap())
            .await
            .map_err(|error| anyhow::anyhow!("bind smoltcp listener failed: {error}"))?;

        Ok(Arc::new(Self {
            ingress_tx,
            output_rx: Mutex::new(Some(stack_stream)),
            listener: Mutex::new(listener),
            _net: net,
            tasks,
        }))
    }

    pub fn local_port(&self) -> u16 {
        8899
    }

    pub async fn send_ingress(&self, packet: ZCPacket) -> anyhow::Result<()> {
        self.ingress_tx
            .send(packet)
            .await
            .map_err(|err| anyhow::anyhow!("send to smoltcp ingress failed: {:?}", err))
    }

    pub async fn take_output_rx(&self) -> anyhow::Result<mpsc::Receiver<Vec<u8>>> {
        self.output_rx
            .lock()
            .await
            .take()
            .ok_or_else(|| anyhow::anyhow!("smoltcp output receiver already taken"))
    }

    pub async fn accept(&self) -> anyhow::Result<(SocketAddr, Box<dyn TcpProxyStream>)> {
        let (stream, src) = self
            .listener
            .lock()
            .await
            .accept()
            .await
            .map_err(|error| anyhow::anyhow!("smoltcp listener accept failed: {error}"))?;
        tracing::info!(
            target: "easytier_core::gateway::stack",
            ?src,
            "smol tcp listener accepted"
        );
        Ok((src, Box::new(stream)))
    }
}

impl Drop for SmolTcpStack {
    fn drop(&mut self) {
        self.tasks.lock().unwrap().abort_all();
    }
}

pub fn output_dst_ip(data: &[u8]) -> anyhow::Result<IpAddr> {
    let ipv4 = smoltcp::wire::Ipv4Packet::new_checked(data)
        .map_err(|err| anyhow::anyhow!("smoltcp output is not an IPv4 packet: {:?}", err))?;
    Ok(IpAddr::V4(ipv4.dst_addr()))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use smoltcp::wire::{Ipv4Address, TcpControl, TcpSeqNumber};

    use super::SmolTcpStack;
    use crate::{
        gateway::smoltcp::tokio_smoltcp::test_utils::{TcpPackets, recv_tcp},
        packet::ZCPacket,
    };

    const LOCAL_ADDR: Ipv4Address = Ipv4Address::new(192, 88, 99, 254);
    const LOCAL_PORT: u16 = 8899;
    const PACKETS: TcpPackets = TcpPackets::new(LOCAL_ADDR, LOCAL_PORT);

    #[tokio::test]
    async fn accepts_concurrent_connections_with_one_logical_listener() {
        let stack = SmolTcpStack::new(LOCAL_ADDR).await.unwrap();
        let mut output = stack.take_output_rx().await.unwrap();
        let client_addr = Ipv4Address::new(192, 88, 99, 1);

        for (port, sequence) in [(40000, 1000), (40001, 2000)] {
            stack
                .send_ingress(ZCPacket::new_with_payload(&PACKETS.syn(
                    client_addr,
                    port,
                    sequence,
                )))
                .await
                .unwrap();
        }

        let mut syn_acks = Vec::new();
        for _ in 0..2 {
            let syn_ack = recv_tcp(&mut output).await;
            assert_eq!(syn_ack.control, TcpControl::Syn);
            syn_acks.push((syn_ack.dst_port, syn_ack.sequence));
        }
        for (port, sequence) in syn_acks {
            let client_sequence = if port == 40000 { 1001 } else { 2001 };
            stack
                .send_ingress(ZCPacket::new_with_payload(&PACKETS.ack(
                    client_addr,
                    port,
                    TcpSeqNumber(client_sequence),
                    sequence + 1,
                )))
                .await
                .unwrap();
        }

        let mut peers = Vec::new();
        let mut streams = Vec::new();
        for _ in 0..2 {
            let (peer, stream) = tokio::time::timeout(Duration::from_secs(1), stack.accept())
                .await
                .unwrap()
                .unwrap();
            peers.push(peer.port());
            streams.push(stream);
        }
        peers.sort_unstable();
        assert_eq!(peers, vec![40000, 40001]);
    }
}
