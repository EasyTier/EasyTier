use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinSet;

use crate::{
    foundation::time::{Duration, timeout},
    packet::ZCPacket,
};

use super::tokio_smoltcp::{BufferSize, Net, NetConfig, channel_device};
use crate::gateway::proxy::runtime::TcpProxyStream;

type SmolTcpAcceptResult = anyhow::Result<(super::tokio_smoltcp::TcpStream, SocketAddr)>;

pub struct SmolTcpStack {
    ingress_tx: mpsc::Sender<ZCPacket>,
    output_rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    net: Arc<Mutex<Option<Net>>>,
    listener_tx: mpsc::UnboundedSender<SmolTcpAcceptResult>,
    listener_rx: Mutex<mpsc::UnboundedReceiver<SmolTcpAcceptResult>>,
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

        let (listener_tx, listener_rx) = mpsc::unbounded_channel();
        Ok(Arc::new(Self {
            ingress_tx,
            output_rx: Mutex::new(Some(stack_stream)),
            net: Arc::new(Mutex::new(Some(net))),
            listener_tx,
            listener_rx: Mutex::new(listener_rx),
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

    pub async fn add_listener(&self) {
        let tx = self.listener_tx.clone();
        let locked_net = self.net.lock().await;
        let mut tcp = locked_net
            .as_ref()
            .expect("smoltcp net initialized")
            .tcp_bind("0.0.0.0:8899".parse().unwrap())
            .await
            .unwrap();
        self.tasks.lock().unwrap().spawn(async move {
            let ret = timeout(Duration::from_secs(10), tcp.accept()).await;
            if let Ok(accept_ret) = ret {
                let _ =
                    tx.send(accept_ret.map_err(|err| {
                        anyhow::anyhow!("smol tcp listener accept failed: {:?}", err)
                    }));
            } else {
                tracing::error!(
                    target: "easytier_core::gateway::stack",
                    "smol tcp listener accept timeout"
                );
            }
        });
        tracing::info!(
            target: "easytier_core::gateway::stack",
            "smol tcp listener added"
        );
    }

    pub async fn accept(&self) -> anyhow::Result<(SocketAddr, Box<dyn TcpProxyStream>)> {
        let (stream, src) = self
            .listener_rx
            .lock()
            .await
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("smoltcp listener closed"))??;
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
