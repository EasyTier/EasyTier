use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
};

use async_trait::async_trait;
use tokio::{sync::mpsc, task::JoinHandle};

use crate::packet::ZCPacket;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IpPacketMeta {
    pub(crate) source: IpAddr,
    pub(crate) destination: IpAddr,
}

pub(crate) fn parse_ip_packet(packet: &[u8]) -> anyhow::Result<IpPacketMeta> {
    let Some(version) = packet.first().map(|byte| byte >> 4) else {
        anyhow::bail!("IP packet is empty");
    };
    match version {
        4 => parse_ipv4_packet(packet),
        6 => parse_ipv6_packet(packet),
        _ => anyhow::bail!("unsupported IP version: {version}"),
    }
}

fn parse_ipv4_packet(packet: &[u8]) -> anyhow::Result<IpPacketMeta> {
    if packet.len() < 20 {
        anyhow::bail!("IPv4 packet is shorter than the minimum header");
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if header_len < 20 || total_len < header_len || total_len != packet.len() {
        anyhow::bail!("invalid IPv4 header or total length");
    }
    Ok(IpPacketMeta {
        source: IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        )),
        destination: IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        )),
    })
}

fn parse_ipv6_packet(packet: &[u8]) -> anyhow::Result<IpPacketMeta> {
    if packet.len() < 40 {
        anyhow::bail!("IPv6 packet is shorter than the fixed header");
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    if (payload_len == 0 && packet.len() != 40)
        || (payload_len != 0 && 40 + payload_len != packet.len())
    {
        anyhow::bail!("IPv6 payload length does not match the packet");
    }
    Ok(IpPacketMeta {
        source: IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[8..24]).expect("checked IPv6 header length"),
        )),
        destination: IpAddr::V6(Ipv6Addr::from(
            <[u8; 16]>::try_from(&packet[24..40]).expect("checked IPv6 header length"),
        )),
    })
}

/// Receives raw IP packet bytes leaving the EasyTier peer graph.
///
/// The host decides whether packets go to a TUN device, a Go callback, or a
/// different packet backend. Core's internal packet headers never cross this
/// boundary, and core never performs platform I/O directly.
#[async_trait]
pub trait PacketSink: Send + Sync + 'static {
    async fn write_packet(&self, packet: Vec<u8>) -> anyhow::Result<()>;
}

#[async_trait]
impl PacketSink for mpsc::Sender<Vec<u8>> {
    async fn write_packet(&self, packet: Vec<u8>) -> anyhow::Result<()> {
        self.send(packet)
            .await
            .map_err(|_| anyhow::anyhow!("packet sink channel is closed"))
    }
}

pub(crate) struct PacketEgress {
    receiver: Mutex<Option<mpsc::Receiver<ZCPacket>>>,
    sink: Arc<dyn PacketSink>,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl PacketEgress {
    pub(crate) fn new(receiver: mpsc::Receiver<ZCPacket>, sink: Arc<dyn PacketSink>) -> Self {
        Self {
            receiver: Mutex::new(Some(receiver)),
            sink,
            task: Mutex::new(None),
        }
    }

    pub(crate) fn start(&self) -> anyhow::Result<()> {
        let mut receiver = self
            .receiver
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow::anyhow!("packet egress is one-shot and already started"))?;
        let sink = self.sink.clone();
        let task = tokio::spawn(async move {
            while let Some(packet) = receiver.recv().await {
                if let Err(error) = sink.write_packet(packet.payload().to_vec()).await {
                    tracing::warn!(?error, "host packet sink rejected an egress packet");
                }
            }
        });
        *self.task.lock().unwrap() = Some(task);
        Ok(())
    }

    pub(crate) async fn stop(&self) {
        let task = self.task.lock().unwrap().take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        self.receiver.lock().unwrap().take();
    }
}

impl Drop for PacketEgress {
    fn drop(&mut self) {
        if let Some(task) = self.task.lock().unwrap().take() {
            task.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::foundation::time::{Duration, timeout};

    use super::*;

    #[test]
    fn parses_ipv4_and_ipv6_packet_endpoints() {
        let mut ipv4 = vec![0u8; 20];
        ipv4[0] = 0x45;
        ipv4[2..4].copy_from_slice(&20u16.to_be_bytes());
        ipv4[12..16].copy_from_slice(&[10, 1, 0, 1]);
        ipv4[16..20].copy_from_slice(&[10, 2, 0, 1]);
        assert_eq!(
            parse_ip_packet(&ipv4).unwrap(),
            IpPacketMeta {
                source: "10.1.0.1".parse().unwrap(),
                destination: "10.2.0.1".parse().unwrap(),
            }
        );

        let mut ipv6 = vec![0u8; 40];
        ipv6[0] = 0x60;
        ipv6[8..24].copy_from_slice(&"fd00::1".parse::<Ipv6Addr>().unwrap().octets());
        ipv6[24..40].copy_from_slice(&"fd00::2".parse::<Ipv6Addr>().unwrap().octets());
        assert_eq!(
            parse_ip_packet(&ipv6).unwrap(),
            IpPacketMeta {
                source: "fd00::1".parse().unwrap(),
                destination: "fd00::2".parse().unwrap(),
            }
        );
    }

    #[test]
    fn rejects_truncated_or_unknown_ip_packets() {
        assert!(parse_ip_packet(&[]).is_err());
        assert!(parse_ip_packet(&[0x70]).is_err());
        assert!(parse_ip_packet(&[0x45; 19]).is_err());
        assert!(parse_ip_packet(&[0x60; 39]).is_err());

        let mut ipv4_with_trailing_bytes = vec![0u8; 21];
        ipv4_with_trailing_bytes[0] = 0x45;
        ipv4_with_trailing_bytes[2..4].copy_from_slice(&20u16.to_be_bytes());
        assert!(parse_ip_packet(&ipv4_with_trailing_bytes).is_err());

        let mut unsupported_ipv6_jumbogram = vec![0u8; 41];
        unsupported_ipv6_jumbogram[0] = 0x60;
        assert!(parse_ip_packet(&unsupported_ipv6_jumbogram).is_err());
    }

    #[tokio::test]
    async fn packet_egress_forwards_to_host_sink_and_joins_on_stop() {
        let (core_tx, core_rx) = mpsc::channel(1);
        let (host_tx, mut host_rx) = mpsc::channel(1);
        let egress = PacketEgress::new(core_rx, Arc::new(host_tx));
        egress.start().unwrap();

        core_tx
            .send(ZCPacket::new_with_payload(b"packet"))
            .await
            .unwrap();
        let packet = timeout(Duration::from_secs(1), host_rx.recv())
            .await
            .expect("packet egress did not forward to the host")
            .expect("host packet channel closed");
        assert_eq!(packet, b"packet");

        egress.stop().await;
        assert!(egress.start().is_err());
    }
}
