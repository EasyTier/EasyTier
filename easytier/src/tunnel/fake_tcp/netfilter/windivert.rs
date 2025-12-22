use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::sync::Mutex;
use windivert::layer;
use windivert::packet::WinDivertPacket;
use windivert::prelude::*;

use crate::tunnel::fake_tcp::stack;

pub struct WinDivertTun {
    recv_queue: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
    sender: Arc<std::sync::Mutex<WinDivert<layer::NetworkLayer>>>,
}

impl WinDivertTun {
    pub fn new(local_addr: SocketAddr) -> io::Result<Self> {
        let (tx, rx) = tokio::sync::mpsc::channel(1024);

        let ip_filter = match local_addr {
            SocketAddr::V4(addr) => format!("ip.DstAddr == {}", addr.ip()),
            SocketAddr::V6(addr) => format!("ipv6.DstAddr == {}", addr.ip()),
        };
        // Filter: DstIP == LocalIP AND TCP.
        let filter = format!("{} and tcp", ip_filter);

        // Sniff mode: 1 (WINDIVERT_FLAG_SNIFF)
        // Layer: Network (0)
        // Priority: 0
        let flags = WinDivertFlags::default().set_sniff();
        let reader = WinDivert::network(&filter, 0, flags)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        std::thread::spawn(move || {
            let mut buffer = vec![0u8; 65536];
            loop {
                match reader.recv(Some(&mut buffer)) {
                    Ok(packet) => {
                        let data = &packet.data;

                        let mut eth_data = vec![0u8; 14 + data.len()];
                        // Set EtherType
                        if data.len() > 0 && data[0] >> 4 == 4 {
                            eth_data[12] = 0x08;
                            eth_data[13] = 0x00;
                        } else {
                            eth_data[12] = 0x86;
                            eth_data[13] = 0xDD;
                        }
                        eth_data[14..].copy_from_slice(data);

                        if let Err(_) = tx.blocking_send(eth_data) {
                            break;
                        }
                    }
                    Err(_) => {
                        // log error?
                        break;
                    }
                }
            }
        });

        // Sender: non-sniff, empty filter?
        // Use "false" to avoid capturing anything.
        // Flags: 0
        let sender = WinDivert::network("false", 0, WinDivertFlags::default())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self {
            recv_queue: Mutex::new(rx),
            sender: Arc::new(std::sync::Mutex::new(sender)),
        })
    }
}

#[async_trait::async_trait]
impl stack::Tun for WinDivertTun {
    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error> {
        let mut rx = self.recv_queue.lock().await;
        match rx.recv().await {
            Some(data) => {
                packet.extend_from_slice(&data);
                Ok(data.len())
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "Channel closed",
            )),
        }
    }

    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
        // Strip ethernet header
        if packet.len() < 14 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Packet too short",
            ));
        }
        let ip_data = &packet[14..];

        let Ok(sender) = self.sender.try_lock() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "WinDivert sender lock failed",
            ));
        };

        let mut pkt = unsafe { WinDivertPacket::<layer::NetworkLayer>::new(ip_data.to_vec()) };
        pkt.address.set_outbound(true);

        sender.send(&pkt).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("WinDivert send failed: {}", e),
            )
        })?;

        Ok(())
    }

    fn driver_type(&self) -> &'static str {
        "windivert"
    }
}
