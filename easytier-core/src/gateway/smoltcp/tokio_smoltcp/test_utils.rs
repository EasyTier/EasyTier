use std::time::Duration;

use smoltcp::{
    phy::ChecksumCapabilities,
    wire::{
        IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr,
        TcpSeqNumber,
    },
};
use tokio::sync::mpsc;

pub(crate) struct TcpPackets {
    local_addr: Ipv4Address,
    local_port: u16,
}

impl TcpPackets {
    pub(crate) const fn new(local_addr: Ipv4Address, local_port: u16) -> Self {
        Self {
            local_addr,
            local_port,
        }
    }

    fn packet(&self, src_addr: Ipv4Address, repr: TcpRepr<'_>) -> Vec<u8> {
        let ipv4_repr = Ipv4Repr {
            src_addr,
            dst_addr: self.local_addr,
            next_header: IpProtocol::Tcp,
            payload_len: repr.buffer_len(),
            hop_limit: 64,
        };
        let mut packet = vec![0; ipv4_repr.buffer_len() + repr.buffer_len()];
        let mut ipv4_packet = Ipv4Packet::new_unchecked(&mut packet);
        ipv4_repr.emit(&mut ipv4_packet, &ChecksumCapabilities::default());
        repr.emit(
            &mut TcpPacket::new_unchecked(ipv4_packet.payload_mut()),
            &IpAddress::Ipv4(src_addr),
            &IpAddress::Ipv4(self.local_addr),
            &ChecksumCapabilities::default(),
        );
        packet
    }

    pub(crate) fn syn(&self, src_addr: Ipv4Address, src_port: u16, sequence: i32) -> Vec<u8> {
        self.packet(
            src_addr,
            TcpRepr {
                src_port,
                dst_port: self.local_port,
                control: TcpControl::Syn,
                seq_number: TcpSeqNumber(sequence),
                ack_number: None,
                window_len: u16::MAX,
                window_scale: None,
                max_seg_size: Some(1200),
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: &[],
            },
        )
    }

    pub(crate) fn ack(
        &self,
        src_addr: Ipv4Address,
        src_port: u16,
        sequence: TcpSeqNumber,
        ack_number: TcpSeqNumber,
    ) -> Vec<u8> {
        self.control(src_addr, src_port, TcpControl::None, sequence, ack_number)
    }

    pub(crate) fn fin(
        &self,
        src_addr: Ipv4Address,
        src_port: u16,
        sequence: TcpSeqNumber,
        ack_number: TcpSeqNumber,
    ) -> Vec<u8> {
        self.control(src_addr, src_port, TcpControl::Fin, sequence, ack_number)
    }

    fn control(
        &self,
        src_addr: Ipv4Address,
        src_port: u16,
        control: TcpControl,
        sequence: TcpSeqNumber,
        ack_number: TcpSeqNumber,
    ) -> Vec<u8> {
        self.packet(
            src_addr,
            TcpRepr {
                src_port,
                dst_port: self.local_port,
                control,
                seq_number: sequence,
                ack_number: Some(ack_number),
                window_len: u16::MAX,
                window_scale: None,
                max_seg_size: None,
                sack_permitted: false,
                sack_ranges: [None; 3],
                timestamp: None,
                payload: &[],
            },
        )
    }
}

pub(crate) struct TcpPacketSummary {
    pub(crate) control: TcpControl,
    pub(crate) sequence: TcpSeqNumber,
    pub(crate) dst_port: u16,
}

pub(crate) async fn recv_tcp(receiver: &mut mpsc::Receiver<Vec<u8>>) -> TcpPacketSummary {
    let packet = tokio::time::timeout(Duration::from_secs(1), receiver.recv())
        .await
        .unwrap()
        .unwrap();
    let ipv4_packet = Ipv4Packet::new_checked(&packet).unwrap();
    let repr = TcpRepr::parse(
        &TcpPacket::new_checked(ipv4_packet.payload()).unwrap(),
        &IpAddress::Ipv4(ipv4_packet.src_addr()),
        &IpAddress::Ipv4(ipv4_packet.dst_addr()),
        &ChecksumCapabilities::default(),
    )
    .unwrap();
    TcpPacketSummary {
        control: repr.control,
        sequence: repr.seq_number,
        dst_port: repr.dst_port,
    }
}

pub(crate) async fn recv_tcp_for_port(
    receiver: &mut mpsc::Receiver<Vec<u8>>,
    dst_port: u16,
) -> TcpPacketSummary {
    loop {
        let packet = recv_tcp(receiver).await;
        if packet.dst_port == dst_port {
            return packet;
        }
    }
}
