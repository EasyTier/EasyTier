use bytes::Bytes;
use bytes::BytesMut;
use zerocopy::byteorder::*;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

type DefaultEndian = LittleEndian;

// TCP TunnelHeader
#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct TCPTunnelHeader {
    pub len: U32<DefaultEndian>,
}
pub const TCP_TUNNEL_HEADER_SIZE: usize = std::mem::size_of::<TCPTunnelHeader>();

#[derive(AsBytes, FromZeroes, Clone, Debug)]
#[repr(u8)]
pub enum UdpPacketType {
    Invalid = 0,
    Syn = 1,
    Sack = 2,
    Data = 3,
    Fin = 4,
    HolePunch = 5,
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct UDPTunnelHeader {
    pub conn_id: U32<DefaultEndian>,
    pub msg_type: u8,
    pub padding: u8,
    pub len: U16<DefaultEndian>,
}
pub const UDP_TUNNEL_HEADER_SIZE: usize = std::mem::size_of::<UDPTunnelHeader>();

#[derive(AsBytes, FromZeroes, Clone, Debug)]
#[repr(u8)]
pub enum PacketType {
    Invalid = 0,
    Data = 1,
    HandShake = 2,
    RoutePacket = 3,
    Ping = 4,
    Pong = 5,
    TaRpc = 6,
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct PeerManagerHeader {
    pub from_peer_id: U32<DefaultEndian>,
    pub to_peer_id: U32<DefaultEndian>,
    pub packet_type: u8,
    pub len: U32<DefaultEndian>,
}
pub const PEER_MANAGER_HEADER_SIZE: usize = std::mem::size_of::<PeerManagerHeader>();

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

struct ZCPacketOffsets {
    pub payload_offset: usize,
    pub peer_manager_header_offset: usize,
    pub tcp_tunnel_header_offset: usize,
    pub udp_tunnel_header_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZCPacketType {
    // received from peer tcp connection
    TCP,
    // received from peer udp connection
    UDP,
    // received from local tun device, should reserve header space for tcp or udp tunnel
    NIC,
}

const PAYLOAD_OFFSET_FOR_NIC_PACKET: usize =
    max(TCP_TUNNEL_HEADER_SIZE, UDP_TUNNEL_HEADER_SIZE) + PEER_MANAGER_HEADER_SIZE;

impl ZCPacketType {
    fn get_packet_offsets(&self) -> ZCPacketOffsets {
        match self {
            ZCPacketType::TCP => ZCPacketOffsets {
                payload_offset: TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: TCP_TUNNEL_HEADER_SIZE,
                tcp_tunnel_header_offset: 0,
                udp_tunnel_header_offset: 0,
            },
            ZCPacketType::UDP => ZCPacketOffsets {
                payload_offset: UDP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: UDP_TUNNEL_HEADER_SIZE,
                tcp_tunnel_header_offset: 0,
                udp_tunnel_header_offset: 0,
            },
            ZCPacketType::NIC => ZCPacketOffsets {
                payload_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET,
                peer_manager_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE,
                tcp_tunnel_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE
                    - TCP_TUNNEL_HEADER_SIZE,
                udp_tunnel_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE
                    - UDP_TUNNEL_HEADER_SIZE,
            },
        }
    }
}

#[derive(Debug)]
pub struct ZCPacket {
    inner: BytesMut,
    packet_type: ZCPacketType,
}

impl ZCPacket {
    fn new(cap: usize) -> Self {
        Self {
            inner: BytesMut::with_capacity(cap),
            packet_type: ZCPacketType::NIC,
        }
    }

    pub fn new_from_buf(buf: BytesMut, packet_type: ZCPacketType) -> Self {
        Self {
            inner: buf,
            packet_type,
        }
    }

    pub fn new_with_payload(payload: BytesMut) -> Self {
        let mut ret = Self::new(payload.len() + 64);
        let total_len = ret.packet_type.get_packet_offsets().payload_offset + payload.len();
        ret.inner.resize(total_len, 0);
        ret.mut_payload()[..payload.len()].copy_from_slice(&payload);
        ret
    }

    pub fn mut_payload(&mut self) -> &mut [u8] {
        &mut self.inner[self.packet_type.get_packet_offsets().payload_offset..]
    }

    pub fn mut_peer_manager_header(&mut self) -> Option<&mut PeerManagerHeader> {
        PeerManagerHeader::mut_from_prefix(
            &mut self.inner[self
                .packet_type
                .get_packet_offsets()
                .peer_manager_header_offset..],
        )
    }

    pub fn mut_tcp_tunnel_header(&mut self) -> Option<&mut TCPTunnelHeader> {
        TCPTunnelHeader::mut_from_prefix(
            &mut self.inner[self
                .packet_type
                .get_packet_offsets()
                .tcp_tunnel_header_offset..],
        )
    }

    pub fn mut_udp_tunnel_header(&mut self) -> Option<&mut UDPTunnelHeader> {
        UDPTunnelHeader::mut_from_prefix(
            &mut self.inner[self
                .packet_type
                .get_packet_offsets()
                .udp_tunnel_header_offset..],
        )
    }

    // ref versions
    pub fn payload(&self) -> &[u8] {
        &self.inner[self.packet_type.get_packet_offsets().payload_offset..]
    }

    pub fn peer_manager_header(&self) -> Option<&PeerManagerHeader> {
        PeerManagerHeader::ref_from_prefix(
            &self.inner[self
                .packet_type
                .get_packet_offsets()
                .peer_manager_header_offset..],
        )
    }

    pub fn tcp_tunnel_header(&self) -> Option<&TCPTunnelHeader> {
        TCPTunnelHeader::ref_from_prefix(
            &self.inner[self
                .packet_type
                .get_packet_offsets()
                .tcp_tunnel_header_offset..],
        )
    }

    pub fn udp_tunnel_header(&self) -> Option<&UDPTunnelHeader> {
        UDPTunnelHeader::ref_from_prefix(
            &self.inner[self
                .packet_type
                .get_packet_offsets()
                .udp_tunnel_header_offset..],
        )
    }

    pub fn udp_payload(&self) -> &[u8] {
        &self.inner[self
            .packet_type
            .get_packet_offsets()
            .udp_tunnel_header_offset
            + UDP_TUNNEL_HEADER_SIZE..]
    }

    pub fn payload_len(&self) -> usize {
        let payload_offset = self.packet_type.get_packet_offsets().payload_offset;
        self.inner.len() - payload_offset
    }

    pub fn buf_len(&self) -> usize {
        self.inner.len()
    }

    pub fn into_bytes(mut self, target_packet_type: ZCPacketType) -> Bytes {
        if target_packet_type == self.packet_type {
            return self.inner.freeze();
        } else {
            assert_eq!(
                self.packet_type,
                ZCPacketType::NIC,
                "only support NIC, got {:?}",
                self
            );
        }

        match target_packet_type {
            ZCPacketType::TCP => self
                .inner
                .split_off(
                    self.packet_type
                        .get_packet_offsets()
                        .tcp_tunnel_header_offset,
                )
                .freeze(),
            ZCPacketType::UDP => self
                .inner
                .split_off(
                    self.packet_type
                        .get_packet_offsets()
                        .udp_tunnel_header_offset,
                )
                .freeze(),
            ZCPacketType::NIC => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zc_packet() {
        let payload = b"hello world";
        let mut p = BytesMut::new();
        p.extend_from_slice(payload);
        let mut packet = ZCPacket::new_with_payload(p);
        let peer_manager_header = packet.mut_peer_manager_header().unwrap();
        peer_manager_header.packet_type = PacketType::Data as u8;
        peer_manager_header.len.set(payload.len() as u32);

        let tcp_tunnel_header = packet.mut_tcp_tunnel_header().unwrap();
        tcp_tunnel_header.len.set(payload.len() as u32);

        // let udp_tunnel_header = packet.mut_udp_tunnel_header().unwrap();
        // udp_tunnel_header.conn_id = 1;
        // udp_tunnel_header.msg_type = 2;
        // udp_tunnel_header.len = payload.len() as u32;

        assert_eq!(packet.payload(), b"hello world");
        assert_eq!(packet.payload_len(), 11);
        println!("{:?}", packet.inner);

        let tcp_packet = packet.into_bytes(ZCPacketType::TCP);
        assert_eq!(&tcp_packet[..1], b"\x0b");
        println!("{:?}", tcp_packet);
    }
}
