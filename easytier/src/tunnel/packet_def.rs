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

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct WGTunnelHeader {
    pub ipv4_header: [u8; 20],
}
pub const WG_TUNNEL_HEADER_SIZE: usize = std::mem::size_of::<WGTunnelHeader>();

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
    Route = 7,
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

#[derive(Default, Debug)]
pub struct ZCPacketOffsets {
    pub payload_offset: usize,
    pub peer_manager_header_offset: usize,
    pub tcp_tunnel_header_offset: usize,
    pub udp_tunnel_header_offset: usize,
    pub wg_tunnel_header_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ZCPacketType {
    // received from peer tcp connection
    TCP,
    // received from peer udp connection
    UDP,
    // received from peer wireguard connection
    WG,
    // received from local tun device, should reserve header space for tcp or udp tunnel
    NIC,
}

const PAYLOAD_OFFSET_FOR_NIC_PACKET: usize = max(
    max(TCP_TUNNEL_HEADER_SIZE, UDP_TUNNEL_HEADER_SIZE),
    WG_TUNNEL_HEADER_SIZE,
) + PEER_MANAGER_HEADER_SIZE;

impl ZCPacketType {
    pub fn get_packet_offsets(&self) -> ZCPacketOffsets {
        match self {
            ZCPacketType::TCP => ZCPacketOffsets {
                payload_offset: TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: TCP_TUNNEL_HEADER_SIZE,
                ..Default::default()
            },
            ZCPacketType::UDP => ZCPacketOffsets {
                payload_offset: UDP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: UDP_TUNNEL_HEADER_SIZE,
                ..Default::default()
            },
            ZCPacketType::WG => ZCPacketOffsets {
                payload_offset: WG_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: WG_TUNNEL_HEADER_SIZE,
                ..Default::default()
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
                wg_tunnel_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE
                    - WG_TUNNEL_HEADER_SIZE,
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct ZCPacket {
    inner: BytesMut,
    packet_type: ZCPacketType,
}

impl ZCPacket {
    pub fn new_nic_packet() -> Self {
        Self {
            inner: BytesMut::new(),
            packet_type: ZCPacketType::NIC,
        }
    }

    pub fn new_from_buf(buf: BytesMut, packet_type: ZCPacketType) -> Self {
        Self {
            inner: buf,
            packet_type,
        }
    }

    pub fn new_with_payload(payload: &[u8]) -> Self {
        let mut ret = Self::new_nic_packet();
        let total_len = ret.packet_type.get_packet_offsets().payload_offset + payload.len();
        ret.inner.resize(total_len, 0);
        ret.mut_payload()[..payload.len()].copy_from_slice(&payload);
        ret
    }

    pub fn new_with_reserved_payload(cap: usize) -> Self {
        let mut ret = Self::new_nic_packet();
        ret.inner.reserve(cap);
        let total_len = ret.packet_type.get_packet_offsets().payload_offset;
        ret.inner.resize(total_len, 0);
        ret
    }

    pub fn packet_type(&self) -> ZCPacketType {
        self.packet_type
    }

    pub fn payload_offset(&self) -> usize {
        self.packet_type.get_packet_offsets().payload_offset
    }

    pub fn mut_payload(&mut self) -> &mut [u8] {
        let offset = self.payload_offset();
        &mut self.inner[offset..]
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

    pub fn mut_wg_tunnel_header(&mut self) -> Option<&mut WGTunnelHeader> {
        WGTunnelHeader::mut_from_prefix(
            &mut self.inner[self
                .packet_type
                .get_packet_offsets()
                .wg_tunnel_header_offset..],
        )
    }

    // ref versions
    pub fn payload(&self) -> &[u8] {
        &self.inner[self.payload_offset()..]
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
        self.inner.len() - self.payload_offset()
    }

    pub fn buf_len(&self) -> usize {
        self.inner.len()
    }

    pub fn fill_peer_manager_hdr(&mut self, from_peer_id: u32, to_peer_id: u32, packet_type: u8) {
        let payload_len = self.payload_len();
        let hdr = self.mut_peer_manager_header().unwrap();
        hdr.from_peer_id.set(from_peer_id);
        hdr.to_peer_id.set(to_peer_id);
        hdr.packet_type = packet_type;
        hdr.len.set(payload_len as u32);
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
            ZCPacketType::WG => self
                .inner
                .split_off(
                    self.packet_type
                        .get_packet_offsets()
                        .wg_tunnel_header_offset,
                )
                .freeze(),
            ZCPacketType::NIC => unreachable!(),
        }
    }

    pub fn inner(self) -> BytesMut {
        self.inner
    }

    pub fn mut_inner(&mut self) -> &mut BytesMut {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zc_packet() {
        let payload = b"hello world";
        let mut packet = ZCPacket::new_with_payload(payload);
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
