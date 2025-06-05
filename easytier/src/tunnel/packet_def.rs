use bytes::Bytes;
use bytes::BytesMut;
use zerocopy::byteorder::*;
use zerocopy::AsBytes;
use zerocopy::FromBytes;
use zerocopy::FromZeroes;

type DefaultEndian = LittleEndian;

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

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
    V6HolePunch = 6, // when receiving v6 hole punch packet, the packet contains a socket addr of other peer, we
                     // will send a hole punch packet to that peer. we only accept this packet from lookback interface.
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct V6HolePunchPacket {
    pub dst_ipv6: [u8; 16],
    pub dst_port: U16<DefaultEndian>,
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
    RoutePacket = 3, // deprecated
    Ping = 4,
    Pong = 5,
    TaRpc = 6, // deprecated
    Route = 7, // deprecated
    RpcReq = 8,
    RpcResp = 9,
    ForeignNetworkPacket = 10,
    KcpSrc = 11,
    KcpDst = 12,
}

bitflags::bitflags! {
    struct PeerManagerHeaderFlags: u8 {
        const ENCRYPTED = 0b0000_0001;
        const LATENCY_FIRST = 0b0000_0010;
        const EXIT_NODE = 0b0000_0100;
        const NO_PROXY = 0b0000_1000;
        const COMPRESSED = 0b0001_0000;

        const _ = !0;
    }
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct PeerManagerHeader {
    pub from_peer_id: U32<DefaultEndian>,
    pub to_peer_id: U32<DefaultEndian>,
    pub packet_type: u8,
    pub flags: u8,
    pub forward_counter: u8,
    reserved: u8,
    pub len: U32<DefaultEndian>,
}
pub const PEER_MANAGER_HEADER_SIZE: usize = std::mem::size_of::<PeerManagerHeader>();

impl PeerManagerHeader {
    pub fn is_encrypted(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::ENCRYPTED)
    }

    pub fn set_encrypted(&mut self, encrypted: bool) {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if encrypted {
            flags.insert(PeerManagerHeaderFlags::ENCRYPTED);
        } else {
            flags.remove(PeerManagerHeaderFlags::ENCRYPTED);
        }
        self.flags = flags.bits();
    }

    pub fn is_latency_first(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::LATENCY_FIRST)
    }

    pub fn is_exit_node(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::EXIT_NODE)
    }

    pub fn is_no_proxy(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::NO_PROXY)
    }

    pub fn is_compressed(&self) -> bool {
        PeerManagerHeaderFlags::from_bits(self.flags)
            .unwrap()
            .contains(PeerManagerHeaderFlags::COMPRESSED)
    }

    pub fn set_latency_first(&mut self, latency_first: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if latency_first {
            flags.insert(PeerManagerHeaderFlags::LATENCY_FIRST);
        } else {
            flags.remove(PeerManagerHeaderFlags::LATENCY_FIRST);
        }
        self.flags = flags.bits();
        self
    }

    pub fn set_exit_node(&mut self, exit_node: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if exit_node {
            flags.insert(PeerManagerHeaderFlags::EXIT_NODE);
        } else {
            flags.remove(PeerManagerHeaderFlags::EXIT_NODE);
        }
        self.flags = flags.bits();
        self
    }

    pub fn set_no_proxy(&mut self, no_proxy: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if no_proxy {
            flags.insert(PeerManagerHeaderFlags::NO_PROXY);
        } else {
            flags.remove(PeerManagerHeaderFlags::NO_PROXY);
        }
        self.flags = flags.bits();
        self
    }

    pub fn set_compressed(&mut self, compressed: bool) -> &mut Self {
        let mut flags = PeerManagerHeaderFlags::from_bits(self.flags).unwrap();
        if compressed {
            flags.insert(PeerManagerHeaderFlags::COMPRESSED);
        } else {
            flags.remove(PeerManagerHeaderFlags::COMPRESSED);
        }
        self.flags = flags.bits();
        self
    }
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct ForeignNetworkPacketHeader {
    pub header_len: U16<DefaultEndian>,
    pub dst_peer_id: U32<DefaultEndian>,
    pub network_name_offset: U16<DefaultEndian>,
    pub network_name_len: U16<DefaultEndian>,
    /* variable length network_name string */
}

impl ForeignNetworkPacketHeader {
    pub fn new(dst_peer_id: u32, network_name: &str) -> Self {
        let network_name_offset = std::mem::size_of::<ForeignNetworkPacketHeader>() as u16;
        let network_name_len = network_name.len() as u16;
        let header_len = network_name_offset + network_name_len;
        Self {
            header_len: U16::new(header_len),
            dst_peer_id: U32::new(dst_peer_id),
            network_name_offset: U16::new(network_name_offset),
            network_name_len: U16::new(network_name_len),
        }
    }

    pub fn get_network_name(&self, zc_packet_payload: &[u8]) -> String {
        let offset = self.network_name_offset.get() as usize;
        let len = self.network_name_len.get() as usize;
        std::str::from_utf8(&zc_packet_payload[offset..offset + len])
            .unwrap()
            .to_string()
    }

    pub fn get_dst_peer_id(&self) -> u32 {
        self.dst_peer_id.get()
    }

    pub fn get_header_len(&self) -> usize {
        self.header_len.get() as usize
    }
}

// reserve the space for aes tag and nonce
#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct AesGcmTail {
    pub tag: [u8; 16],
    pub nonce: [u8; 12],
}
pub const AES_GCM_ENCRYPTION_RESERVED: usize = std::mem::size_of::<AesGcmTail>();

#[derive(AsBytes, FromZeroes, Clone, Debug, Copy, PartialEq, Hash, Eq)]
#[repr(u8)]
pub enum CompressorAlgo {
    None = 0,
    ZstdDefault = 1,
}

#[repr(C, packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Debug, Default)]
pub struct CompressorTail {
    pub algo: u8,
}
pub const COMPRESSOR_TAIL_SIZE: usize = std::mem::size_of::<CompressorTail>();

impl CompressorTail {
    pub fn get_algo(&self) -> Option<CompressorAlgo> {
        match self.algo {
            1 => Some(CompressorAlgo::ZstdDefault),
            _ => None,
        }
    }

    pub fn new(algo: CompressorAlgo) -> Self {
        Self { algo: algo as u8 }
    }
}

pub const TAIL_RESERVED_SIZE: usize = max(AES_GCM_ENCRYPTION_RESERVED, COMPRESSOR_TAIL_SIZE);

#[derive(Default, Debug)]
pub struct ZCPacketOffsets {
    pub payload_offset: usize,
    pub peer_manager_header_offset: usize,
    pub tcp_tunnel_header_offset: usize,
    pub udp_tunnel_header_offset: usize,
    pub wg_tunnel_header_offset: usize,
    pub dummy_tunnel_header_offset: usize,
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
    // tunnel without header
    DummyTunnel,
}

const PAYLOAD_OFFSET_FOR_NIC_PACKET: usize = max(
    max(TCP_TUNNEL_HEADER_SIZE, UDP_TUNNEL_HEADER_SIZE),
    WG_TUNNEL_HEADER_SIZE,
) + PEER_MANAGER_HEADER_SIZE;

// UDP Tunnel: TUN MTU + 24 (Easy) + 20 (Encrypted) + 8(UDP) + 20(IP) = TUN MTU + 72
// TCP Tunnel: TUN MTU + 20 (Easy) + 20 (Encrypted) + 20(TCP) + 20(IP) = TUN MTU + 80

const INVALID_OFFSET: usize = usize::MAX;

const fn get_converted_offset(old_hdr_size: usize, new_hdr_size: usize) -> usize {
    if old_hdr_size < new_hdr_size {
        INVALID_OFFSET
    } else {
        old_hdr_size - new_hdr_size
    }
}

impl ZCPacketType {
    pub fn get_packet_offsets(&self) -> ZCPacketOffsets {
        match self {
            ZCPacketType::TCP => ZCPacketOffsets {
                payload_offset: TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: TCP_TUNNEL_HEADER_SIZE,
                tcp_tunnel_header_offset: 0,
                udp_tunnel_header_offset: get_converted_offset(
                    TCP_TUNNEL_HEADER_SIZE,
                    UDP_TUNNEL_HEADER_SIZE,
                ),
                wg_tunnel_header_offset: get_converted_offset(
                    TCP_TUNNEL_HEADER_SIZE,
                    WG_TUNNEL_HEADER_SIZE,
                ),
                dummy_tunnel_header_offset: get_converted_offset(TCP_TUNNEL_HEADER_SIZE, 0),
            },
            ZCPacketType::UDP => ZCPacketOffsets {
                payload_offset: UDP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: UDP_TUNNEL_HEADER_SIZE,
                tcp_tunnel_header_offset: get_converted_offset(
                    UDP_TUNNEL_HEADER_SIZE,
                    TCP_TUNNEL_HEADER_SIZE,
                ),
                udp_tunnel_header_offset: 0,
                wg_tunnel_header_offset: get_converted_offset(
                    UDP_TUNNEL_HEADER_SIZE,
                    WG_TUNNEL_HEADER_SIZE,
                ),
                dummy_tunnel_header_offset: get_converted_offset(UDP_TUNNEL_HEADER_SIZE, 0),
            },
            ZCPacketType::WG => ZCPacketOffsets {
                payload_offset: WG_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: WG_TUNNEL_HEADER_SIZE,
                tcp_tunnel_header_offset: get_converted_offset(
                    WG_TUNNEL_HEADER_SIZE,
                    TCP_TUNNEL_HEADER_SIZE,
                ),
                udp_tunnel_header_offset: get_converted_offset(
                    WG_TUNNEL_HEADER_SIZE,
                    UDP_TUNNEL_HEADER_SIZE,
                ),
                wg_tunnel_header_offset: 0,
                dummy_tunnel_header_offset: get_converted_offset(WG_TUNNEL_HEADER_SIZE, 0),
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
                dummy_tunnel_header_offset: PAYLOAD_OFFSET_FOR_NIC_PACKET
                    - PEER_MANAGER_HEADER_SIZE,
            },
            ZCPacketType::DummyTunnel => ZCPacketOffsets {
                payload_offset: PEER_MANAGER_HEADER_SIZE,
                peer_manager_header_offset: 0,
                tcp_tunnel_header_offset: get_converted_offset(0, TCP_TUNNEL_HEADER_SIZE),
                udp_tunnel_header_offset: get_converted_offset(0, UDP_TUNNEL_HEADER_SIZE),
                wg_tunnel_header_offset: get_converted_offset(0, WG_TUNNEL_HEADER_SIZE),
                dummy_tunnel_header_offset: 0,
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
        let payload_off = ret.packet_type.get_packet_offsets().payload_offset;
        let total_len = payload_off + payload.len();
        ret.inner.reserve(total_len);
        unsafe { ret.inner.set_len(total_len) };
        ret.mut_payload()[..payload.len()].copy_from_slice(&payload);
        ret
    }

    pub fn new_for_tun(cap: usize, packet_info_len: usize) -> Self {
        let mut ret = Self::new_nic_packet();
        ret.inner.reserve(cap);
        let total_len = ret.packet_type.get_packet_offsets().payload_offset - packet_info_len;
        unsafe { ret.inner.set_len(total_len) };
        ret
    }

    pub fn new_for_foreign_network(
        network_name: &String,
        dst_peer_id: u32,
        foreign_zc_packet: &ZCPacket,
    ) -> Self {
        let foreign_network_hdr = ForeignNetworkPacketHeader::new(dst_peer_id, &network_name);
        let total_payload_len =
            foreign_network_hdr.get_header_len() + foreign_zc_packet.tunnel_payload().len();

        let mut ret = Self::new_nic_packet();
        let payload_off = ret.packet_type.get_packet_offsets().payload_offset;
        ret.inner.reserve(payload_off + total_payload_len);
        unsafe { ret.inner.set_len(payload_off + total_payload_len) };

        let fixed_hdr_len = std::mem::size_of::<ForeignNetworkPacketHeader>();
        ret.mut_payload()[..fixed_hdr_len].copy_from_slice(foreign_network_hdr.as_bytes());

        let name_offset = foreign_network_hdr.network_name_offset.get() as usize;
        let name_len = foreign_network_hdr.network_name_len.get() as usize;
        ret.mut_payload()[name_offset..name_offset + name_len]
            .copy_from_slice(network_name.as_bytes());

        ret.mut_payload()[foreign_network_hdr.get_header_len()..]
            .copy_from_slice(foreign_zc_packet.tunnel_payload());

        let hdr = ret.mut_peer_manager_header().unwrap();
        hdr.from_peer_id = 0.into();
        hdr.to_peer_id = 0.into();
        hdr.packet_type = PacketType::ForeignNetworkPacket as u8;
        hdr.len.set(total_payload_len as u32);

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

    pub fn payload_bytes(mut self) -> BytesMut {
        self.inner.split_off(self.payload_offset())
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
        hdr.flags = 0;
        hdr.forward_counter = 1;
        hdr.len.set(payload_len as u32);
    }

    pub fn tunnel_payload(&self) -> &[u8] {
        &self.inner[self
            .packet_type
            .get_packet_offsets()
            .peer_manager_header_offset..]
    }

    pub fn tunnel_payload_bytes(mut self) -> BytesMut {
        self.inner.split_off(
            self.packet_type
                .get_packet_offsets()
                .peer_manager_header_offset,
        )
    }

    pub fn convert_type(mut self, target_packet_type: ZCPacketType) -> Self {
        if target_packet_type == self.packet_type {
            return self;
        }

        let new_offset = match target_packet_type {
            ZCPacketType::TCP => {
                self.packet_type
                    .get_packet_offsets()
                    .tcp_tunnel_header_offset
            }
            ZCPacketType::UDP => {
                self.packet_type
                    .get_packet_offsets()
                    .udp_tunnel_header_offset
            }
            ZCPacketType::WG => {
                self.packet_type
                    .get_packet_offsets()
                    .wg_tunnel_header_offset
            }
            ZCPacketType::DummyTunnel => {
                self.packet_type
                    .get_packet_offsets()
                    .dummy_tunnel_header_offset
            }
            ZCPacketType::NIC => unreachable!(),
        };

        tracing::trace!(?self.packet_type, ?target_packet_type, ?new_offset, "convert zc packet type");

        if new_offset == INVALID_OFFSET {
            // copy peer manager header and payload to new buffer
            let tunnel_payload = self.tunnel_payload();
            let new_pm_offset = target_packet_type
                .get_packet_offsets()
                .peer_manager_header_offset;
            let mut buf = BytesMut::with_capacity(new_pm_offset + tunnel_payload.len());
            unsafe { buf.set_len(new_pm_offset) };
            buf.extend_from_slice(tunnel_payload);
            return Self::new_from_buf(buf, target_packet_type);
        }

        return Self::new_from_buf(self.inner.split_off(new_offset), target_packet_type);
    }

    pub fn into_bytes(self) -> Bytes {
        self.inner.freeze()
    }

    pub fn inner(self) -> BytesMut {
        self.inner
    }

    pub fn mut_inner(&mut self) -> &mut BytesMut {
        &mut self.inner
    }

    pub fn is_lossy(&self) -> bool {
        self.peer_manager_header()
            .and_then(|hdr| Some(hdr.packet_type == PacketType::Data as u8))
            .unwrap_or(false)
    }

    pub fn foreign_network_hdr(&self) -> Option<&ForeignNetworkPacketHeader> {
        if self.peer_manager_header().unwrap().packet_type == PacketType::ForeignNetworkPacket as u8
        {
            ForeignNetworkPacketHeader::ref_from_prefix(self.payload())
        } else {
            None
        }
    }

    pub fn foreign_network_packet(mut self) -> Self {
        let hdr = self.foreign_network_hdr().unwrap();
        let foreign_hdr_len = hdr.get_header_len();

        Self::new_from_buf(
            self.inner
                .split_off(foreign_hdr_len + self.payload_offset()),
            ZCPacketType::DummyTunnel,
        )
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

        let tcp_packet = packet.convert_type(ZCPacketType::TCP).into_bytes();
        assert_eq!(&tcp_packet[..1], b"\x0b");
        println!("{:?}", tcp_packet);
    }
}
