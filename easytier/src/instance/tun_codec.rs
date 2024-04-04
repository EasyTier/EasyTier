use std::io;

use byteorder::{NativeEndian, NetworkEndian, WriteBytesExt};
use tokio_util::bytes::{BufMut, Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

/// A packet protocol IP version
#[derive(Debug, Clone, Copy, Default)]
enum PacketProtocol {
    #[default]
    IPv4,
    IPv6,
    Other(u8),
}

// Note: the protocol in the packet information header is platform dependent.
impl PacketProtocol {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        use nix::libc;
        match self {
            PacketProtocol::IPv4 => Ok(libc::ETH_P_IP as u16),
            PacketProtocol::IPv6 => Ok(libc::ETH_P_IPV6 as u16),
            PacketProtocol::Other(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "neither an IPv4 nor IPv6 packet",
            )),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        use nix::libc;
        match self {
            PacketProtocol::IPv4 => Ok(libc::PF_INET as u16),
            PacketProtocol::IPv6 => Ok(libc::PF_INET6 as u16),
            PacketProtocol::Other(_) => Err(io::Error::new(
                io::ErrorKind::Other,
                "neither an IPv4 nor IPv6 packet",
            )),
        }
    }

    #[cfg(target_os = "windows")]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        unimplemented!()
    }
}

#[derive(Debug)]
pub enum TunPacketBuffer {
    Bytes(Bytes),
    BytesMut(BytesMut),
}

impl From<TunPacketBuffer> for Bytes {
    fn from(buf: TunPacketBuffer) -> Self {
        match buf {
            TunPacketBuffer::Bytes(bytes) => bytes,
            TunPacketBuffer::BytesMut(bytes) => bytes.freeze(),
        }
    }
}

impl AsRef<[u8]> for TunPacketBuffer {
    fn as_ref(&self) -> &[u8] {
        match self {
            TunPacketBuffer::Bytes(bytes) => bytes.as_ref(),
            TunPacketBuffer::BytesMut(bytes) => bytes.as_ref(),
        }
    }
}

/// A Tun Packet to be sent or received on the TUN interface.
#[derive(Debug)]
pub struct TunPacket(PacketProtocol, TunPacketBuffer);

/// Infer the protocol based on the first nibble in the packet buffer.
fn infer_proto(buf: &[u8]) -> PacketProtocol {
    match buf[0] >> 4 {
        4 => PacketProtocol::IPv4,
        6 => PacketProtocol::IPv6,
        p => PacketProtocol::Other(p),
    }
}

impl TunPacket {
    /// Create a new `TunPacket` based on a byte slice.
    pub fn new(buffer: TunPacketBuffer) -> TunPacket {
        let proto = infer_proto(buffer.as_ref());
        TunPacket(proto, buffer)
    }

    /// Return this packet's bytes.
    pub fn get_bytes(&self) -> &[u8] {
        match &self.1 {
            TunPacketBuffer::Bytes(bytes) => bytes.as_ref(),
            TunPacketBuffer::BytesMut(bytes) => bytes.as_ref(),
        }
    }

    pub fn into_bytes(self) -> Bytes {
        match self.1 {
            TunPacketBuffer::Bytes(bytes) => bytes,
            TunPacketBuffer::BytesMut(bytes) => bytes.freeze(),
        }
    }

    pub fn into_bytes_mut(self) -> BytesMut {
        match self.1 {
            TunPacketBuffer::Bytes(_) => panic!("cannot into_bytes_mut from bytes"),
            TunPacketBuffer::BytesMut(bytes) => bytes,
        }
    }
}

/// A TunPacket Encoder/Decoder.
pub struct TunPacketCodec(bool, i32);

impl TunPacketCodec {
    /// Create a new `TunPacketCodec` specifying whether the underlying
    ///  tunnel Device has enabled the packet information header.
    pub fn new(pi: bool, mtu: i32) -> TunPacketCodec {
        TunPacketCodec(pi, mtu)
    }
}

impl Decoder for TunPacketCodec {
    type Item = TunPacket;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if buf.is_empty() {
            return Ok(None);
        }

        let mut pkt = buf.split_to(buf.len());

        // reserve enough space for the next packet
        if self.0 {
            buf.reserve(self.1 as usize + 4);
        } else {
            buf.reserve(self.1 as usize);
        }

        // if the packet information is enabled we have to ignore the first 4 bytes
        if self.0 {
            let _ = pkt.split_to(4);
        }

        let proto = infer_proto(pkt.as_ref());
        Ok(Some(TunPacket(proto, TunPacketBuffer::BytesMut(pkt))))
    }
}

impl Encoder<TunPacket> for TunPacketCodec {
    type Error = io::Error;

    fn encode(&mut self, item: TunPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(item.get_bytes().len() + 4);
        match item {
            TunPacket(proto, bytes) if self.0 => {
                // build the packet information header comprising of 2 u16
                // fields: flags and protocol.
                let mut buf = Vec::<u8>::with_capacity(4);

                // flags is always 0
                buf.write_u16::<NativeEndian>(0)?;
                // write the protocol as network byte order
                buf.write_u16::<NetworkEndian>(proto.into_pi_field()?)?;

                dst.put_slice(&buf);
                dst.put(Bytes::from(bytes));
            }
            TunPacket(_, bytes) => dst.put(Bytes::from(bytes)),
        }
        Ok(())
    }
}
