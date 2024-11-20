use std::net::SocketAddr;

use bytecodec::fixnum::{U32beDecoder, U32beEncoder};
use stun_codec::net::{socket_addr_xor, SocketAddrDecoder, SocketAddrEncoder};

use stun_codec::rfc5389::attributes::{
    MappedAddress, Software, XorMappedAddress, XorMappedAddress2,
};
use stun_codec::rfc5780::attributes::{OtherAddress, ResponseOrigin};
use stun_codec::{define_attribute_enums, AttributeType, Message, TransactionId};

use bytecodec::{ByteCount, Decode, Encode, Eos, Result, SizedEncode, TryTaggedDecode};

use stun_codec::macros::track;

macro_rules! impl_decode {
    ($decoder:ty, $item:ident, $and_then:expr) => {
        impl Decode for $decoder {
            type Item = $item;

            fn decode(&mut self, buf: &[u8], eos: Eos) -> Result<usize> {
                track!(self.0.decode(buf, eos))
            }

            fn finish_decoding(&mut self) -> Result<Self::Item> {
                track!(self.0.finish_decoding()).and_then($and_then)
            }

            fn requiring_bytes(&self) -> ByteCount {
                self.0.requiring_bytes()
            }

            fn is_idle(&self) -> bool {
                self.0.is_idle()
            }
        }
        impl TryTaggedDecode for $decoder {
            type Tag = AttributeType;

            fn try_start_decoding(&mut self, attr_type: Self::Tag) -> Result<bool> {
                Ok(attr_type.as_u16() == $item::CODEPOINT)
            }
        }
    };
}

macro_rules! impl_encode {
    ($encoder:ty, $item:ty, $map_from:expr) => {
        impl Encode for $encoder {
            type Item = $item;

            fn encode(&mut self, buf: &mut [u8], eos: Eos) -> Result<usize> {
                track!(self.0.encode(buf, eos))
            }

            #[allow(clippy::redundant_closure_call)]
            fn start_encoding(&mut self, item: Self::Item) -> Result<()> {
                track!(self.0.start_encoding($map_from(item)))
            }

            fn requiring_bytes(&self) -> ByteCount {
                self.0.requiring_bytes()
            }

            fn is_idle(&self) -> bool {
                self.0.is_idle()
            }
        }
        impl SizedEncode for $encoder {
            fn exact_requiring_bytes(&self) -> u64 {
                self.0.exact_requiring_bytes()
            }
        }
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangedAddress(SocketAddr);
impl ChangedAddress {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0005;

    pub fn new(addr: SocketAddr) -> Self {
        ChangedAddress(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl stun_codec::Attribute for ChangedAddress {
    type Decoder = ChangedAddressDecoder;
    type Encoder = ChangedAddressEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }

    fn before_encode<A: stun_codec::Attribute>(
        &mut self,
        message: &Message<A>,
    ) -> bytecodec::Result<()> {
        self.0 = socket_addr_xor(self.0, message.transaction_id());
        Ok(())
    }

    fn after_decode<A: stun_codec::Attribute>(
        &mut self,
        message: &Message<A>,
    ) -> bytecodec::Result<()> {
        self.0 = socket_addr_xor(self.0, message.transaction_id());
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct ChangedAddressDecoder(SocketAddrDecoder);
impl ChangedAddressDecoder {
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(ChangedAddressDecoder, ChangedAddress, |item| Ok(
    ChangedAddress(item)
));

#[derive(Debug, Default)]
pub struct ChangedAddressEncoder(SocketAddrEncoder);
impl ChangedAddressEncoder {
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(ChangedAddressEncoder, ChangedAddress, |item: Self::Item| {
    item.0
});

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SourceAddress(SocketAddr);
impl SourceAddress {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0004;

    pub fn new(addr: SocketAddr) -> Self {
        SourceAddress(addr)
    }

    /// Returns the address of this instance.
    pub fn address(&self) -> SocketAddr {
        self.0
    }
}
impl stun_codec::Attribute for SourceAddress {
    type Decoder = SourceAddressDecoder;
    type Encoder = SourceAddressEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }

    fn before_encode<A: stun_codec::Attribute>(
        &mut self,
        message: &Message<A>,
    ) -> bytecodec::Result<()> {
        self.0 = socket_addr_xor(self.0, message.transaction_id());
        Ok(())
    }

    fn after_decode<A: stun_codec::Attribute>(
        &mut self,
        message: &Message<A>,
    ) -> bytecodec::Result<()> {
        self.0 = socket_addr_xor(self.0, message.transaction_id());
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SourceAddressDecoder(SocketAddrDecoder);
impl SourceAddressDecoder {
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(SourceAddressDecoder, SourceAddress, |item| Ok(
    SourceAddress(item)
));

#[derive(Debug, Default)]
pub struct SourceAddressEncoder(SocketAddrEncoder);
impl SourceAddressEncoder {
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(SourceAddressEncoder, SourceAddress, |item: Self::Item| {
    item.0
});

/// `CHANGE-REQUEST` attribute.
///
/// See [RFC 5780 -- 7.2. CHANGE-REQUEST] about this attribute.
///
/// [RFC 5780 -- 7.2. CHANGE-REQUEST]: https://tools.ietf.org/html/rfc5780#section-7.2
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChangeRequest(bool, bool);

impl ChangeRequest {
    /// The codepoint of the type of the attribute.
    pub const CODEPOINT: u16 = 0x0003;

    /// Makes a new `ChangeRequest` instance.
    pub fn new(ip: bool, port: bool) -> Self {
        ChangeRequest(ip, port)
    }

    /// Returns whether the client requested the server to send the Binding Response with a
    /// different IP address than the one the Binding Request was received on
    pub fn ip(&self) -> bool {
        self.0
    }

    /// Returns whether the client requested the server to send the Binding Response with a
    /// different port than the one the Binding Request was received on
    pub fn port(&self) -> bool {
        self.1
    }
}

impl stun_codec::Attribute for ChangeRequest {
    type Decoder = ChangeRequestDecoder;
    type Encoder = ChangeRequestEncoder;

    fn get_type(&self) -> AttributeType {
        AttributeType::new(Self::CODEPOINT)
    }
}

/// [`ChangeRequest`] decoder.
#[derive(Debug, Default)]
pub struct ChangeRequestDecoder(U32beDecoder);

impl ChangeRequestDecoder {
    /// Makes a new `ChangeRequestDecoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_decode!(ChangeRequestDecoder, ChangeRequest, |item| {
    Ok(ChangeRequest((item & 0x4) != 0, (item & 0x2) != 0))
});

/// [`ChangeRequest`] encoder.
#[derive(Debug, Default)]
pub struct ChangeRequestEncoder(U32beEncoder);

impl ChangeRequestEncoder {
    /// Makes a new `ChangeRequestEncoder` instance.
    pub fn new() -> Self {
        Self::default()
    }
}
impl_encode!(ChangeRequestEncoder, ChangeRequest, |item: Self::Item| {
    let ip = item.0 as u8;
    let port = item.1 as u8;
    ((ip << 1 | port) << 1) as u32
});

pub fn tid_to_u32(tid: &TransactionId) -> u32 {
    let mut tid_buf = [0u8; 4];
    // copy bytes from msg_tid to tid_buf
    tid_buf[..].copy_from_slice(&tid.as_bytes()[8..12]);
    u32::from_le_bytes(tid_buf)
}

pub fn u32_to_tid(tid: u32) -> TransactionId {
    let tid_buf = tid.to_le_bytes();
    let mut tid_arr = [0u8; 12];
    tid_arr[..4].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
    tid_arr[8..12].copy_from_slice(&tid_buf);
    TransactionId::new(tid_arr)
}

define_attribute_enums!(
    Attribute,
    AttributeDecoder,
    AttributeEncoder,
    [
        Software,
        MappedAddress,
        XorMappedAddress,
        XorMappedAddress2,
        OtherAddress,
        ChangeRequest,
        ChangedAddress,
        SourceAddress,
        ResponseOrigin
    ]
);
