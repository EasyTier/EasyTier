use std::net::SocketAddr;

use stun_codec::net::{socket_addr_xor, SocketAddrDecoder, SocketAddrEncoder};

use stun_codec::rfc5389::attributes::{
    MappedAddress, Software, XorMappedAddress, XorMappedAddress2,
};
use stun_codec::rfc5780::attributes::{ChangeRequest, OtherAddress, ResponseOrigin};
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

pub fn tid_to_u128(tid: &TransactionId) -> u128 {
    let mut tid_buf = [0u8; 16];
    // copy bytes from msg_tid to tid_buf
    tid_buf[..tid.as_bytes().len()].copy_from_slice(tid.as_bytes());
    u128::from_le_bytes(tid_buf)
}

pub fn u128_to_tid(tid: u128) -> TransactionId {
    let tid_buf = tid.to_le_bytes();
    let mut tid_arr = [0u8; 12];
    tid_arr.copy_from_slice(&tid_buf[..12]);
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
