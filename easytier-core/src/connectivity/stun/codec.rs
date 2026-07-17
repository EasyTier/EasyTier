//! STUN message codec and responder support.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytecodec::fixnum::{U32beDecoder, U32beEncoder};
use bytecodec::{ByteCount, Decode, DecodeExt as _, Encode, EncodeExt as _, Eos, Result};
use bytecodec::{SizedEncode, TryTaggedDecode};
use stun_codec::macros::track;
use stun_codec::net::{SocketAddrDecoder, SocketAddrEncoder, socket_addr_xor};
use stun_codec::rfc5389::attributes::{
    MappedAddress, Software, XorMappedAddress, XorMappedAddress2,
};
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::rfc5780::attributes::{OtherAddress, ResponseOrigin};
use stun_codec::{
    AttributeType, Message, MessageClass, MessageDecoder, MessageEncoder, TransactionId,
    define_attribute_enums,
};

use crate::socket::udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StunResponseSendSource {
    SameSocket,
    NewSocket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunResponse {
    pub bytes: Vec<u8>,
    pub send_source: StunResponseSendSource,
}

pub fn build_stun_response(addr: SocketAddr, req_buf: &[u8]) -> anyhow::Result<StunResponse> {
    let mut decoder = MessageDecoder::<Attribute>::new();
    let req_msg = decoder
        .decode_from_bytes(req_buf)
        .map_err(|e| anyhow::anyhow!("stun decode error: {:?}", e))?
        .map_err(|e| anyhow::anyhow!("stun decode broken message error: {:?}", e))?;

    let tid = req_msg.transaction_id();
    // we only respond easytier stun req, whose tid has 0xdeadbeef prefix
    if tid.as_bytes()[0..4] != [0xde, 0xad, 0xbe, 0xef] {
        anyhow::bail!("stun req tid not from easytier");
    }

    let mut resp_msg = Message::<Attribute>::new(
        MessageClass::SuccessResponse,
        BINDING,
        // we discard the prefix, make sure our implementation is not compatible with other stun client
        u32_to_tid(tid_to_u32(&tid)),
    );
    resp_msg.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(addr)));

    let mut encoder = MessageEncoder::new();
    let bytes = encoder
        .encode_into_bytes(resp_msg.clone())
        .map_err(|e| anyhow::anyhow!("stun encode error: {:?}", e))?;

    let change_req = req_msg
        .get_attribute::<ChangeRequest>()
        .map(|r| r.ip() || r.port())
        .unwrap_or(false);

    Ok(StunResponse {
        bytes,
        send_source: if change_req {
            StunResponseSendSource::NewSocket
        } else {
            StunResponseSendSource::SameSocket
        },
    })
}

async fn respond_stun_packet<S, F>(
    socket: Arc<S>,
    factory: &F,
    addr: SocketAddr,
    req_buf: &[u8],
) -> anyhow::Result<()>
where
    S: VirtualUdpSocket,
    F: VirtualUdpSocketFactory<Socket = S> + ?Sized,
{
    let response = build_stun_response(addr, req_buf)?;
    match response.send_source {
        StunResponseSendSource::SameSocket => {
            socket
                .send_to(&response.bytes, addr)
                .await
                .with_context(|| "send stun response error")?;
        }
        StunResponseSendSource::NewSocket => {
            let bind_addr = if addr.is_ipv4() {
                "0.0.0.0:0".parse().unwrap()
            } else {
                "[::]:0".parse().unwrap()
            };
            let socket = factory
                .bind_udp(
                    UdpBindOptions::hole_punch_control()
                        .with_context(socket.socket_context())
                        .with_local_addr(Some(bind_addr)),
                )
                .await?;
            socket.send_to(&response.bytes, addr).await?;
        }
    }

    tracing::debug!(?addr, "udp respond stun packet done");
    Ok(())
}

#[async_trait::async_trait]
impl<S, F> crate::socket::udp::UdpSessionStunResponder<S> for F
where
    S: VirtualUdpSocket,
    F: VirtualUdpSocketFactory<Socket = S>,
{
    async fn respond_stun(
        &self,
        socket: Arc<S>,
        datagram: &[u8],
        remote_addr: SocketAddr,
    ) -> std::io::Result<()> {
        respond_stun_packet(socket, self, remote_addr, datagram)
            .await
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::Other, error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::{io, sync::Mutex};

    use async_trait::async_trait;

    use super::*;

    #[derive(Debug, Default)]
    struct MockSocket {
        sent: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    impl MockSocket {
        fn sent(&self) -> Vec<(Vec<u8>, SocketAddr)> {
            self.sent.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VirtualUdpSocket for MockSocket {
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }

        async fn send_to(&self, data: &[u8], addr: SocketAddr) -> io::Result<usize> {
            self.sent.lock().unwrap().push((data.to_vec(), addr));
            Ok(data.len())
        }

        async fn recv_from(&self, _buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            std::future::pending().await
        }
    }

    #[derive(Debug, Default)]
    struct MockFactory {
        bind_options: Mutex<Vec<UdpBindOptions>>,
        sockets: Mutex<Vec<Arc<MockSocket>>>,
    }

    impl MockFactory {
        fn bind_options(&self) -> Vec<UdpBindOptions> {
            self.bind_options.lock().unwrap().clone()
        }

        fn sockets(&self) -> Vec<Arc<MockSocket>> {
            self.sockets.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl VirtualUdpSocketFactory for MockFactory {
        type Socket = MockSocket;

        async fn bind_udp(&self, options: UdpBindOptions) -> anyhow::Result<Arc<Self::Socket>> {
            self.bind_options.lock().unwrap().push(options);
            let socket = Arc::new(MockSocket::default());
            self.sockets.lock().unwrap().push(socket.clone());
            Ok(socket)
        }
    }

    fn stun_request(change_ip: bool, change_port: bool) -> Vec<u8> {
        let mut request = Message::<Attribute>::new(MessageClass::Request, BINDING, u32_to_tid(7));
        if change_ip || change_port {
            request.add_attribute(Attribute::ChangeRequest(ChangeRequest::new(
                change_ip,
                change_port,
            )));
        }
        MessageEncoder::new().encode_into_bytes(request).unwrap()
    }

    #[test]
    fn easytier_transaction_id_roundtrips_u32() {
        let tid = u32_to_tid(0x1122_3344);

        assert_eq!(&tid.as_bytes()[..4], &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(tid_to_u32(&tid), 0x1122_3344);
    }

    #[test]
    fn build_stun_response_rejects_non_easytier_tid() {
        let request =
            Message::<Attribute>::new(MessageClass::Request, BINDING, TransactionId::new([0; 12]));
        let mut encoder = MessageEncoder::new();
        let request = encoder.encode_into_bytes(request).unwrap();

        assert!(build_stun_response("127.0.0.1:1234".parse().unwrap(), &request).is_err());
    }

    #[test]
    fn build_stun_response_detects_change_request() {
        let request = stun_request(true, false);

        let response = build_stun_response("127.0.0.1:1234".parse().unwrap(), &request).unwrap();

        assert_eq!(response.send_source, StunResponseSendSource::NewSocket);
        assert!(!response.bytes.is_empty());
    }

    #[tokio::test]
    async fn respond_stun_packet_uses_ipv6_unspecified_socket_for_ipv6_change_request() {
        let listener_socket = Arc::new(MockSocket::default());
        let factory = MockFactory::default();
        let remote_addr = "[::1]:1234".parse().unwrap();

        respond_stun_packet(
            listener_socket.clone(),
            &factory,
            remote_addr,
            &stun_request(true, false),
        )
        .await
        .unwrap();

        assert!(listener_socket.sent().is_empty());
        assert_eq!(
            factory.bind_options(),
            vec![
                UdpBindOptions::hole_punch_control()
                    .with_local_addr(Some("[::]:0".parse().unwrap()))
            ]
        );
        let sockets = factory.sockets();
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].sent()[0].1, remote_addr);
    }
}
