//! STUN binding-response support over UDP sockets.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytecodec::{DecodeExt as _, EncodeExt as _};
use stun_codec::rfc5389::attributes::XorMappedAddress;
use stun_codec::rfc5389::methods::BINDING;
use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};

use crate::packet::stun::{Attribute, ChangeRequest, tid_to_u32, u32_to_tid};
use crate::socket::udp::{UdpBindOptions, VirtualUdpSocket, VirtualUdpSocketFactory};

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
            .map_err(|error| std::io::Error::other(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use std::{io, sync::Mutex};

    use async_trait::async_trait;
    use stun_codec::TransactionId;

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
