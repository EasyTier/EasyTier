//! Native composition for the portable core STUN collector.

#[cfg(test)]
use std::{net::SocketAddr, sync::Arc};

#[cfg(test)]
use async_trait::async_trait;
#[cfg(test)]
use easytier_core::connectivity::stun::{StunInfoProvider, StunSocketMapper};
use easytier_core::{
    connectivity::stun::StunInfoCollector as CoreStunInfoCollector, socket::SocketContext,
};
#[cfg(test)]
use easytier_proto::common::{NatType, StunInfo};

use crate::host_runtime::{NativeHostRuntime, native_host_runtime};
#[cfg(test)]
use crate::socket::udp::RuntimeUdpSocket;

pub type StunInfoCollector = CoreStunInfoCollector<NativeHostRuntime, NativeHostRuntime>;

pub fn default_udp_stun_servers() -> Vec<String> {
    if cfg!(test) {
        Vec::new()
    } else {
        StunInfoCollector::get_default_servers()
    }
}

pub fn default_tcp_stun_servers() -> Vec<String> {
    if cfg!(test) {
        Vec::new()
    } else {
        StunInfoCollector::get_default_tcp_servers()
    }
}

pub fn default_udp_v6_stun_servers() -> Vec<String> {
    if cfg!(test) {
        Vec::new()
    } else {
        StunInfoCollector::get_default_servers_v6()
    }
}

#[cfg(test)]
pub struct MockStunInfoCollector {
    pub udp_nat_type: NatType,
}

#[cfg(test)]
#[async_trait]
impl StunInfoProvider for MockStunInfoCollector {
    fn get_stun_info(&self) -> StunInfo {
        StunInfo {
            udp_nat_type: self.udp_nat_type as i32,
            tcp_nat_type: NatType::Unknown as i32,
            last_update_time: unix_timestamp(),
            min_port: 100,
            max_port: 200,
            public_ip: vec!["127.0.0.1".to_owned(), "::1".to_owned()],
        }
    }

    async fn get_udp_port_mapping(&self, mut port: u16) -> anyhow::Result<SocketAddr> {
        if port == 0 {
            port = 40144;
        }
        Ok(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    async fn get_tcp_port_mapping(&self, mut port: u16) -> anyhow::Result<SocketAddr> {
        if port == 0 {
            port = 40144;
        }
        Ok(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn update_stun_info(&self) {}
}

#[cfg(test)]
#[async_trait]
impl StunSocketMapper<RuntimeUdpSocket> for MockStunInfoCollector {
    async fn get_udp_port_mapping_with_socket(
        &self,
        socket: Arc<RuntimeUdpSocket>,
    ) -> anyhow::Result<SocketAddr> {
        use easytier_core::socket::udp::VirtualUdpSocket as _;
        self.get_udp_port_mapping(socket.local_addr()?.port()).await
    }
}

pub fn runtime_stun_info_collector(socket_context: SocketContext) -> StunInfoCollector {
    let runtime = native_host_runtime();
    StunInfoCollector::new(
        runtime.clone(),
        runtime,
        socket_context,
        default_udp_stun_servers(),
        default_tcp_stun_servers(),
        default_udp_v6_stun_servers(),
    )
}

#[cfg(test)]
fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytecodec::{DecodeExt as _, EncodeExt as _};
    use easytier_core::{
        connectivity::stun::{Attribute, TcpNatTypeDetector, UdpNatTypeDetector},
        listener::SocketListener,
        socket::{NetNamespace, udp::VirtualUdpSocketFactory},
    };
    use stun_codec::rfc5389::{attributes::XorMappedAddress, methods::BINDING};
    use stun_codec::{Message, MessageClass, MessageDecoder, MessageEncoder};
    use tokio::{
        io::{AsyncReadExt as _, AsyncWriteExt as _},
        task::JoinSet,
    };
    use tokio_util::task::AbortOnDropHandle;

    use crate::{
        host_runtime::native_host_runtime, proto::rpc::standalone::runtime_udp_tunnel_listener,
    };

    use super::*;

    #[tokio::test]
    async fn runtime_collector_starts_with_native_runtime() {
        let context = SocketContext::default()
            .with_socket_mark(Some(0))
            .with_netns(Some(NetNamespace::new("instance-a")));
        let collector = runtime_stun_info_collector(context);

        assert_eq!(
            StunInfoProvider::get_stun_info(&collector),
            StunInfo::default()
        );
    }

    #[test]
    fn native_runtime_supports_collector_socket() {
        fn assert_factory<F: VirtualUdpSocketFactory<Socket = RuntimeUdpSocket>>() {}
        assert_factory::<NativeHostRuntime>();
    }

    #[tokio::test]
    async fn native_udp_runtime_drives_core_stun_detector() {
        let mut first = runtime_udp_tunnel_listener(
            "udp://127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        );
        let mut second = runtime_udp_tunnel_listener(
            "udp://127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        );
        first.listen().await.unwrap();
        second.listen().await.unwrap();
        let servers = vec![
            SocketAddr::from(([127, 0, 0, 1], first.local_url().port().unwrap())).to_string(),
            SocketAddr::from(([127, 0, 0, 1], second.local_url().port().unwrap())).to_string(),
        ];
        let mut tasks = JoinSet::new();
        tasks.spawn(async move {
            loop {
                first.accept().await.unwrap();
            }
        });
        tasks.spawn(async move {
            loop {
                second.accept().await.unwrap();
            }
        });

        let runtime = native_host_runtime();
        let detector = UdpNatTypeDetector::new(
            runtime.clone(),
            runtime,
            SocketContext::default(),
            servers,
            1,
        );
        let result = detector.detect_nat_type(0).await.unwrap();

        assert_eq!(result.nat_type(), NatType::Restricted);
        tasks.abort_all();
    }

    #[tokio::test]
    async fn native_tcp_runtime_drives_core_stun_detector() {
        async fn spawn_server() -> (SocketAddr, AbortOnDropHandle<()>) {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let task = tokio::spawn(async move {
                let (mut stream, peer_addr) = listener.accept().await.unwrap();
                let mut header = [0_u8; 20];
                stream.read_exact(&mut header).await.unwrap();
                let payload_len = u16::from_be_bytes([header[2], header[3]]) as usize;
                let mut bytes = vec![0_u8; 20 + payload_len];
                bytes[..20].copy_from_slice(&header);
                stream.read_exact(&mut bytes[20..]).await.unwrap();
                let request = MessageDecoder::<Attribute>::new()
                    .decode_from_bytes(&bytes)
                    .unwrap()
                    .unwrap();
                let mut response = Message::<Attribute>::new(
                    MessageClass::SuccessResponse,
                    BINDING,
                    request.transaction_id(),
                );
                response.add_attribute(Attribute::XorMappedAddress(XorMappedAddress::new(
                    peer_addr,
                )));
                let bytes = MessageEncoder::new().encode_into_bytes(response).unwrap();
                stream.write_all(&bytes).await.unwrap();
            });
            (address, AbortOnDropHandle::new(task))
        }

        let (first, _first_task) = spawn_server().await;
        let (second, _second_task) = spawn_server().await;
        let runtime = native_host_runtime();
        let detector = TcpNatTypeDetector::new(
            runtime.clone(),
            runtime,
            SocketContext::default(),
            vec![first.to_string(), second.to_string()],
            1,
        );

        let result = tokio::time::timeout(Duration::from_secs(5), detector.detect_nat_type(0))
            .await
            .unwrap()
            .unwrap();

        assert_eq!(result.nat_type(), NatType::OpenInternet);
        assert_eq!(result.usable_stun_resp_count(), 2);
    }
}
