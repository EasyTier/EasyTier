use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::Arc,
};

use easytier_core::{
    gateway::proxy::runtime::{IcmpProxyHost, IcmpProxySocket, ProxyRuntimeError},
    socket::SocketContext,
};
use socket2::Socket;

use crate::common::netns::NetNS;

#[derive(Debug, Default)]
pub(crate) struct RuntimeIcmpProxyHost;

impl RuntimeIcmpProxyHost {
    fn create_raw_socket(context: &SocketContext) -> Result<Socket, std::io::Error> {
        let _guard = NetNS::from_socket_context(context).guard();
        let socket = Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )?;
        socket.bind(&socket2::SockAddr::from(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            0,
        )))?;
        Ok(socket)
    }
}

#[derive(Debug)]
struct RuntimeIcmpSocket {
    socket: Arc<Socket>,
}

#[async_trait::async_trait]
impl IcmpProxySocket for RuntimeIcmpSocket {
    async fn send(&self, destination: Ipv4Addr, packet: &[u8]) -> Result<(), ProxyRuntimeError> {
        self.socket
            .send_to(packet, &SocketAddrV4::new(destination, 0).into())?;
        Ok(())
    }

    async fn recv(&self) -> Result<(IpAddr, Vec<u8>), ProxyRuntimeError> {
        let socket = self.socket.clone();
        tokio::task::spawn_blocking(move || {
            let mut buffer = vec![0_u8; 8192];
            let uninitialized: &mut [MaybeUninit<u8>] =
                unsafe { std::mem::transmute(&mut buffer[..]) };
            let (length, peer_ip) = socket_recv(&socket, uninitialized)?;
            buffer.truncate(length);
            Ok((peer_ip, buffer))
        })
        .await
        .map_err(|error| ProxyRuntimeError::Other(error.into()))?
    }

    fn close(&self) {
        let _ = self.socket.shutdown(std::net::Shutdown::Both);
    }
}

#[async_trait::async_trait]
impl IcmpProxyHost for RuntimeIcmpProxyHost {
    async fn open_icmp_v4(
        &self,
        context: SocketContext,
    ) -> Result<Arc<dyn IcmpProxySocket>, ProxyRuntimeError> {
        let socket = Self::create_raw_socket(&context).inspect_err(|error| {
            tracing::warn!(?error, "create ICMP socket failed");
        })?;
        Ok(Arc::new(RuntimeIcmpSocket {
            socket: Arc::new(socket),
        }))
    }
}

fn socket_recv(
    socket: &Socket,
    buffer: &mut [MaybeUninit<u8>],
) -> Result<(usize, IpAddr), std::io::Error> {
    let (size, address) = socket.recv_from(buffer)?;
    let peer_ip = address
        .as_socket()
        .map(|address| address.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    Ok((size, peer_ip))
}
