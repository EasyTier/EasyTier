use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};

use easytier_core::instance::ProxyService;
use easytier_core::proxy::{
    icmp_proxy_service::IcmpProxyService,
    runtime::{
        IcmpProxyRuntime, IcmpProxySocket, ProxyRuntimeError, ProxyRuntimeInfo,
        ProxyRuntimeSnapshot,
    },
};
use socket2::Socket;

use crate::{
    common::{error::Error, global_ctx::ArcGlobalCtx},
    peers::peer_manager::PeerManager,
};

use super::CidrSet;

#[derive(Debug)]
struct RuntimeIcmpProxyAdapter {
    global_ctx: ArcGlobalCtx,
    socket: std::sync::Mutex<Option<Arc<RuntimeIcmpSocket>>>,
}

impl RuntimeIcmpProxyAdapter {
    fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            socket: std::sync::Mutex::new(None),
        }
    }

    fn create_raw_socket(&self) -> Result<Socket, std::io::Error> {
        let _guard = self.global_ctx.net_ns.guard();
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
            let mut buf = vec![0_u8; 8192];
            let data: &mut [MaybeUninit<u8>] = unsafe { std::mem::transmute(&mut buf[..]) };
            let (len, peer_ip) = socket_recv(&socket, data)?;
            buf.truncate(len);
            Ok((peer_ip, buf))
        })
        .await
        .map_err(|err| ProxyRuntimeError::Other(err.into()))?
    }
}

impl ProxyRuntimeInfo for RuntimeIcmpProxyAdapter {
    fn proxy_runtime_snapshot(&self) -> ProxyRuntimeSnapshot {
        let local_inet = self.global_ctx.get_ipv4().as_ref().cloned();
        ProxyRuntimeSnapshot {
            local_inet,
            virtual_ipv4: local_inet.map(|inet| inet.address()),
            no_tun: self.global_ctx.no_tun(),
            enable_exit_node: self.global_ctx.enable_exit_node(),
            smoltcp_enabled: false,
            latency_first: self.global_ctx.latency_first(),
        }
    }

    fn is_ip_local_virtual_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_ip_local_virtual_ip(ip)
    }
}

#[async_trait::async_trait]
impl IcmpProxyRuntime for RuntimeIcmpProxyAdapter {
    type Socket = RuntimeIcmpSocket;

    async fn start_icmp(&self) -> Result<Arc<Self::Socket>, ProxyRuntimeError> {
        let socket = self.create_raw_socket().inspect_err(|err| {
            tracing::warn!(?err, "create ICMP socket failed");
        })?;
        let socket = Arc::new(RuntimeIcmpSocket {
            socket: Arc::new(socket),
        });
        self.socket.lock().unwrap().replace(socket.clone());
        Ok(socket)
    }

    fn stop_icmp(&self) {
        tracing::info!(socket = ?self.socket.lock().unwrap().as_ref(), "stopping ICMP runtime");
        if let Some(socket) = self.socket.lock().unwrap().as_ref() {
            let _ = socket.socket.shutdown(std::net::Shutdown::Both);
        }
    }
}

fn socket_recv(
    socket: &Socket,
    buf: &mut [MaybeUninit<u8>],
) -> Result<(usize, IpAddr), std::io::Error> {
    let (size, addr) = socket.recv_from(buf)?;
    let addr = match addr.as_socket() {
        None => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        Some(addr) => addr.ip(),
    };
    Ok((size, addr))
}

pub struct IcmpProxy {
    service: Arc<IcmpProxyService<RuntimeIcmpProxyAdapter>>,
}

impl IcmpProxy {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
        cidr_set: Arc<CidrSet>,
    ) -> Result<Arc<Self>, Error> {
        let runtime = Arc::new(RuntimeIcmpProxyAdapter::new(global_ctx));
        let service = IcmpProxyService::new(
            peer_manager.core(),
            runtime,
            cidr_set.table(),
            Duration::from_secs(10),
        );
        Ok(Arc::new(Self { service }))
    }

    pub async fn start(&self) -> Result<(), Error> {
        self.service
            .start()
            .await
            .map_err(|err| anyhow::anyhow!(err).into())
    }

    pub fn stop(&self) {
        self.service.stop();
    }
}

impl Drop for IcmpProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

#[async_trait::async_trait]
impl ProxyService for IcmpProxy {
    async fn start(&self) -> anyhow::Result<()> {
        if let Err(err) = IcmpProxy::start(self).await {
            tracing::error!(?err, "start ICMP proxy failed");
            if cfg!(not(any(
                target_os = "android",
                any(
                    target_os = "ios",
                    all(target_os = "macos", feature = "macos-ne")
                ),
                target_env = "ohos"
            ))) {
                return Err(err.into());
            }
        }
        Ok(())
    }

    async fn stop(&self) {
        IcmpProxy::stop(self);
    }
}
