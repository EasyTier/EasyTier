use std::{
    mem::MaybeUninit,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::Context;
use easytier_core::instance::ProxyService;
use easytier_core::proxy::{
    icmp_proxy_service::IcmpProxyService,
    runtime::{
        IcmpProxyResponseSink, IcmpProxyRuntime, ProxyRuntimeError, ProxyRuntimeInfo,
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
    socket: std::sync::Mutex<Option<Arc<Socket>>>,
    recv_stopped: std::sync::Mutex<Option<Arc<AtomicBool>>>,
}

impl RuntimeIcmpProxyAdapter {
    fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            socket: std::sync::Mutex::new(None),
            recv_stopped: std::sync::Mutex::new(None),
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

impl IcmpProxyRuntime for RuntimeIcmpProxyAdapter {
    fn start_icmp(
        &self,
        response_sink: Weak<dyn IcmpProxyResponseSink>,
    ) -> Result<(), ProxyRuntimeError> {
        let socket = self.create_raw_socket().inspect_err(|err| {
            tracing::warn!(?err, "create ICMP socket failed");
        })?;
        let socket = Arc::new(socket);
        self.socket.lock().unwrap().replace(socket.clone());
        let recv_stopped = Arc::new(AtomicBool::new(false));
        self.recv_stopped
            .lock()
            .unwrap()
            .replace(recv_stopped.clone());
        thread::spawn(move || socket_recv_loop(socket, response_sink, recv_stopped));
        Ok(())
    }

    fn send_icmp_to_socket(
        &self,
        destination: Ipv4Addr,
        packet: &[u8],
    ) -> Result<(), ProxyRuntimeError> {
        let socket = self.socket.lock().unwrap();
        let socket = socket.as_ref().with_context(|| "ICMP socket not created")?;
        socket.send_to(packet, &SocketAddrV4::new(destination, 0).into())?;
        Ok(())
    }

    fn stop_icmp(&self) {
        tracing::info!(socket = ?self.socket.lock().unwrap().as_ref(), "stopping ICMP runtime");
        if let Some(recv_stopped) = self.recv_stopped.lock().unwrap().take() {
            recv_stopped.store(true, Ordering::Release);
        }
        if let Some(socket) = self.socket.lock().unwrap().as_ref() {
            let _ = socket.shutdown(std::net::Shutdown::Both);
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

fn recv_loop_should_stop(
    recv_stopped: &AtomicBool,
    response_sink: &Weak<dyn IcmpProxyResponseSink>,
) -> bool {
    recv_stopped.load(Ordering::Acquire) || response_sink.strong_count() == 0
}

fn socket_recv_loop(
    socket: Arc<Socket>,
    response_sink: Weak<dyn IcmpProxyResponseSink>,
    recv_stopped: Arc<AtomicBool>,
) {
    let mut buf = [0_u8; 8192];
    let data: &mut [MaybeUninit<u8>] = unsafe { std::mem::transmute(&mut buf[..]) };

    loop {
        let (len, peer_ip) = match socket_recv(&socket, data) {
            Ok(result) => result,
            Err(err) => {
                tracing::error!(?err, "receive ICMP packet failed");
                if recv_loop_should_stop(&recv_stopped, &response_sink) {
                    break;
                }
                continue;
            }
        };

        if len == 0 {
            tracing::error!(len, "received empty ICMP packet");
            return;
        }
        if recv_loop_should_stop(&recv_stopped, &response_sink) {
            break;
        }

        let IpAddr::V4(peer_ip) = peer_ip else {
            continue;
        };
        let Some(response_sink) = response_sink.upgrade() else {
            break;
        };
        response_sink.handle_socket_response(peer_ip, &mut buf[..len]);
    }
}

pub struct IcmpProxy {
    cidr_set: CidrSet,
    service: Arc<IcmpProxyService<RuntimeIcmpProxyAdapter>>,
}

impl IcmpProxy {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: Arc<PeerManager>,
    ) -> Result<Arc<Self>, Error> {
        let cidr_set = CidrSet::new(global_ctx.clone());
        let runtime = Arc::new(RuntimeIcmpProxyAdapter::new(global_ctx));
        let service = IcmpProxyService::new(
            peer_manager.core(),
            runtime,
            cidr_set.table(),
            Duration::from_secs(10),
        );
        Ok(Arc::new(Self { cidr_set, service }))
    }

    pub async fn start(&self) -> Result<(), Error> {
        self.service
            .start()
            .await
            .map_err(|err| anyhow::anyhow!(err).into())
    }

    pub fn stop(&self) {
        self.service.stop();
        self.cidr_set.stop_updater();
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

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopResponseSink;

    impl IcmpProxyResponseSink for NoopResponseSink {
        fn handle_socket_response(&self, _peer_ip: Ipv4Addr, _packet: &mut [u8]) {}
    }

    #[test]
    fn stopped_runtime_terminates_recv_while_sink_is_retained() {
        let sink: Arc<dyn IcmpProxyResponseSink> = Arc::new(NoopResponseSink);
        let sink = Arc::downgrade(&sink);
        let stopped = AtomicBool::new(true);

        assert!(recv_loop_should_stop(&stopped, &sink));
    }
}
