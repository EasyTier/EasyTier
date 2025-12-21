use std::{net::SocketAddr, sync::Arc};

#[cfg(target_os = "linux")]
use crate::tunnel::fake_tcp::stack;

#[cfg(target_os = "linux")]
pub mod linux_bpf;

#[cfg(target_os = "macos")]
pub mod macos_bpf;

#[cfg(target_os = "windows")]
pub mod windivert;

pub mod pnet;

#[cfg(target_os = "linux")]
pub fn create_tun(
    interface_name: &str,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> Arc<dyn stack::Tun> {
    match linux_bpf::LinuxBpfTun::new(interface_name, src_addr, dst_addr) {
        Ok(tun) => Arc::new(tun),
        Err(e) => {
            tracing::warn!(
                ?e,
                interface_name,
                "LinuxBpfTun init failed, falling back to PnetTun"
            );
            Arc::new(pnet::PnetTun::new(
                interface_name,
                pnet::create_packet_filter(src_addr, dst_addr),
            ))
        }
    }
}

#[cfg(target_os = "macos")]
pub fn create_tun(
    interface_name: &str,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> Arc<dyn super::stack::Tun> {
    match macos_bpf::MacosBpfTun::new(interface_name, src_addr, dst_addr) {
        Ok(tun) => Arc::new(tun),
        Err(e) => {
            tracing::warn!(
                ?e,
                interface_name,
                "MacosBpfTun init failed, falling back to PnetTun"
            );
            Arc::new(pnet::PnetTun::new(
                interface_name,
                pnet::create_packet_filter(src_addr, dst_addr),
            ))
        }
    }
}

#[cfg(all(not(windows), not(target_os = "linux"), not(target_os = "macos")))]
pub fn create_tun(
    interface_name: &str,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> Arc<dyn super::stack::Tun> {
    Arc::new(pnet::PnetTun::new(
        interface_name,
        pnet::create_packet_filter(src_addr, dst_addr),
    ))
}

#[cfg(windows)]
pub fn create_tun(
    _interface_name: &str,
    _src_addr: Option<SocketAddr>,
    local_addr: SocketAddr,
) -> Arc<dyn super::stack::Tun> {
    Arc::new(windivert::WinDivertTun::new(local_addr))
}
