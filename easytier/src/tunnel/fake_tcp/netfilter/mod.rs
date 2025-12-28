pub mod pnet;

use std::{io, net::SocketAddr, sync::Arc};

cfg_if::cfg_if! {
    if #[cfg(target_os = "linux")] {
        pub mod linux_bpf;

        pub fn create_tun(
            interface_name: &str,
            src_addr: Option<SocketAddr>,
            dst_addr: SocketAddr,
        ) -> io::Result<Arc<dyn super::stack::Tun>> {
            match linux_bpf::LinuxBpfTun::new(interface_name, src_addr, dst_addr) {
                Ok(tun) => Ok(Arc::new(tun)),
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        interface_name,
                        "LinuxBpfTun init failed, falling back to PnetTun"
                    );
                    Ok(Arc::new(pnet::PnetTun::new(
                        interface_name,
                        pnet::create_packet_filter(src_addr, dst_addr),
                    )?))
                }
            }
        }
    } else if #[cfg(target_os = "macos")] {
        pub mod macos_bpf;

        pub fn create_tun(
            interface_name: &str,
            src_addr: Option<SocketAddr>,
            dst_addr: SocketAddr,
        ) -> io::Result<Arc<dyn super::stack::Tun>> {
            match macos_bpf::MacosBpfTun::new(interface_name, src_addr, dst_addr) {
                Ok(tun) => Ok(Arc::new(tun)),
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        interface_name,
                        "MacosBpfTun init failed, falling back to PnetTun"
                    );
                    Ok(Arc::new(pnet::PnetTun::new(
                        interface_name,
                        pnet::create_packet_filter(src_addr, dst_addr),
                    )?))
                }
            }
        }
    } else if #[cfg(all(windows, any(target_arch = "x86_64", target_arch = "x86")))] {
        pub mod windivert;

        pub fn create_tun(
            _interface_name: &str,
            _src_addr: Option<SocketAddr>,
            local_addr: SocketAddr,
        ) -> io::Result<Arc<dyn super::stack::Tun>> {
            match windivert::WinDivertTun::new(local_addr) {
                Ok(tun) => Ok(Arc::new(tun)),
                Err(e) => {
                    tracing::warn!(
                        ?e,
                        ?local_addr,
                        "WinDivertTun init failed, falling back to PnetTun"
                    );
                    Ok(Arc::new(pnet::PnetTun::new(
                        local_addr.to_string().as_str(),
                        pnet::create_packet_filter(None, local_addr),
                    )?))
                }
            }
        }
    } else {
        pub fn create_tun(
            interface_name: &str,
            src_addr: Option<SocketAddr>,
            dst_addr: SocketAddr,
        ) -> io::Result<Arc<dyn super::stack::Tun>> {
            Ok(Arc::new(pnet::PnetTun::new(
                interface_name,
                pnet::create_packet_filter(src_addr, dst_addr),
            )?))
        }
    }
}
