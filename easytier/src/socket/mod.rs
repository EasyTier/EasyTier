#[cfg(feature = "faketcp")]
pub(crate) mod fake_tcp;
pub(crate) mod tcp;
pub(crate) mod udp;
pub(crate) mod udp_src;

use std::net::IpAddr;

use easytier_core::{
    socket::{BindConfig, IpVersion},
    tunnel::TunnelError,
};
use tokio::io;
use tokio::net::{TcpListener, TcpSocket, UdpSocket};

use crate::common::netns::NetNS;

fn get_interface_name_by_ip(local_ip: &IpAddr) -> Option<String> {
    if local_ip.is_unspecified() || local_ip.is_multicast() {
        return None;
    }
    #[cfg(target_os = "windows")]
    let ifaces = crate::common::network::get_interfaces_cached()?;
    // Enumerate under the caller's namespace guard on non-Windows platforms.
    #[cfg(not(target_os = "windows"))]
    let ifaces = {
        use network_interface::NetworkInterfaceConfig;
        network_interface::NetworkInterface::show().ok()?
    };
    for iface in ifaces.iter() {
        for addr in &iface.addr {
            if addr.ip() == *local_ip {
                return Some(iface.name.clone());
            }
        }
    }

    tracing::error!(?local_ip, "can not find interface name by ip");
    None
}

pub(crate) fn set_mark(socket: &socket2::Socket, mark: u32) -> io::Result<()> {
    cfg_select! {
        any(target_os = "android", target_os = "fuchsia", target_os = "linux") => {
            socket.set_mark(mark)?;
        }
        _ => {
            let _ = mark;
        }
    }
    Ok(())
}

pub(crate) trait Bindable: Sized {
    const TYPE: socket2::Type;
    const PROTOCOL: Option<socket2::Protocol>;

    fn finalize(socket: socket2::Socket) -> Result<Self, TunnelError>;
}

impl Bindable for TcpSocket {
    const TYPE: socket2::Type = socket2::Type::STREAM;
    const PROTOCOL: Option<socket2::Protocol> = Some(socket2::Protocol::TCP);

    fn finalize(socket: socket2::Socket) -> Result<Self, TunnelError> {
        let socket = TcpSocket::from_std_stream(socket.into());

        if let Err(error) = socket.set_nodelay(true) {
            tracing::warn!(?error, "set_nodelay failed for tcp socket");
        }

        Ok(socket)
    }
}

impl Bindable for TcpListener {
    const TYPE: socket2::Type = socket2::Type::STREAM;
    const PROTOCOL: Option<socket2::Protocol> = Some(socket2::Protocol::TCP);

    fn finalize(socket: socket2::Socket) -> Result<Self, TunnelError> {
        Ok(TcpSocket::finalize(socket)?.listen(1024)?)
    }
}

impl Bindable for UdpSocket {
    const TYPE: socket2::Type = socket2::Type::DGRAM;
    const PROTOCOL: Option<socket2::Protocol> = Some(socket2::Protocol::UDP);

    fn finalize(socket: socket2::Socket) -> Result<Self, TunnelError> {
        Ok(UdpSocket::from_std(socket.into())?)
    }
}

/// Creates, protects, configures and binds the requested native socket type.
///
/// Supplying `local_addr` binds to that address; otherwise
/// `config.context.ip_version` selects the family and TCP defers source
/// selection to connect while UDP binds an ephemeral source port.
/// Protection completes before bind/listen; namespace guards never cross an
/// await. Failures drop the unbound socket instead of allowing early I/O.
pub(crate) async fn bind<B: Bindable>(config: BindConfig) -> Result<B, TunnelError> {
    let BindConfig {
        context,
        need_protect,
        local_addr,
        bind_device,
        only_v6,
        reuse_addr,
        reuse_port,
    } = config;
    let net_ns = NetNS::from_socket_context(&context);
    let socket_mark = context.socket_mark;
    let family_addr = match context.ip_version {
        IpVersion::V4 => Some("0.0.0.0:0".parse().unwrap()),
        IpVersion::V6 => Some("[::]:0".parse().unwrap()),
        IpVersion::Both => None,
    };
    // UDP creation always binds a source port; TCP can defer source selection to connect.
    let addr = local_addr.or_else(|| {
        (B::TYPE == socket2::Type::DGRAM)
            .then(|| family_addr.unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()))
    });
    let socket_addr = addr.or(family_addr).ok_or_else(|| {
        TunnelError::InvalidAddr(
            "socket requires a local address or explicit IP version".to_owned(),
        )
    })?;
    // Independent UDP receivers stay exclusive unless reuse is explicitly requested.
    let reuse_addr = reuse_addr.unwrap_or(
        B::TYPE != socket2::Type::DGRAM && addr.is_some() && !cfg!(target_os = "windows"),
    );
    let (socket, dev) = {
        let _g = net_ns.guard();
        let dev = match bind_device.as_deref() {
            None => addr.and_then(|addr| get_interface_name_by_ip(&addr.ip())),
            Some("") => None,
            Some(name) => Some(name.to_owned()),
        };
        let socket = socket2::Socket::new(
            socket2::Domain::for_address(socket_addr),
            B::TYPE,
            B::PROTOCOL,
        )?;
        // A platform protector may set its own routing mark. Never overwrite
        // that mark with caller options after its acknowledgement.
        if let Some(mark) = socket_mark {
            set_mark(&socket, mark)?;
        }
        (socket, dev)
    };
    crate::socket_protector::protect_native_socket(&socket, need_protect).await?;
    // Restore the requested namespace for synchronous configuration and bind only.
    let _g = net_ns.guard();
    #[cfg(target_os = "windows")]
    {
        let is_udp = B::TYPE == socket2::Type::DGRAM;
        crate::arch::windows::setup_socket_for_win(&socket, &socket_addr, dev, is_udp)?;
    }

    if socket_addr.is_ipv6() {
        socket.set_only_v6(only_v6)?;
    }
    socket.set_nonblocking(true)?;
    socket.set_reuse_address(reuse_addr)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    if reuse_port {
        socket.set_reuse_port(true)?;
    }
    #[cfg(not(all(unix, not(target_os = "solaris"), not(target_os = "illumos"))))]
    let _ = reuse_port;

    if let Some(addr) = addr {
        socket.bind(&socket2::SockAddr::from(addr))?;
    }

    // Linux/macOS need an explicit device binding to constrain outgoing traffic.
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    if let Some(dev_name) = dev {
        let c_dev_name = std::ffi::CString::new(dev_name.clone()).map_err(|err| {
            TunnelError::InvalidAddr(format!("invalid interface name {dev_name}: {err}"))
        })?;
        let dev_idx = unsafe { nix::libc::if_nametoindex(c_dev_name.as_ptr()) };
        let Some(dev_idx) = std::num::NonZeroU32::new(dev_idx) else {
            return Err(TunnelError::InvalidAddr(format!(
                "network interface not found: {dev_name}"
            )));
        };
        if socket_addr.is_ipv4() {
            socket.bind_device_by_index_v4(Some(dev_idx))?;
        } else {
            socket.bind_device_by_index_v6(Some(dev_idx))?;
        }
    }

    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_env = "ohos"
    ))]
    if let Some(dev_name) = dev {
        socket.bind_device(Some(dev_name.as_bytes()))?;
    }
    #[cfg(not(any(
        target_os = "windows",
        target_os = "ios",
        target_os = "macos",
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_env = "ohos"
    )))]
    let _ = dev;

    B::finalize(socket)
}

#[cfg(test)]
mod tests {
    use easytier_core::socket::SocketContext;
    use easytier_core::socket::{BindConfig, IpVersion};
    use easytier_core::tunnel::TunnelError;

    use super::{TcpListener, TcpSocket, UdpSocket, bind};

    #[tokio::test]
    async fn bind_tcp_uses_configured_family_and_preserves_optional_source_binding_and_options() {
        for ip in ["127.0.0.1", "::1"] {
            let ip: std::net::IpAddr = ip.parse().unwrap();
            let listener = TcpListener::bind((ip, 0)).await.unwrap();
            let remote_addr = listener.local_addr().unwrap();
            for (local_addr, reuse_addr) in [
                (None, None),
                (None, Some(true)),
                (Some(std::net::SocketAddr::new(ip, 0)), None),
                (Some(std::net::SocketAddr::new(ip, 0)), Some(false)),
            ] {
                let socket = bind::<TcpSocket>(BindConfig {
                    context: SocketContext {
                        ip_version: if ip.is_ipv6() {
                            IpVersion::V6
                        } else {
                            IpVersion::V4
                        },
                        ..SocketContext::default()
                    },
                    local_addr,
                    bind_device: Some("".into()),
                    only_v6: ip.is_ipv6(),
                    reuse_addr,
                    reuse_port: true,
                    ..BindConfig::default()
                })
                .await
                .unwrap();

                let addr = socket.local_addr().unwrap();
                assert_eq!(addr.port() == 0, local_addr.is_none());
                let socket_ref = socket2::SockRef::from(&socket);
                assert_eq!(
                    socket_ref.reuse_address().unwrap(),
                    reuse_addr.unwrap_or(local_addr.is_some() && !cfg!(target_os = "windows"))
                );
                if ip.is_ipv6() {
                    assert!(socket_ref.only_v6().unwrap());
                }
                #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
                assert!(socket_ref.reuse_port().unwrap());

                let stream = socket.connect(remote_addr).await.unwrap();
                let (_, peer) = listener.accept().await.unwrap();
                assert_eq!(stream.local_addr().unwrap(), peer);
                assert_eq!(peer.ip(), ip);
                if local_addr.is_some() {
                    assert_eq!(peer, addr);
                }
            }
        }
    }

    #[tokio::test]
    async fn bind_rejects_occupied_ports() {
        for ip in ["127.0.0.1", "::1"] {
            let ip: std::net::IpAddr = ip.parse().unwrap();
            let occupied_udp = std::net::UdpSocket::bind((ip, 0)).unwrap();
            let occupied_tcp = std::net::TcpListener::bind((ip, 0)).unwrap();
            let udp_addr = occupied_udp.local_addr().unwrap();
            let tcp_addr = occupied_tcp.local_addr().unwrap();

            for error in [
                bind::<UdpSocket>(BindConfig {
                    local_addr: Some(udp_addr),
                    ..BindConfig::default()
                })
                .await
                .unwrap_err(),
                bind::<TcpSocket>(BindConfig {
                    local_addr: Some(tcp_addr),
                    ..BindConfig::default()
                })
                .await
                .unwrap_err(),
                bind::<TcpListener>(BindConfig {
                    local_addr: Some(tcp_addr),
                    ..BindConfig::default()
                })
                .await
                .unwrap_err(),
            ] {
                assert!(matches!(
                    error,
                    TunnelError::IOError(error) if error.kind() == std::io::ErrorKind::AddrInUse
                ));
            }
        }
    }

    #[tokio::test]
    async fn bind_rejects_nonlocal_ipv6_address() {
        let addr = "[2001:db8::ffff]:0".parse().unwrap();
        for error in [
            bind::<UdpSocket>(BindConfig {
                local_addr: Some(addr),
                bind_device: Some("".into()),
                ..BindConfig::default()
            })
            .await
            .unwrap_err(),
            bind::<TcpSocket>(BindConfig {
                local_addr: Some(addr),
                bind_device: Some("".into()),
                ..BindConfig::default()
            })
            .await
            .unwrap_err(),
            bind::<TcpListener>(BindConfig {
                local_addr: Some(addr),
                bind_device: Some("".into()),
                ..BindConfig::default()
            })
            .await
            .unwrap_err(),
        ] {
            assert!(matches!(
                error,
                TunnelError::IOError(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable
            ));
        }
    }

    #[cfg(any(
        target_os = "android",
        target_os = "fuchsia",
        target_os = "linux",
        target_env = "ohos"
    ))]
    #[tokio::test]
    async fn bind_custom_device_is_applied_for_unspecified_addr() {
        use std::net::SocketAddr;

        let addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let _err = bind::<UdpSocket>(BindConfig {
            local_addr: Some(addr),
            bind_device: Some("et/invalid-device-name".into()),
            ..BindConfig::default()
        })
        .await
        .expect_err("custom device must not be skipped for unspecified bind addr");
    }
}
