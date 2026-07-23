use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use tokio::net::UdpSocket;

pub(crate) fn enable_recv_pktinfo(socket: &UdpSocket) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    use nix::libc;

    let fd = socket.as_raw_fd();
    let enabled: libc::c_int = 1;
    unsafe {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        );
        #[cfg(any(
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "netbsd",
            target_os = "macos",
            target_os = "ios"
        ))]
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_RECVDSTADDR,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        );
        let _ = libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &enabled as *const _ as *const libc::c_void,
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn enable_recv_pktinfo(_socket: &UdpSocket) -> io::Result<()> {
    Ok(())
}

pub(crate) async fn recv_from_with_dst_ip(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    socket
        .async_io(tokio::io::Interest::READABLE, || {
            loop {
                match recv_from_with_dst_ip_once(socket, buf) {
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    ret => break ret,
                }
            }
        })
        .await
}

#[cfg(not(any(unix, windows)))]
pub(crate) async fn recv_from_with_dst_ip(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let (len, addr) = socket.recv_from(buf).await?;
    Ok((len, addr, None))
}

fn recv_from_with_dst_ip_once(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    use std::{mem, os::fd::AsRawFd};

    use nix::libc;

    #[repr(align(8))]
    struct ControlBuffer([u8; 256]);

    fn sockaddr_to_socket_addr(
        storage: &libc::sockaddr_storage,
        len: libc::socklen_t,
    ) -> io::Result<SocketAddr> {
        match storage.ss_family as libc::c_int {
            libc::AF_INET => {
                if (len as usize) < mem::size_of::<libc::sockaddr_in>() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short IPv4 sockaddr",
                    ));
                }
                let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
                let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
                let port = u16::from_be(addr.sin_port);
                Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            libc::AF_INET6 => {
                if (len as usize) < mem::size_of::<libc::sockaddr_in6>() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "short IPv6 sockaddr",
                    ));
                }
                let addr = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
                let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
                let port = u16::from_be(addr.sin6_port);
                Ok(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    addr.sin6_flowinfo,
                    addr.sin6_scope_id,
                )))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported UDP sockaddr family",
            )),
        }
    }

    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let mut name = unsafe { mem::zeroed::<libc::sockaddr_storage>() };
    let mut control = ControlBuffer([0u8; 256]);
    let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
    msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
    msg.msg_namelen = mem::size_of::<libc::sockaddr_storage>() as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control.0.len() as _;

    let len = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut msg, 0) };
    if len < 0 {
        return Err(io::Error::last_os_error());
    }

    let remote_addr = sockaddr_to_socket_addr(&name, msg.msg_namelen)?;
    let mut dst_ip = None;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
        while !cmsg.is_null() {
            #[cfg(any(target_os = "linux", target_os = "android"))]
            {
                if (*cmsg).cmsg_level == libc::IPPROTO_IP && (*cmsg).cmsg_type == libc::IP_PKTINFO {
                    let pktinfo = &*(libc::CMSG_DATA(cmsg) as *const libc::in_pktinfo);
                    dst_ip = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                        pktinfo.ipi_addr.s_addr,
                    ))));
                }
            }
            #[cfg(any(
                target_os = "freebsd",
                target_os = "openbsd",
                target_os = "netbsd",
                target_os = "macos",
                target_os = "ios"
            ))]
            {
                if (*cmsg).cmsg_level == libc::IPPROTO_IP
                    && (*cmsg).cmsg_type == libc::IP_RECVDSTADDR
                {
                    let addr = &*(libc::CMSG_DATA(cmsg) as *const libc::in_addr);
                    dst_ip = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(addr.s_addr))));
                }
            }
            if (*cmsg).cmsg_level == libc::IPPROTO_IPV6 && (*cmsg).cmsg_type == libc::IPV6_PKTINFO {
                let pktinfo = &*(libc::CMSG_DATA(cmsg) as *const libc::in6_pktinfo);
                dst_ip = Some(IpAddr::V6(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr)));
            }
            cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
        }
    }

    Ok((len as usize, remote_addr, dst_ip))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) async fn send_to_with_src_ip(
    socket: &UdpSocket,
    src_ip: IpAddr,
    dst_addr: SocketAddr,
    buf: &[u8],
) -> io::Result<usize> {
    socket
        .async_io(tokio::io::Interest::WRITABLE, || {
            send_to_with_src_ip_raw(socket, src_ip, dst_addr, buf)
        })
        .await
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub(crate) async fn send_to_with_src_ip(
    socket: &UdpSocket,
    src_ip: IpAddr,
    dst_addr: SocketAddr,
    buf: &[u8],
) -> io::Result<usize> {
    match (src_ip, dst_addr) {
        (IpAddr::V4(src), SocketAddr::V4(dst)) => {
            socket
                .async_io(tokio::io::Interest::WRITABLE, || {
                    send_to_with_src_ipv4_to_addr(socket, src, SocketAddr::V4(dst), buf)
                })
                .await
        }
        (IpAddr::V4(src), SocketAddr::V6(dst)) => {
            if dst.ip().to_ipv4_mapped().is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("source address {src} does not match destination {dst} family"),
                ));
            }
            socket
                .async_io(tokio::io::Interest::WRITABLE, || {
                    send_to_with_src_ipv4_to_addr(socket, src, SocketAddr::V6(dst), buf)
                })
                .await
        }
        (IpAddr::V6(src), SocketAddr::V6(dst)) => {
            socket
                .async_io(tokio::io::Interest::WRITABLE, || {
                    send_to_with_src_ipv6(socket, src, 0, dst, buf)
                })
                .await
        }
        (src, dst) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("source address {src} does not match destination {dst} family"),
        )),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn send_to_with_src_ipv4_to_addr(
    socket: &UdpSocket,
    src_ip: Ipv4Addr,
    dst_addr: SocketAddr,
    buf: &[u8],
) -> io::Result<usize> {
    match dst_addr {
        SocketAddr::V4(dst) => send_to_with_src_ipv4(socket, src_ip, dst, buf),
        SocketAddr::V6(dst) => {
            let Some(mapped_dst) = dst.ip().to_ipv4_mapped() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("source address {src_ip} does not match destination {dst} family"),
                ));
            };
            send_to_with_src_ipv4_mapped_v6(socket, src_ip, dst, mapped_dst, buf)
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android", windows)))]
fn send_to_with_src_ipv4_mapped_v6(
    socket: &UdpSocket,
    src_ip: Ipv4Addr,
    dst_addr: SocketAddrV6,
    mapped_dst: Ipv4Addr,
    buf: &[u8],
) -> io::Result<usize> {
    send_to_with_src_ipv4(
        socket,
        src_ip,
        SocketAddrV4::new(mapped_dst, dst_addr.port()),
        buf,
    )
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_to_with_src_ip_raw(
    socket: &UdpSocket,
    src_ip: IpAddr,
    dst_addr: SocketAddr,
    buf: &[u8],
) -> io::Result<usize> {
    match (src_ip, dst_addr) {
        (IpAddr::V4(src), SocketAddr::V4(dst)) => send_to_with_src_ipv4(socket, src, dst, buf),
        (IpAddr::V4(src), SocketAddr::V6(dst)) => {
            let Some(mapped_dst) = dst.ip().to_ipv4_mapped() else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("source address {src} does not match destination {dst} family"),
                ));
            };
            send_to_with_src_ipv4(socket, src, SocketAddrV4::new(mapped_dst, dst.port()), buf)
        }
        (IpAddr::V6(src), SocketAddr::V6(dst)) => send_to_with_src_ipv6(socket, src, 0, dst, buf),
        (src, dst) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("source address {src} does not match destination {dst} family"),
        )),
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn send_to_with_src_ipv4(
    socket: &UdpSocket,
    src_ip: Ipv4Addr,
    dst_addr: SocketAddrV4,
    buf: &[u8],
) -> io::Result<usize> {
    use std::{mem, os::fd::AsRawFd, ptr};

    use nix::libc;

    #[repr(align(8))]
    struct ControlBuffer([u8; 128]);

    let pktinfo = libc::in_pktinfo {
        ipi_ifindex: 0,
        ipi_spec_dst: libc::in_addr {
            s_addr: u32::from(src_ip).to_be(),
        },
        ipi_addr: libc::in_addr { s_addr: 0 },
    };
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let dst_addr = socket2::SockAddr::from(std::net::SocketAddr::V4(dst_addr));
    let control_len =
        unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in_pktinfo>() as libc::c_uint) as usize };
    let mut control = ControlBuffer([0u8; 128]);
    if control_len > control.0.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 packet info control buffer is too small",
        ));
    }

    let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
    msg.msg_name = dst_addr.as_ptr() as *mut libc::c_void;
    msg.msg_namelen = dst_addr.len() as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_len as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv4 packet info control buffer is invalid",
            ));
        }
        (*cmsg).cmsg_level = libc::IPPROTO_IP;
        (*cmsg).cmsg_type = libc::IP_PKTINFO;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as libc::c_uint) as _;
        ptr::write(libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo, pktinfo);

        let ret = libc::sendmsg(socket.as_raw_fd(), &msg, 0);
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

#[cfg(any(
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios"
))]
fn send_to_with_src_ipv4(
    socket: &UdpSocket,
    src_ip: Ipv4Addr,
    dst_addr: SocketAddrV4,
    buf: &[u8],
) -> io::Result<usize> {
    use std::{mem, os::fd::AsRawFd, ptr};

    use nix::libc;

    #[repr(align(8))]
    struct ControlBuffer([u8; 128]);

    if let Ok(SocketAddr::V4(local_addr)) = socket.local_addr() {
        if !local_addr.ip().is_unspecified() {
            return socket.try_send_to(buf, SocketAddr::V4(dst_addr));
        }
    }

    let src_addr = libc::in_addr {
        s_addr: u32::from(src_ip).to_be(),
    };
    let mut iov = libc::iovec {
        iov_base: buf.as_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    let dst_addr = socket2::SockAddr::from(std::net::SocketAddr::V4(dst_addr));
    let control_len =
        unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in_addr>() as libc::c_uint) as usize };
    let mut control = ControlBuffer([0u8; 128]);
    if control_len > control.0.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 source address control buffer is too small",
        ));
    }

    let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
    msg.msg_name = dst_addr.as_ptr() as *mut libc::c_void;
    msg.msg_namelen = dst_addr.len() as _;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = control_len as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv4 source address control buffer is invalid",
            ));
        }
        (*cmsg).cmsg_level = libc::IPPROTO_IP;
        (*cmsg).cmsg_type = libc::IP_RECVDSTADDR;
        (*cmsg).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::in_addr>() as libc::c_uint) as _;
        ptr::write(libc::CMSG_DATA(cmsg) as *mut libc::in_addr, src_addr);

        let ret = libc::sendmsg(socket.as_raw_fd(), &msg, 0);
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "macos",
    target_os = "ios",
    windows
)))]
fn send_to_with_src_ipv4(
    socket: &UdpSocket,
    _src_ip: Ipv4Addr,
    dst_addr: SocketAddrV4,
    buf: &[u8],
) -> io::Result<usize> {
    socket.try_send_to(buf, SocketAddr::V4(dst_addr))
}

pub(crate) fn send_to_with_src_ipv6(
    socket: &UdpSocket,
    src_ip: Ipv6Addr,
    src_ifindex: u32,
    dst_addr: SocketAddrV6,
    buf: &[u8],
) -> io::Result<usize> {
    #[cfg(target_env = "ohos")]
    {
        let _ = (socket, src_ip, src_ifindex, dst_addr, buf);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sending UDP with a selected IPv6 source is not supported on OHOS",
        ));
    }

    #[cfg(not(target_env = "ohos"))]
    {
        use std::{mem, os::fd::AsRawFd, ptr};

        use nix::libc;

        #[repr(align(8))]
        struct ControlBuffer([u8; 128]);

        #[cfg(target_os = "android")]
        let ipi6_ifindex: libc::c_int = i32::try_from(src_ifindex).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 source interface index is out of range",
            )
        })?;
        #[cfg(not(target_os = "android"))]
        let ipi6_ifindex: libc::c_uint = src_ifindex;

        let pktinfo = libc::in6_pktinfo {
            ipi6_addr: libc::in6_addr {
                s6_addr: src_ip.octets(),
            },
            ipi6_ifindex,
        };
        let mut iov = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let dst_addr = socket2::SockAddr::from(std::net::SocketAddr::V6(dst_addr));
        let control_len = unsafe {
            libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as libc::c_uint) as usize
        };
        let mut control = ControlBuffer([0u8; 128]);
        if control_len > control.0.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "IPv6 packet info control buffer is too small",
            ));
        }

        let mut msg = unsafe { mem::zeroed::<libc::msghdr>() };
        msg.msg_name = dst_addr.as_ptr() as *mut libc::c_void;
        msg.msg_namelen = dst_addr.len() as _;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.0.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = control_len as _;
        msg.msg_flags = 0;

        unsafe {
            let cmsg = libc::CMSG_FIRSTHDR(&msg);
            if cmsg.is_null() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "IPv6 packet info control buffer is invalid",
                ));
            }
            (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
            (*cmsg).cmsg_type = libc::IPV6_PKTINFO;
            (*cmsg).cmsg_len =
                libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as libc::c_uint) as _;
            ptr::write(libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo, pktinfo);

            let ret = libc::sendmsg(socket.as_raw_fd(), &msg, 0);
            if ret < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(ret as usize)
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn send_to_with_src_ipv6(
    _socket: &UdpSocket,
    _src_ip: Ipv6Addr,
    _src_ifindex: u32,
    _dst_addr: SocketAddrV6,
    _buf: &[u8],
) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "sending UDP with a selected IPv6 source is not supported on this platform",
    ))
}
