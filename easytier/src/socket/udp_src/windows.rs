use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use std::sync::OnceLock;

use tokio::net::UdpSocket;

pub(crate) fn enable_recv_pktinfo(socket: &UdpSocket) -> io::Result<()> {
    use std::os::windows::io::AsRawSocket;

    use windows::Win32::Networking::WinSock::{
        IP_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO, SOCKET, setsockopt,
    };

    let enabled = 1u32.to_ne_bytes();
    unsafe {
        let _ = setsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            IPPROTO_IP.0,
            IP_PKTINFO,
            Some(&enabled),
        );
        let _ = setsockopt(
            SOCKET(socket.as_raw_socket() as usize),
            IPPROTO_IPV6.0,
            IPV6_PKTINFO,
            Some(&enabled),
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

fn windows_cmsghdr_align(length: usize) -> usize {
    use windows::Win32::Networking::WinSock::CMSGHDR;

    (length + std::mem::align_of::<CMSGHDR>() - 1) & !(std::mem::align_of::<CMSGHDR>() - 1)
}

fn windows_cmsgdata_align(length: usize) -> usize {
    (length + std::mem::align_of::<usize>() - 1) & !(std::mem::align_of::<usize>() - 1)
}

fn windows_cmsg_len(length: usize) -> usize {
    use windows::Win32::Networking::WinSock::CMSGHDR;

    windows_cmsgdata_align(std::mem::size_of::<CMSGHDR>()) + length
}

fn windows_cmsg_space(length: usize) -> usize {
    use windows::Win32::Networking::WinSock::CMSGHDR;

    windows_cmsgdata_align(std::mem::size_of::<CMSGHDR>() + windows_cmsghdr_align(length))
}

fn windows_cmsg_data(cmsg: *mut windows::Win32::Networking::WinSock::CMSGHDR) -> *mut u8 {
    (cmsg as usize
        + windows_cmsgdata_align(std::mem::size_of::<
            windows::Win32::Networking::WinSock::CMSGHDR,
        >())) as *mut u8
}

fn wsa_recvmsg_ptr() -> windows::Win32::Networking::WinSock::LPFN_WSARECVMSG {
    use std::mem;

    use windows::Win32::Networking::WinSock::{
        AF_INET, INVALID_SOCKET, IPPROTO_UDP, SIO_GET_EXTENSION_FUNCTION_POINTER, SOCK_DGRAM,
        WSAID_WSARECVMSG, WSAIoctl, closesocket, socket,
    };

    static WSA_RECVMSG: OnceLock<windows::Win32::Networking::WinSock::LPFN_WSARECVMSG> =
        OnceLock::new();

    *WSA_RECVMSG.get_or_init(|| unsafe {
        let Ok(socket) = socket(AF_INET.0.into(), SOCK_DGRAM, IPPROTO_UDP.0) else {
            return None;
        };
        if socket == INVALID_SOCKET {
            return None;
        }

        let guid = WSAID_WSARECVMSG;
        let mut recvmsg = None;
        let mut len = 0;
        let ret = WSAIoctl(
            socket,
            SIO_GET_EXTENSION_FUNCTION_POINTER,
            Some(&guid as *const _ as *const _),
            mem::size_of_val(&guid) as u32,
            Some(&mut recvmsg as *mut _ as *mut _),
            mem::size_of_val(&recvmsg) as u32,
            &mut len,
            None,
            None,
        );
        closesocket(socket);
        if ret == -1 || len as usize != mem::size_of_val(&recvmsg) {
            None
        } else {
            recvmsg
        }
    })
}

fn sockaddr_inet_to_socket_addr(
    addr: &windows::Win32::Networking::WinSock::SOCKADDR_INET,
) -> io::Result<SocketAddr> {
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let family = unsafe { addr.si_family };
    if family == AF_INET {
        let addr = unsafe { addr.Ipv4 };
        let ip = Ipv4Addr::from(u32::from_be(unsafe { addr.sin_addr.S_un.S_addr }));
        let port = u16::from_be(addr.sin_port);
        return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
    }
    if family == AF_INET6 {
        let addr = unsafe { addr.Ipv6 };
        let ip = Ipv6Addr::from(unsafe { addr.sin6_addr.u.Byte });
        let port = u16::from_be(addr.sin6_port);
        let scope_id = unsafe { addr.Anonymous.sin6_scope_id };
        return Ok(SocketAddr::V6(SocketAddrV6::new(
            ip,
            port,
            addr.sin6_flowinfo,
            scope_id,
        )));
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unsupported UDP sockaddr family",
    ))
}

fn recv_from_with_dst_ip_once(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    use std::{mem, os::windows::io::AsRawSocket, ptr};

    use windows::{
        Win32::Networking::WinSock::{
            CMSGHDR, IN_PKTINFO, IN6_PKTINFO, IP_PKTINFO, IPPROTO_IP, IPPROTO_IPV6, IPV6_PKTINFO,
            SOCKADDR_INET, SOCKET, SOCKET_ERROR, WSABUF, WSAGetLastError, WSAMSG,
        },
        core::PSTR,
    };

    #[repr(align(8))]
    struct ControlBuffer([u8; 256]);

    let Some(wsa_recvmsg) = wsa_recvmsg_ptr() else {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "WSARecvMsg is not supported",
        ));
    };

    let mut source = unsafe { mem::zeroed::<SOCKADDR_INET>() };
    let mut data = WSABUF {
        len: buf.len() as u32,
        buf: PSTR(buf.as_mut_ptr()),
    };
    let mut control = ControlBuffer([0u8; 256]);
    let mut msg = WSAMSG {
        name: &mut source as *mut _ as *mut _,
        namelen: mem::size_of_val(&source) as i32,
        lpBuffers: &mut data,
        dwBufferCount: 1,
        Control: WSABUF {
            len: control.0.len() as u32,
            buf: PSTR(control.0.as_mut_ptr()),
        },
        dwFlags: 0,
    };

    let mut len = 0;
    let ret = unsafe {
        wsa_recvmsg(
            SOCKET(socket.as_raw_socket() as usize),
            &mut msg,
            &mut len,
            ptr::null_mut(),
            None,
        )
    };
    if ret == SOCKET_ERROR {
        return Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError().0 }));
    }

    let remote_addr = sockaddr_inet_to_socket_addr(&source)?;
    let mut dst_ip = None;
    let control_start = msg.Control.buf.0 as usize;
    let control_end = control_start + msg.Control.len as usize;
    let mut cmsg_ptr = control_start;
    while cmsg_ptr + mem::size_of::<CMSGHDR>() <= control_end {
        let cmsg = cmsg_ptr as *const CMSGHDR;
        let cmsg_len = unsafe { (*cmsg).cmsg_len };
        if cmsg_len < mem::size_of::<CMSGHDR>() || cmsg_ptr + cmsg_len > control_end {
            break;
        }
        match (unsafe { (*cmsg).cmsg_level }, unsafe { (*cmsg).cmsg_type }) {
            (level, cmsg_type) if level == IPPROTO_IP.0 && cmsg_type == IP_PKTINFO => {
                let pktinfo = unsafe { &*(windows_cmsg_data(cmsg as *mut _) as *const IN_PKTINFO) };
                dst_ip = Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(unsafe {
                    pktinfo.ipi_addr.S_un.S_addr
                }))));
            }
            (level, cmsg_type) if level == IPPROTO_IPV6.0 && cmsg_type == IPV6_PKTINFO => {
                let pktinfo =
                    unsafe { &*(windows_cmsg_data(cmsg as *mut _) as *const IN6_PKTINFO) };
                dst_ip = Some(IpAddr::V6(Ipv6Addr::from(unsafe {
                    pktinfo.ipi6_addr.u.Byte
                })));
            }
            _ => {}
        }
        cmsg_ptr += windows_cmsghdr_align(cmsg_len);
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

fn send_to_with_src_ipv4_mapped_v6(
    socket: &UdpSocket,
    src_ip: Ipv4Addr,
    dst_addr: SocketAddrV6,
    _mapped_dst: Ipv4Addr,
    buf: &[u8],
) -> io::Result<usize> {
    send_to_with_src_ipv4_windows(socket, src_ip, SocketAddr::V6(dst_addr), buf)
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

fn send_to_with_src_ipv4(
    socket: &UdpSocket,
    src_ip: Ipv4Addr,
    dst_addr: SocketAddrV4,
    buf: &[u8],
) -> io::Result<usize> {
    send_to_with_src_ipv4_windows(socket, src_ip, SocketAddr::V4(dst_addr), buf)
}

fn send_to_with_src_ipv4_windows(
    socket: &UdpSocket,
    src_ip: Ipv4Addr,
    dst_addr: SocketAddr,
    buf: &[u8],
) -> io::Result<usize> {
    use std::{mem, os::windows::io::AsRawSocket, ptr};

    use windows::{
        Win32::Networking::WinSock::{
            CMSGHDR, IN_ADDR, IN_ADDR_0, IN_PKTINFO, IP_PKTINFO, IPPROTO_IP, SOCKET, SOCKET_ERROR,
            WSABUF, WSAGetLastError, WSAMSG, WSASendMsg,
        },
        core::PSTR,
    };

    #[repr(align(8))]
    struct ControlBuffer([u8; 128]);

    let dst = socket2::SockAddr::from(dst_addr);
    let mut data = WSABUF {
        len: buf.len() as u32,
        buf: PSTR(buf.as_ptr() as *mut u8),
    };
    let control_len = windows_cmsg_space(mem::size_of::<IN_PKTINFO>());
    let mut control = ControlBuffer([0u8; 128]);
    if control_len > control.0.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 packet info control buffer is too small",
        ));
    }
    let msg = WSAMSG {
        name: dst.as_ptr() as *mut _,
        namelen: dst.len(),
        lpBuffers: &mut data,
        dwBufferCount: 1,
        Control: WSABUF {
            len: control_len as u32,
            buf: PSTR(control.0.as_mut_ptr()),
        },
        dwFlags: 0,
    };

    let pktinfo = IN_PKTINFO {
        ipi_addr: IN_ADDR {
            S_un: IN_ADDR_0 {
                S_addr: u32::from(src_ip).to_be(),
            },
        },
        ipi_ifindex: 0,
    };

    unsafe {
        let cmsg = control.0.as_mut_ptr() as *mut CMSGHDR;
        (*cmsg).cmsg_level = IPPROTO_IP.0;
        (*cmsg).cmsg_type = IP_PKTINFO;
        (*cmsg).cmsg_len = windows_cmsg_len(mem::size_of::<IN_PKTINFO>());
        ptr::write(windows_cmsg_data(cmsg) as *mut IN_PKTINFO, pktinfo);

        let mut sent = 0;
        let ret = WSASendMsg(
            SOCKET(socket.as_raw_socket() as usize),
            &msg,
            0,
            Some(&mut sent),
            None,
            None,
        );
        if ret == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(WSAGetLastError().0));
        }
        Ok(sent as usize)
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
    use std::{mem, os::windows::io::AsRawSocket, ptr};

    use windows::{
        Win32::Networking::WinSock::{
            CMSGHDR, IN6_ADDR, IN6_ADDR_0, IN6_PKTINFO, IPPROTO_IPV6, IPV6_PKTINFO, SOCKET,
            SOCKET_ERROR, WSABUF, WSAGetLastError, WSAMSG, WSASendMsg,
        },
        core::PSTR,
    };

    #[repr(align(8))]
    struct ControlBuffer([u8; 128]);

    let dst = socket2::SockAddr::from(std::net::SocketAddr::V6(dst_addr));
    let mut data = WSABUF {
        len: buf.len() as u32,
        buf: PSTR(buf.as_ptr() as *mut u8),
    };
    let control_len = windows_cmsg_space(mem::size_of::<IN6_PKTINFO>());
    let mut control = ControlBuffer([0u8; 128]);
    if control_len > control.0.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 packet info control buffer is too small",
        ));
    }
    let msg = WSAMSG {
        name: dst.as_ptr() as *mut _,
        namelen: dst.len(),
        lpBuffers: &mut data,
        dwBufferCount: 1,
        Control: WSABUF {
            len: control_len as u32,
            buf: PSTR(control.0.as_mut_ptr()),
        },
        dwFlags: 0,
    };

    let pktinfo = IN6_PKTINFO {
        ipi6_addr: IN6_ADDR {
            u: IN6_ADDR_0 {
                Byte: src_ip.octets(),
            },
        },
        ipi6_ifindex: src_ifindex,
    };

    unsafe {
        let cmsg = control.0.as_mut_ptr() as *mut CMSGHDR;
        (*cmsg).cmsg_level = IPPROTO_IPV6.0;
        (*cmsg).cmsg_type = IPV6_PKTINFO;
        (*cmsg).cmsg_len = windows_cmsg_len(mem::size_of::<IN6_PKTINFO>());
        ptr::write(windows_cmsg_data(cmsg) as *mut IN6_PKTINFO, pktinfo);
        let mut sent = 0;
        let ret = WSASendMsg(
            SOCKET(socket.as_raw_socket() as usize),
            &msg,
            0,
            Some(&mut sent),
            None,
            None,
        );
        if ret == SOCKET_ERROR {
            return Err(io::Error::from_raw_os_error(WSAGetLastError().0));
        }
        Ok(sent as usize)
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
