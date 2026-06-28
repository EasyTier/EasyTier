use std::{
    io,
    net::{Ipv6Addr, SocketAddrV6},
};

use tokio::net::UdpSocket;

#[cfg(unix)]
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

#[cfg(windows)]
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

    fn cmsghdr_align(length: usize) -> usize {
        (length + mem::align_of::<CMSGHDR>() - 1) & !(mem::align_of::<CMSGHDR>() - 1)
    }

    fn cmsgdata_align(length: usize) -> usize {
        (length + mem::align_of::<usize>() - 1) & !(mem::align_of::<usize>() - 1)
    }

    fn cmsg_len(length: usize) -> usize {
        cmsgdata_align(mem::size_of::<CMSGHDR>()) + length
    }

    fn cmsg_space(length: usize) -> usize {
        cmsgdata_align(mem::size_of::<CMSGHDR>() + cmsghdr_align(length))
    }

    fn cmsg_data(cmsg: *mut CMSGHDR) -> *mut u8 {
        (cmsg as usize + cmsgdata_align(mem::size_of::<CMSGHDR>())) as *mut u8
    }

    #[repr(align(8))]
    struct ControlBuffer([u8; 128]);

    let dst = socket2::SockAddr::from(std::net::SocketAddr::V6(dst_addr));
    let mut data = WSABUF {
        len: buf.len() as u32,
        buf: PSTR(buf.as_ptr() as *mut u8),
    };
    let control_len = cmsg_space(mem::size_of::<IN6_PKTINFO>());
    let mut control = ControlBuffer([0u8; 128]);
    if control_len > control.0.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv6 packet info control buffer is too small",
        ));
    }
    let mut msg = WSAMSG {
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
        (*cmsg).cmsg_len = cmsg_len(mem::size_of::<IN6_PKTINFO>());
        ptr::write(cmsg_data(cmsg) as *mut IN6_PKTINFO, pktinfo);
        msg.Control.len = control_len as u32;

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
