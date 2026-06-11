use std::{
    io,
    net::{Ipv6Addr, SocketAddrV6},
};

use tokio::net::UdpSocket;

#[cfg(unix)]
pub(crate) fn send_to_with_src_ipv6(
    socket: &UdpSocket,
    src_ip: Ipv6Addr,
    dst_addr: SocketAddrV6,
    buf: &[u8],
) -> io::Result<usize> {
    use std::{io::IoSlice, os::fd::AsRawFd};

    use nix::libc;
    use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrIn6, sendmsg};

    let pktinfo = libc::in6_pktinfo {
        ipi6_ifindex: 0,
        ipi6_addr: libc::in6_addr {
            s6_addr: src_ip.octets(),
        },
    };
    let iov = [IoSlice::new(buf)];
    let cmsgs = [ControlMessage::Ipv6PacketInfo(&pktinfo)];
    let dst_addr = SockaddrIn6::from(dst_addr);

    sendmsg(
        socket.as_raw_fd(),
        &iov,
        &cmsgs,
        MsgFlags::empty(),
        Some(&dst_addr),
    )
    .map_err(|err| io::Error::from_raw_os_error(err as i32))
}

#[cfg(windows)]
pub(crate) fn send_to_with_src_ipv6(
    socket: &UdpSocket,
    src_ip: Ipv6Addr,
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
        ipi6_ifindex: dst_addr.scope_id(),
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
            &mut sent,
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
    _dst_addr: SocketAddrV6,
    _buf: &[u8],
) -> io::Result<usize> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "sending UDP with a selected IPv6 source is not supported on this platform",
    ))
}
