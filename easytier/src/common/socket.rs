use std::{
    fmt::Debug,
    io::{IoSliceMut, Result as IoResult},
    net::{IpAddr, SocketAddr, UdpSocket as StdUdpSocket},
};

use tokio::{io::Interest, net::UdpSocket as TokioUdpSocket};

use quinn_udp::{RecvMeta, Transmit, UdpSocketState};

use cfg_if::cfg_if;
use socket2::SockRef;

#[cfg(unix)]
pub mod options {
    use crate::arch::unix::set_socket_option_supported;
    use cfg_if::cfg_if;
    use nix::libc;
    use socket2::SockRef;
    use std::io::Result as IoResult;

    pub fn set_socket_fragmentation(socket: SockRef<'_>, enabled: bool) -> IoResult<bool> {
        let addr = socket.local_addr()?;
        let is_ipv4 = addr.family() == libc::AF_INET as libc::sa_family_t;

        let mut all_supported = true;

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            all_supported = all_supported
                && set_socket_option_supported(
                    &*socket,
                    libc::IPPROTO_IP,
                    libc::IP_MTU_DISCOVER,
                    if enabled {
                        libc::IP_PMTUDISC_DONT
                    } else {
                        libc::IP_PMTUDISC_PROBE
                    },
                )?;
            if !is_ipv4 {
                all_supported = all_supported
                    && set_socket_option_supported(
                        &*socket,
                        libc::IPPROTO_IPV6,
                        libc::IPV6_MTU_DISCOVER,
                        if enabled {
                            libc::IPV6_PMTUDISC_DONT
                        } else {
                            libc::IPV6_PMTUDISC_PROBE
                        },
                    )?;
            }
        }

        #[cfg(any(target_os = "freebsd", target_vendor = "apple"))]
        {
            if is_ipv4 {
                all_supported = all_supported
                    && set_socket_option_supported(
                        &*socket,
                        libc::IPPROTO_IP,
                        libc::IP_DONTFRAG,
                        (!enabled).into(),
                    )?;
            }
        }

        if !is_ipv4 {
            all_supported = all_supported
                && set_socket_option_supported(
                    &*socket,
                    libc::IPPROTO_IPV6,
                    libc::IPV6_DONTFRAG,
                    (!enabled).into(),
                )?;
        }

        Ok(all_supported)
    }

    cfg_if! {
        if #[cfg(any(target_os = "linux", target_os = "android"))] {
            pub fn set_socket_gro(socket: SockRef<'_>, enabled: bool) -> IoResult<bool> {
                set_socket_option_supported(&*socket, libc::SOL_UDP, libc::UDP_GRO, enabled.into())
            }
            pub fn set_socket_gso(socket: SockRef<'_>, segment_size: Option<u32>) -> IoResult<bool> {
                set_socket_option_supported(
                    &*socket,
                    libc::SOL_UDP,
                    libc::UDP_SEGMENT,
                    segment_size.unwrap_or(0) as libc::c_int,
                )
            }
        } else {
            pub fn set_socket_gro(socket: SockRef<'_>, enabled: bool) -> IoResult<bool> {
                Ok(false)
            }
            pub fn set_socket_gso(socket: SockRef<'_>, segment_size: Option<u32>) -> IoResult<bool> {
                Ok(false)
            }
        }
    }
}

#[cfg(windows)]
pub mod options {
    use crate::arch::windows::{get_socket_option, set_socket_option};
    use socket2::SockRef;
    use std::io::Result as IoResult;
    use windows::Win32::Networking::WinSock;

    fn is_socket_v6_only(socket: SockRef<'_>) -> IoResult<bool> {
        get_socket_option(&*socket, WinSock::IPPROTO_IPV6.0, WinSock::IPV6_V6ONLY).map(|r| r != 0)
    }

    pub fn set_socket_fragmentation(socket: SockRef<'_>, enabled: bool) -> IoResult<bool> {
        let addr = socket.local_addr()?;
        let is_ipv6 = addr.as_socket_ipv6().is_some();
        let is_ipv4 = addr.as_socket_ipv4().is_some() || !is_socket_v6_only((&*socket).into())?;

        if is_ipv4 {
            set_socket_option(
                &*socket,
                WinSock::IPPROTO_IP.0,
                WinSock::IP_DONTFRAGMENT,
                (!enabled).into(),
            )?;
        }
        if is_ipv6 {
            set_socket_option(
                &*socket,
                WinSock::IPPROTO_IPV6.0,
                WinSock::IPV6_DONTFRAG,
                (!enabled).into(),
            )?;
        }

        Ok(true)
    }

    pub fn set_socket_gro(socket: SockRef<'_>, enabled: bool) -> IoResult<bool> {
        let ret = set_socket_option(
            &*socket,
            WinSock::IPPROTO_UDP.0,
            WinSock::UDP_RECV_MAX_COALESCED_SIZE,
            // u32 per https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-udp-socket-options.
            // Choice of 2^16 - 1 inspired by msquic.
            if enabled { u16::MAX as u32 } else { 0 },
        );
        Ok(ret.is_ok())
    }
    pub fn set_socket_gso(socket: SockRef<'_>, segment_size: Option<u32>) -> IoResult<bool> {
        let ret = set_socket_option(
            &*socket,
            WinSock::IPPROTO_UDP.0,
            WinSock::UDP_SEND_MSG_SIZE,
            segment_size.unwrap_or(0),
        );
        Ok(ret.is_ok())
    }
}

#[cfg(not(any(unix, windows)))]
pub mod options {
    use socket2::SockRef;
    use std::io::Result as IoResult;

    pub fn set_socket_fragmentation(socket: SockRef<'_>, enabled: bool) -> IoResult<bool> {
        Ok(false)
    }

    pub fn set_socket_gro(socket: SockRef<'_>, enabled: bool) -> IoResult<bool> {
        Ok(false)
    }
    pub fn set_socket_gso(socket: SockRef<'_>, segment_size: Option<u32>) -> IoResult<bool> {
        Ok(false)
    }
}

#[derive(Debug, derive_more::Into)]
pub struct UdpSocket {
    #[into]
    io: TokioUdpSocket,
    ext: UdpSocketState,
}

impl TryFrom<TokioUdpSocket> for UdpSocket {
    type Error = std::io::Error;

    fn try_from(value: TokioUdpSocket) -> IoResult<Self> {
        let ext = UdpSocketState::new((&value).into())?;
        // turn off these options used by QUIC
        options::set_socket_fragmentation((&value).into(), true)?;
        options::set_socket_gro((&value).into(), false)?;
        options::set_socket_gso((&value).into(), None)?;
        Ok(Self { io: value, ext })
    }
}

cfg_if! {
    if #[cfg(windows)] {
        use std::os::windows::io::{RawSocket, AsRawSocket};

        impl AsRawSocket for UdpSocket {
            fn as_raw_socket(&self) -> RawSocket {
                self.io.as_raw_socket()
            }
        }
    }
}

impl<'s> From<&'s UdpSocket> for SockRef<'s> {
    fn from(value: &'s UdpSocket) -> Self {
        (&value.io).into()
    }
}

impl UdpSocket {
    pub fn from_std(socket: StdUdpSocket) -> IoResult<Self> {
        TokioUdpSocket::from_std(socket)?.try_into()
    }

    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A) -> IoResult<Self> {
        TokioUdpSocket::bind(addr).await?.try_into()
    }

    delegate::delegate! {
        to self.io {
            pub fn into_std(self) -> IoResult<StdUdpSocket>;
            pub fn local_addr(&self) -> IoResult<SocketAddr>;
            pub fn peer_addr(&self) -> IoResult<SocketAddr>;
        }
    }

    fn inner_send_to(
        &self,
        buf: &[u8],
        addr: SocketAddr,
        src_ip: Option<IpAddr>,
    ) -> IoResult<usize> {
        self.ext.try_send(
            (&self.io).into(),
            &Transmit {
                destination: addr,
                ecn: Option::None,
                contents: buf,
                segment_size: Option::None,
                src_ip,
            },
        )?;
        Ok(buf.len())
    }

    pub async fn send_to(
        &self,
        buf: &[u8],
        addr: SocketAddr,
        src_ip: Option<IpAddr>,
    ) -> IoResult<usize> {
        self.io
            .async_io(Interest::WRITABLE, || self.inner_send_to(buf, addr, src_ip))
            .await
    }

    fn inner_recv_from(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr, Option<IpAddr>)> {
        let mut buf = IoSliceMut::new(buf);
        let mut meta: RecvMeta = Default::default();
        self.ext.recv(
            (&self.io).into(),
            std::slice::from_mut(&mut buf),
            std::slice::from_mut(&mut meta),
        )?;
        Ok((meta.len, meta.addr, meta.dst_ip))
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> IoResult<(usize, SocketAddr, Option<IpAddr>)> {
        self.io
            .async_io(Interest::READABLE, || self.inner_recv_from(buf))
            .await
    }

    pub async fn recv_buf_from<B: bytes::buf::BufMut>(
        &self,
        buf: &mut B,
    ) -> IoResult<(usize, SocketAddr, Option<IpAddr>)> {
        // basically copies the implementation in tokio
        let dst = buf.chunk_mut();
        let dst = unsafe { &mut *(dst as *mut _ as *mut [std::mem::MaybeUninit<u8>] as *mut [u8]) };
        let (n, addr, dst_ip) = self.recv_from(dst).await?;
        unsafe {
            buf.advance_mut(n);
        }
        Ok((n, addr, dst_ip))
    }
}
