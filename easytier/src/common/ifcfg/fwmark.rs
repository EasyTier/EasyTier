//! Linux policy routing: fwmark utilities and constants.
//!
//! Used to set SO_MARK on sockets, marking easytier-core traffic to bypass the VPN routing table.

use std::os::unix::io::AsRawFd;

use nix::libc;

// ============================================================================
// Constants
// ============================================================================

/// EasyTier dedicated routing table number (35 = "ET" on keyboard).
pub const EASYTIER_ROUTE_TABLE: u8 = 35;

/// Linux main routing table.
pub const RT_TABLE_MAIN: u8 = 254;

/// Linux default routing table.
pub const RT_TABLE_DEFAULT: u8 = 253;

/// Fwmark mask, uses only the third byte (bits 16:23).
/// Avoids conflicts with sysadmins (first byte) and Kubernetes (second byte).
pub const ET_FWMARK_MASK: u32 = 0xff0000;

/// Bypass traffic mark.
/// Traffic from easytier-core to other nodes must bypass the VPN routing table.
pub const ET_BYPASS_MARK: u32 = 0x90000;

/// IP rule base priority.
pub const IP_RULE_PREF_BASE: u32 = 5300;

/// Rule priority offsets relative to base.
pub const IP_RULE_OFFSET_MAIN: u32 = 10; // 5310: bypass → main
pub const IP_RULE_OFFSET_DEFAULT: u32 = 30; // 5330: bypass → default
pub const IP_RULE_OFFSET_UNREACHABLE: u32 = 50; // 5350: bypass → unreachable
pub const IP_RULE_OFFSET_VPN: u32 = 70; // 5370: all → table 35

/// Calculate actual priority from offset.
#[inline]
pub const fn rule_priority(offset: u32) -> u32 {
    IP_RULE_PREF_BASE + offset
}

// ============================================================================
// Socket Fwmark Functions
// ============================================================================

/// Set SO_MARK on a socket.
///
/// # Arguments
/// * `socket` - Any type implementing AsRawFd (std::net::UdpSocket, tokio::net::UdpSocket, etc.)
/// * `mark` - The fwmark value to set.
pub fn set_socket_mark<S: AsRawFd>(socket: &S, mark: u32) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    let mark = mark as libc::c_int;
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const _ as *const libc::c_void,
            std::mem::size_of_val(&mark) as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Set bypass mark on a socket.
///
/// This is a convenience wrapper around `set_socket_mark` using `ET_BYPASS_MARK`.
pub fn set_socket_bypass_mark<S: AsRawFd>(socket: &S) -> std::io::Result<()> {
    set_socket_mark(socket, ET_BYPASS_MARK)
}

/// Get the current fwmark of a socket.
pub fn get_socket_mark<S: AsRawFd>(socket: &S) -> std::io::Result<u32> {
    let fd = socket.as_raw_fd();
    let mut mark: libc::c_int = 0;
    let mut len: libc::socklen_t = std::mem::size_of_val(&mark) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mut mark as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(mark as u32)
}

// ============================================================================
// Bypass Socket Factory Functions
// ============================================================================

use std::net::SocketAddr;

/// Create a UDP socket with bypass fwmark pre-applied.
///
/// This is the recommended way to create UDP sockets for external connections
/// (STUN, hole punching, etc.) to prevent routing loops.
///
/// # Arguments
/// * `bind_addr` - The address to bind to (e.g., "0.0.0.0:0" or "[::]:0")
///
/// # Returns
/// A tokio UdpSocket with SO_MARK set to ET_BYPASS_MARK on Linux.
pub async fn create_bypass_udp_socket(bind_addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let socket2_socket = socket2::Socket::new(
        socket2::Domain::for_address(bind_addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;

    // Set bypass fwmark FIRST, before any other operations
    if let Err(e) = set_socket_bypass_mark(&socket2_socket) {
        tracing::warn!(?e, "failed to set socket fwmark (may require CAP_NET_ADMIN)");
    }

    socket2_socket.set_nonblocking(true)?;
    socket2_socket.set_reuse_address(true)?;

    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    {
        let _ = socket2_socket.set_reuse_port(true);
    }

    if bind_addr.is_ipv6() {
        socket2_socket.set_only_v6(true)?;
    }

    socket2_socket.bind(&socket2::SockAddr::from(bind_addr))?;

    let std_socket: std::net::UdpSocket = socket2_socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

/// Create an IPv4 UDP socket with bypass fwmark on the specified port.
///
/// Convenience wrapper for `create_bypass_udp_socket` with IPv4 wildcard address.
pub async fn create_bypass_udp_socket_v4(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    create_bypass_udp_socket(bind_addr).await
}

/// Create an IPv6 UDP socket with bypass fwmark on the specified port.
///
/// Convenience wrapper for `create_bypass_udp_socket` with IPv6 wildcard address.
pub async fn create_bypass_udp_socket_v6(port: u16) -> std::io::Result<tokio::net::UdpSocket> {
    let bind_addr: SocketAddr = format!("[::]:{}", port).parse().unwrap();
    create_bypass_udp_socket(bind_addr).await
}

/// Create a TCP socket (not connected) with bypass fwmark pre-applied.
///
/// # Arguments
/// * `is_ipv6` - Whether to create an IPv6 socket
///
/// # Returns
/// A socket2::Socket ready for bind() and connect() operations.
pub fn create_bypass_tcp_socket(is_ipv6: bool) -> std::io::Result<socket2::Socket> {
    let domain = if is_ipv6 {
        socket2::Domain::IPV6
    } else {
        socket2::Domain::IPV4
    };

    let socket2_socket = socket2::Socket::new(
        domain,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;

    // Set bypass fwmark FIRST
    if let Err(e) = set_socket_bypass_mark(&socket2_socket) {
        tracing::warn!(?e, "failed to set socket fwmark (may require CAP_NET_ADMIN)");
    }

    socket2_socket.set_nonblocking(true)?;
    socket2_socket.set_reuse_address(true)?;

    if is_ipv6 {
        socket2_socket.set_only_v6(true)?;
    }

    Ok(socket2_socket)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    #[test]
    fn test_set_and_get_socket_mark() {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();

        match set_socket_mark(&socket, 0x12345) {
            Ok(_) => {
                let mark = get_socket_mark(&socket).unwrap();
                assert_eq!(mark, 0x12345);
            }
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("Skipping test: CAP_NET_ADMIN required");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }

    #[test]
    fn test_set_bypass_mark() {
        let socket = UdpSocket::bind("0.0.0.0:0").unwrap();

        match set_socket_bypass_mark(&socket) {
            Ok(_) => {
                let mark = get_socket_mark(&socket).unwrap();
                assert_eq!(mark, ET_BYPASS_MARK);
            }
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                eprintln!("Skipping test: CAP_NET_ADMIN required");
            }
            Err(e) => panic!("Unexpected error: {:?}", e),
        }
    }
}
