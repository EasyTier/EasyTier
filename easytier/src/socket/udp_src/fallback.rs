use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use tokio::net::UdpSocket;

pub(crate) fn enable_recv_pktinfo(_socket: &UdpSocket) -> io::Result<()> {
    Ok(())
}

pub(crate) async fn recv_from_with_dst_ip(
    socket: &UdpSocket,
    buf: &mut [u8],
) -> io::Result<(usize, SocketAddr, Option<IpAddr>)> {
    let (len, addr) = socket.recv_from(buf).await?;
    Ok((len, addr, None))
}

pub(crate) async fn send_to_with_src_ip(
    socket: &UdpSocket,
    src_ip: IpAddr,
    dst_addr: SocketAddr,
    buf: &[u8],
) -> io::Result<usize> {
    match (src_ip, dst_addr) {
        (IpAddr::V4(src), SocketAddr::V4(dst)) => {
            send_to_with_src_ipv4(socket, src, dst, buf).await
        }
        (IpAddr::V4(src), SocketAddr::V6(dst)) => {
            let Some(mapped_dst) = dst.ip().to_ipv4_mapped() else {
                return Err(source_address_family_mismatch(src, dst));
            };
            send_to_with_src_ipv4(socket, src, SocketAddrV4::new(mapped_dst, dst.port()), buf).await
        }
        (IpAddr::V6(src), SocketAddr::V6(dst)) => {
            socket
                .async_io(tokio::io::Interest::WRITABLE, || {
                    send_to_with_src_ipv6(socket, src, 0, dst, buf)
                })
                .await
        }
        (src, dst) => Err(source_address_family_mismatch(src, dst)),
    }
}

async fn send_to_with_src_ipv4(
    socket: &UdpSocket,
    _src_ip: Ipv4Addr,
    dst_addr: SocketAddrV4,
    buf: &[u8],
) -> io::Result<usize> {
    socket
        .async_io(tokio::io::Interest::WRITABLE, || {
            socket.try_send_to(buf, SocketAddr::V4(dst_addr))
        })
        .await
}

fn send_to_with_src_ipv6(
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

fn source_address_family_mismatch(
    src: impl std::fmt::Display,
    dst: impl std::fmt::Display,
) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("source address {src} does not match destination {dst} family"),
    )
}
