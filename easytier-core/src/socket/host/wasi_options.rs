use std::io;

use crate::socket::{
    tcp::{TcpConnectOptions, TcpListenOptions, TcpListenPurpose, TcpSocketPurpose},
    udp::{UdpBindOptions, UdpSocketPurpose},
};

use super::{
    HostSocketHandle,
    factory::{HostTcpConnectResult, HostUdpBindResult},
    listener::HostTcpBindResult,
    wasi_wire::{SOCKET_ADDRESS_LEN, decode_socket_address, encode_socket_address},
};

const OPTIONS_VERSION: u8 = 1;
pub(super) const TCP_SOCKET_RESULT_LEN: usize = 8 + SOCKET_ADDRESS_LEN * 2;
pub(super) const BOUND_SOCKET_RESULT_LEN: usize = 8 + SOCKET_ADDRESS_LEN;

pub(super) fn encode_tcp_connect_options(options: &TcpConnectOptions) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::with_capacity(69 + bind_device_len(&options.bind.bind_device));
    encoded.push(OPTIONS_VERSION);
    encoded.extend_from_slice(&encode_socket_address(options.remote_addr));
    encode_optional_address(&mut encoded, options.bind.local_addr);
    encode_mark(&mut encoded, options.bind.socket_mark);
    encoded.push(match options.bind.reuse_addr {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
    encoded.push(u8::from(options.bind.reuse_port));
    encoded.push(u8::from(options.bind.only_v6));
    encoded.push(match options.purpose {
        TcpSocketPurpose::DirectConnect => 0,
        TcpSocketPurpose::FakeTcp => 1,
        TcpSocketPurpose::HolePunch => 2,
        TcpSocketPurpose::ManualConnect => 3,
        TcpSocketPurpose::ProxyNat => 4,
    });
    encode_bind_device(&mut encoded, &options.bind.bind_device)?;
    Ok(encoded)
}

pub(super) fn encode_udp_bind_options(options: &UdpBindOptions) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::with_capacity(42 + bind_device_len(&options.bind_device));
    encoded.push(OPTIONS_VERSION);
    encode_optional_address(&mut encoded, options.local_addr);
    encode_mark(&mut encoded, options.socket_mark);
    encoded.push(u8::from(options.reuse_addr));
    encoded.push(u8::from(options.reuse_port));
    encoded.push(u8::from(options.only_v6));
    encoded.push(match options.purpose {
        UdpSocketPurpose::HolePunchControl => 0,
        UdpSocketPurpose::HolePunchCandidate => 1,
        UdpSocketPurpose::DirectConnect => 2,
        UdpSocketPurpose::PortBoundListener => 3,
        UdpSocketPurpose::ProxyNat => 4,
    });
    encode_bind_device(&mut encoded, &options.bind_device)?;
    Ok(encoded)
}

pub(super) fn encode_tcp_listen_options(options: &TcpListenOptions) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::with_capacity(42 + bind_device_len(&options.bind.bind_device));
    encoded.push(OPTIONS_VERSION);
    encode_optional_address(&mut encoded, options.bind.local_addr);
    encode_mark(&mut encoded, options.bind.socket_mark);
    encoded.push(match options.bind.reuse_addr {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
    encoded.push(u8::from(options.bind.reuse_port));
    encoded.push(u8::from(options.bind.only_v6));
    encoded.push(match options.purpose {
        TcpListenPurpose::DirectConnect => 0,
        TcpListenPurpose::HolePunch => 1,
        TcpListenPurpose::ManualConnect => 2,
        TcpListenPurpose::ProxyNat => 3,
    });
    encode_bind_device(&mut encoded, &options.bind.bind_device)?;
    Ok(encoded)
}

pub(super) fn decode_tcp_socket_result(
    encoded: &[u8; TCP_SOCKET_RESULT_LEN],
) -> io::Result<HostTcpConnectResult> {
    let local = <[u8; SOCKET_ADDRESS_LEN]>::try_from(&encoded[8..8 + SOCKET_ADDRESS_LEN]).unwrap();
    let peer = <[u8; SOCKET_ADDRESS_LEN]>::try_from(&encoded[8 + SOCKET_ADDRESS_LEN..]).unwrap();
    Ok(HostTcpConnectResult {
        handle: HostSocketHandle(u64::from_be_bytes(encoded[..8].try_into().unwrap())),
        local_addr: decode_socket_address(&local)?,
        peer_addr: decode_socket_address(&peer)?,
        transport_label: None,
    })
}

pub(super) fn decode_udp_bind_result(
    encoded: &[u8; BOUND_SOCKET_RESULT_LEN],
) -> io::Result<HostUdpBindResult> {
    Ok(HostUdpBindResult {
        handle: decode_bound_handle(encoded),
        local_addr: decode_bound_address(encoded)?,
    })
}

pub(super) fn decode_tcp_bind_result(
    encoded: &[u8; BOUND_SOCKET_RESULT_LEN],
) -> io::Result<HostTcpBindResult> {
    Ok(HostTcpBindResult {
        handle: decode_bound_handle(encoded),
        local_addr: decode_bound_address(encoded)?,
    })
}

fn decode_bound_handle(encoded: &[u8; BOUND_SOCKET_RESULT_LEN]) -> HostSocketHandle {
    HostSocketHandle(u64::from_be_bytes(encoded[..8].try_into().unwrap()))
}

fn decode_bound_address(
    encoded: &[u8; BOUND_SOCKET_RESULT_LEN],
) -> io::Result<std::net::SocketAddr> {
    let address = <[u8; SOCKET_ADDRESS_LEN]>::try_from(&encoded[8..]).unwrap();
    decode_socket_address(&address)
}

fn encode_optional_address(encoded: &mut Vec<u8>, address: Option<std::net::SocketAddr>) {
    encoded.extend_from_slice(
        &address
            .map(encode_socket_address)
            .unwrap_or([0; SOCKET_ADDRESS_LEN]),
    );
}

fn encode_mark(encoded: &mut Vec<u8>, mark: Option<u32>) {
    encoded.push(u8::from(mark.is_some()));
    encoded.extend_from_slice(&mark.unwrap_or_default().to_be_bytes());
}

fn encode_bind_device(encoded: &mut Vec<u8>, device: &Option<String>) -> io::Result<()> {
    let bytes = device.as_deref().unwrap_or_default().as_bytes();
    encoded.push(u8::from(device.is_some()));
    let length = u32::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bind device is too long"))?;
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
    Ok(())
}

fn bind_device_len(device: &Option<String>) -> usize {
    device.as_ref().map_or(0, String::len)
}

#[cfg(test)]
mod tests {
    use crate::socket::tcp::TcpBindOptions;

    use super::*;

    #[test]
    fn encodes_tcp_connect_options_with_stable_offsets() {
        let options = TcpConnectOptions {
            remote_addr: "192.0.2.2:11013".parse().unwrap(),
            bind: TcpBindOptions::default()
                .with_local_addr(Some("[2001:db8::1]:22026".parse().unwrap()))
                .with_socket_mark(Some(0x01020304))
                .with_bind_device(Some("mihomo0".to_owned()))
                .with_reuse_addr(true)
                .with_reuse_port(true)
                .with_only_v6(true),
            purpose: TcpSocketPurpose::ManualConnect,
        };
        let encoded = encode_tcp_connect_options(&options).unwrap();
        assert_eq!(encoded.len(), 76);
        assert_eq!(encoded[0], OPTIONS_VERSION);
        assert_eq!(&encoded[55..60], &[1, 1, 2, 3, 4]);
        assert_eq!(&encoded[60..64], &[2, 1, 1, 3]);
        assert_eq!(encoded[64], 1);
        assert_eq!(&encoded[65..69], &7_u32.to_be_bytes());
        assert_eq!(&encoded[69..], b"mihomo0");
    }

    #[test]
    fn bind_device_presence_distinguishes_none_empty_and_named() {
        let remote = "192.0.2.2:11013".parse().unwrap();
        let none = encode_tcp_connect_options(&TcpConnectOptions::direct_connect(remote)).unwrap();
        let empty = encode_tcp_connect_options(
            &TcpConnectOptions::direct_connect(remote)
                .with_bind(TcpBindOptions::default().with_bind_device(Some(String::new()))),
        )
        .unwrap();
        assert_eq!(&none[64..69], &[0, 0, 0, 0, 0]);
        assert_eq!(&empty[64..69], &[1, 0, 0, 0, 0]);

        let udp_none = encode_udp_bind_options(&UdpBindOptions::direct_connect()).unwrap();
        let udp_empty = encode_udp_bind_options(
            &UdpBindOptions::direct_connect().with_bind_device(Some(String::new())),
        )
        .unwrap();
        assert_eq!(&udp_none[37..42], &[0, 0, 0, 0, 0]);
        assert_eq!(&udp_empty[37..42], &[1, 0, 0, 0, 0]);

        let listen_none = encode_tcp_listen_options(&TcpListenOptions::direct_connect(
            "192.0.2.1:11013".parse().unwrap(),
        ))
        .unwrap();
        let listen_empty = encode_tcp_listen_options(
            &TcpListenOptions::direct_connect("192.0.2.1:11013".parse().unwrap())
                .with_bind(TcpBindOptions::default().with_bind_device(Some(String::new()))),
        )
        .unwrap();
        assert_eq!(&listen_none[37..42], &[0, 0, 0, 0, 0]);
        assert_eq!(&listen_empty[37..42], &[1, 0, 0, 0, 0]);
    }

    #[test]
    fn encodes_udp_proxy_nat_purpose() {
        let encoded = encode_udp_bind_options(&UdpBindOptions::proxy_nat()).unwrap();
        assert_eq!(encoded[36], 4);
    }

    #[test]
    fn encodes_tcp_proxy_nat_purposes() {
        let remote = "192.0.2.2:11013".parse().unwrap();
        let connect = encode_tcp_connect_options(&TcpConnectOptions::proxy_nat(remote)).unwrap();
        assert_eq!(connect[63], 4);

        let local = "0.0.0.0:0".parse().unwrap();
        let listen = encode_tcp_listen_options(&TcpListenOptions::proxy_nat(local)).unwrap();
        assert_eq!(listen[36], 3);
    }

    #[test]
    fn decodes_fixed_socket_results() {
        let mut tcp = [0_u8; TCP_SOCKET_RESULT_LEN];
        tcp[..8].copy_from_slice(&41_u64.to_be_bytes());
        tcp[8..35].copy_from_slice(&encode_socket_address("192.0.2.1:40100".parse().unwrap()));
        tcp[35..].copy_from_slice(&encode_socket_address("192.0.2.2:11013".parse().unwrap()));
        let result = decode_tcp_socket_result(&tcp).unwrap();
        assert_eq!(result.handle, HostSocketHandle(41));
        assert_eq!(result.local_addr, "192.0.2.1:40100".parse().unwrap());
        assert_eq!(result.peer_addr, "192.0.2.2:11013".parse().unwrap());

        let mut bound = [0_u8; BOUND_SOCKET_RESULT_LEN];
        bound[..8].copy_from_slice(&42_u64.to_be_bytes());
        bound[8..].copy_from_slice(&encode_socket_address("[::]:22026".parse().unwrap()));
        assert_eq!(
            decode_udp_bind_result(&bound).unwrap().handle,
            HostSocketHandle(42)
        );
        assert_eq!(
            decode_tcp_bind_result(&bound).unwrap().local_addr,
            "[::]:22026".parse().unwrap()
        );
    }
}
