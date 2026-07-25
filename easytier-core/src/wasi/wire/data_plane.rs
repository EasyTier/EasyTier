//! Explicit big-endian wire records returned by data-plane guest exports.

use std::{io, net::SocketAddr};

use crate::gateway::{DataPlaneCompletionDescriptor, DataPlaneErrorKind};

use super::socket::{SOCKET_ADDRESS_LEN, decode_socket_address, encode_socket_address};

pub(crate) const COMPLETION_LEN: usize = 12;
pub(crate) const TCP_CONNECT_RESULT_LEN: usize = 8 + SOCKET_ADDRESS_LEN * 2;
pub(crate) const TCP_BIND_RESULT_LEN: usize = 8 + SOCKET_ADDRESS_LEN;
pub(crate) const TCP_ACCEPT_RESULT_LEN: usize = TCP_CONNECT_RESULT_LEN;
pub(crate) const UDP_BIND_RESULT_LEN: usize = TCP_BIND_RESULT_LEN;
pub(crate) const TCP_READ_METADATA_LEN: usize = 1;
pub(crate) const UDP_RECEIVE_METADATA_LEN: usize = SOCKET_ADDRESS_LEN + 1;

pub(crate) fn decode_ipv4_socket_address(wire: &[u8]) -> io::Result<SocketAddr> {
    let wire = <&[u8; SOCKET_ADDRESS_LEN]>::try_from(wire).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "invalid socket address length")
    })?;
    let address = decode_socket_address(wire)?;
    if !address.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "data-plane ABI v2 supports IPv4 only",
        ));
    }
    Ok(address)
}

pub(crate) fn encode_completion(completion: DataPlaneCompletionDescriptor) -> [u8; COMPLETION_LEN] {
    let mut wire = [0; COMPLETION_LEN];
    wire[..8].copy_from_slice(&completion.operation_id.get().to_be_bytes());
    wire[8..10].copy_from_slice(&(completion.kind as u16).to_be_bytes());
    wire[10..12].copy_from_slice(&completion.status.code().to_be_bytes());
    wire
}

pub(crate) fn encode_resource_and_address(
    resource: u64,
    address: SocketAddr,
) -> [u8; TCP_BIND_RESULT_LEN] {
    let mut wire = [0; TCP_BIND_RESULT_LEN];
    wire[..8].copy_from_slice(&resource.to_be_bytes());
    wire[8..].copy_from_slice(&encode_socket_address(address));
    wire
}

pub(crate) fn encode_stream_addresses(
    stream: u64,
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
) -> [u8; TCP_CONNECT_RESULT_LEN] {
    let mut wire = [0; TCP_CONNECT_RESULT_LEN];
    wire[..8].copy_from_slice(&stream.to_be_bytes());
    wire[8..8 + SOCKET_ADDRESS_LEN].copy_from_slice(&encode_socket_address(local_addr));
    wire[8 + SOCKET_ADDRESS_LEN..].copy_from_slice(&encode_socket_address(peer_addr));
    wire
}

pub(crate) fn encode_tcp_read_metadata(eof: bool) -> [u8; TCP_READ_METADATA_LEN] {
    [u8::from(eof)]
}

pub(crate) fn encode_udp_receive_metadata(
    peer_addr: SocketAddr,
    truncated: bool,
) -> [u8; UDP_RECEIVE_METADATA_LEN] {
    let mut wire = [0; UDP_RECEIVE_METADATA_LEN];
    wire[..SOCKET_ADDRESS_LEN].copy_from_slice(&encode_socket_address(peer_addr));
    wire[SOCKET_ADDRESS_LEN] = u8::from(truncated);
    wire
}

pub(crate) fn error_status(kind: DataPlaneErrorKind) -> i32 {
    -(kind as i32)
}

pub(crate) fn normalize_call_status(entered: bool, status: i32) -> i32 {
    if entered {
        status
    } else {
        error_status(DataPlaneErrorKind::HandleClosed)
    }
}

#[cfg(test)]
mod tests {
    use crate::gateway::{DataPlaneCompletionStatus, DataPlaneOperationId, DataPlaneOperationKind};

    use super::*;

    #[test]
    fn completion_record_has_no_native_padding() {
        let completion = DataPlaneCompletionDescriptor {
            operation_id: DataPlaneOperationId::from_raw(0x0102_0304_0506_0708).unwrap(),
            kind: DataPlaneOperationKind::UdpReceive,
            status: DataPlaneCompletionStatus::Error(DataPlaneErrorKind::BufferTooSmall),
        };
        assert_eq!(
            encode_completion(completion),
            [1, 2, 3, 4, 5, 6, 7, 8, 0, 7, 0, 13]
        );
    }

    #[test]
    fn operation_result_records_have_stable_layouts() {
        let local_addr = "192.0.2.1:1234".parse().unwrap();
        let peer_addr = "198.51.100.2:4321".parse().unwrap();
        let resource = 0x0102_0304_0506_0708;

        let resource_and_address = encode_resource_and_address(resource, local_addr);
        assert_eq!(resource_and_address.len(), UDP_BIND_RESULT_LEN);
        assert_eq!(&resource_and_address[..8], &resource.to_be_bytes());
        assert_eq!(
            &resource_and_address[8..],
            &encode_socket_address(local_addr)
        );

        let stream_addresses = encode_stream_addresses(resource, local_addr, peer_addr);
        assert_eq!(stream_addresses.len(), TCP_ACCEPT_RESULT_LEN);
        assert_eq!(&stream_addresses[..8], &resource.to_be_bytes());
        assert_eq!(
            &stream_addresses[8..8 + SOCKET_ADDRESS_LEN],
            &encode_socket_address(local_addr)
        );
        assert_eq!(
            &stream_addresses[8 + SOCKET_ADDRESS_LEN..],
            &encode_socket_address(peer_addr)
        );

        assert_eq!(encode_tcp_read_metadata(false), [0]);
        assert_eq!(encode_tcp_read_metadata(true), [1]);

        let udp_metadata = encode_udp_receive_metadata(peer_addr, true);
        assert_eq!(
            &udp_metadata[..SOCKET_ADDRESS_LEN],
            &encode_socket_address(peer_addr)
        );
        assert_eq!(udp_metadata[SOCKET_ADDRESS_LEN], 1);
    }

    #[test]
    fn public_address_decoder_rejects_ipv6() {
        let address = "[2001:db8::1]:80".parse().unwrap();
        let error = decode_ipv4_socket_address(&encode_socket_address(address)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn lifecycle_failures_use_data_plane_status_codes() {
        assert_eq!(
            normalize_call_status(false, -1),
            error_status(DataPlaneErrorKind::HandleClosed)
        );
        assert_eq!(
            normalize_call_status(true, error_status(DataPlaneErrorKind::Cancelled)),
            error_status(DataPlaneErrorKind::Cancelled)
        );
    }
}
