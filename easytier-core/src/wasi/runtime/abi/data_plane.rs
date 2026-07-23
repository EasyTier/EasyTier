//! Public data-plane guest exports backed by the instance operation broker.

use std::{net::SocketAddr, time::Duration};

use crate::{
    gateway::{
        DataPlaneError, DataPlaneErrorKind, DataPlaneOperationId, DataPlaneOperationKind,
        DataPlaneOperationResult, DataPlaneResourceId, DataPlaneSession,
    },
    wasi::{
        abi::{
            DATA_PLANE_ABI_VERSION, DATA_PLANE_CAPABILITY, DATA_PLANE_TCP_CAPABILITY,
            DATA_PLANE_UDP_CAPABILITY,
        },
        wire::{
            data_plane::{
                COMPLETION_LEN, TCP_ACCEPT_RESULT_LEN, TCP_BIND_RESULT_LEN, TCP_CONNECT_RESULT_LEN,
                TCP_READ_METADATA_LEN, UDP_BIND_RESULT_LEN, UDP_RECEIVE_METADATA_LEN,
                decode_ipv4_socket_address, encode_completion, encode_resource_and_address,
                encode_stream_addresses, encode_tcp_read_metadata, encode_udp_receive_metadata,
                error_status, normalize_call_status,
            },
            socket::SOCKET_ADDRESS_LEN,
        },
    },
};

use super::{WasiInstance, set_instance_error, with_abi_state, with_abi_state_mut, with_instance};

const OPERATION_ID_LEN: usize = 8;
const MAX_WRITE_LEN: usize = 1024 * 1024;

type WasiDataPlaneSession = DataPlaneSession<
    crate::connectivity::connector_host::ConnectorHost<
        crate::wasi::adapter::socket::backend::WasiHostSocketBackend,
        crate::wasi::adapter::environment::WasiHostConnectorEnvironmentIo,
    >,
>;

impl WasiInstance {
    fn data_plane_session(&self) -> std::sync::Arc<WasiDataPlaneSession> {
        self.core.core().data_plane_session()
    }

    fn submit_data_plane(
        &self,
        submit: impl FnOnce(
            &std::sync::Arc<WasiDataPlaneSession>,
        ) -> Result<DataPlaneOperationId, DataPlaneError>,
    ) -> Result<DataPlaneOperationId, DataPlaneError> {
        let execution = self.execution.lock().unwrap();
        let _domain = crate::foundation::time::enter_domain(self.domain);
        let _runtime = execution.runtime.enter();
        submit(&self.data_plane_session())
    }
}

fn error(kind: DataPlaneErrorKind, message: impl Into<String>) -> DataPlaneError {
    DataPlaneError::new(kind, message)
}

fn invalid_input(message: impl Into<String>) -> DataPlaneError {
    error(DataPlaneErrorKind::Io, message)
}

fn timeout(timeout_ms: u64) -> Option<Duration> {
    (timeout_ms != u64::MAX).then(|| Duration::from_millis(timeout_ms))
}

fn operation_id(raw: u64) -> Result<DataPlaneOperationId, DataPlaneError> {
    DataPlaneOperationId::from_raw(raw)
        .ok_or_else(|| error(DataPlaneErrorKind::HandleClosed, "invalid operation ID"))
}

fn resource_id(raw: u64) -> Result<DataPlaneResourceId, DataPlaneError> {
    DataPlaneResourceId::from_raw(raw)
        .ok_or_else(|| error(DataPlaneErrorKind::HandleClosed, "invalid resource ID"))
}

fn validate_local_port(raw: u32) -> Result<u16, DataPlaneError> {
    u16::try_from(raw).map_err(|_| invalid_input(format!("invalid local port {raw}")))
}

fn data_plane_call(
    handle: u64,
    operation: impl FnOnce(&WasiInstance) -> Result<i32, DataPlaneError>,
) -> i32 {
    let mut entered = false;
    let status = with_instance(handle, |instance| {
        entered = true;
        Ok(match operation(instance) {
            Ok(status) => status,
            Err(error) => {
                let status = error_status(error.kind());
                set_instance_error(handle, error.message());
                status
            }
        })
    });
    normalize_call_status(entered, status)
}

fn validate_output(pointer: u32, capacity: usize, required: usize) -> Result<(), DataPlaneError> {
    if required == 0 && capacity == 0 && pointer == 0 {
        return Ok(());
    }
    if pointer == 0 {
        return Err(invalid_input("guest output buffer pointer is zero"));
    }
    with_abi_state(|state| {
        let buffer = state
            .buffers
            .get(&pointer)
            .ok_or_else(|| invalid_input(format!("unknown guest buffer: {pointer}")))?;
        if capacity > buffer.len() {
            return Err(invalid_input(format!(
                "guest output capacity {capacity} exceeds allocation {}",
                buffer.len()
            )));
        }
        if required > capacity {
            return Err(error(
                DataPlaneErrorKind::BufferTooSmall,
                format!("result requires {required} bytes, buffer has {capacity}"),
            ));
        }
        Ok(())
    })
}

fn validate_fixed_output(pointer: u32, required: usize) -> Result<(), DataPlaneError> {
    validate_output(pointer, required, required)
}

fn write_output(pointer: u32, bytes: &[u8]) -> Result<(), DataPlaneError> {
    if bytes.is_empty() && pointer == 0 {
        return Ok(());
    }
    with_abi_state_mut(|state| {
        let buffer = state
            .buffers
            .get_mut(&pointer)
            .ok_or_else(|| invalid_input(format!("unknown guest buffer: {pointer}")))?;
        if bytes.len() > buffer.len() {
            return Err(error(
                DataPlaneErrorKind::BufferTooSmall,
                format!(
                    "result requires {} bytes, allocation has {}",
                    bytes.len(),
                    buffer.len()
                ),
            ));
        }
        buffer[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    })
}

fn read_input(pointer: u32, length: u32, maximum: usize) -> Result<Vec<u8>, DataPlaneError> {
    let length = usize::try_from(length).expect("u32 fits usize on wasm32");
    if length == 0 {
        return Ok(Vec::new());
    }
    if pointer == 0 || length > maximum {
        return Err(invalid_input("invalid guest input buffer reference"));
    }
    with_abi_state(|state| {
        state
            .read_buffer(pointer, length)
            .map_err(DataPlaneError::from)
    })
}

fn read_ipv4_address(pointer: u32) -> Result<SocketAddr, DataPlaneError> {
    let encoded = read_input(pointer, SOCKET_ADDRESS_LEN as u32, SOCKET_ADDRESS_LEN)?;
    decode_ipv4_socket_address(&encoded).map_err(DataPlaneError::from)
}

fn write_operation_id(pointer: u32, operation: DataPlaneOperationId) -> Result<(), DataPlaneError> {
    write_output(pointer, &operation.get().to_be_bytes())
}

fn submit_operation(
    handle: u64,
    output: u32,
    submit: impl FnOnce(&WasiInstance) -> Result<DataPlaneOperationId, DataPlaneError>,
) -> i32 {
    data_plane_call(handle, |instance| {
        validate_fixed_output(output, OPERATION_ID_LEN)?;
        let operation = submit(instance)?;
        if let Err(error) = write_operation_id(output, operation) {
            instance.data_plane_session().free_operation(operation);
            return Err(error);
        }
        Ok(0)
    })
}

fn take_result<T>(
    session: &WasiDataPlaneSession,
    operation: DataPlaneOperationId,
    expected: DataPlaneOperationKind,
    take: impl FnOnce(&DataPlaneOperationResult) -> Result<T, DataPlaneError>,
) -> Result<T, DataPlaneError> {
    let actual = session.operation_kind(operation)?;
    if actual != expected {
        return Err(invalid_input(format!(
            "operation kind mismatch: expected {expected:?}, got {actual:?}"
        )));
    }

    let mut extraction_error = None;
    let result = session.take_result_with(operation, |outcome| {
        Some(match outcome {
            Ok(result) => match take(result) {
                Ok(value) => Ok(value),
                Err(error) => {
                    extraction_error = Some(error);
                    return None;
                }
            },
            Err(kind) => Err(error(
                *kind,
                format!("data-plane operation failed with {kind:?}"),
            )),
        })
    })?;
    if let Some(error) = extraction_error {
        return Err(error);
    }
    result.ok_or_else(|| invalid_input("data-plane result could not be consumed"))?
}

fn require_ipv4(address: SocketAddr) -> Result<SocketAddr, DataPlaneError> {
    address.is_ipv4().then_some(address).ok_or_else(|| {
        error(
            DataPlaneErrorKind::AddressFamilyUnsupported,
            "data-plane ABI v2 supports IPv4 only",
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_abi_version() -> u32 {
    DATA_PLANE_ABI_VERSION
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_capabilities() -> u64 {
    DATA_PLANE_CAPABILITY | DATA_PLANE_TCP_CAPABILITY | DATA_PLANE_UDP_CAPABILITY
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_connect_submit(
    handle: u64,
    peer_address: u32,
    timeout_ms: u64,
    output_operation: u32,
) -> i32 {
    let peer_address = match read_ipv4_address(peer_address) {
        Ok(address) => address,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    submit_operation(handle, output_operation, |instance| {
        instance.submit_data_plane(|session| {
            session.submit_tcp_connect(peer_address, timeout(timeout_ms))
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_bind_submit(
    handle: u64,
    local_port: u32,
    timeout_ms: u64,
    output_operation: u32,
) -> i32 {
    let local_port = match validate_local_port(local_port) {
        Ok(port) => port,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    submit_operation(handle, output_operation, |instance| {
        instance
            .submit_data_plane(|session| session.submit_tcp_bind(local_port, timeout(timeout_ms)))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_accept_submit(
    handle: u64,
    listener: u64,
    timeout_ms: u64,
    output_operation: u32,
) -> i32 {
    let listener = match resource_id(listener) {
        Ok(listener) => listener,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    submit_operation(handle, output_operation, |instance| {
        instance
            .submit_data_plane(|session| session.submit_tcp_accept(listener, timeout(timeout_ms)))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_read_submit(
    handle: u64,
    stream: u64,
    max_len: u32,
    timeout_ms: u64,
    output_operation: u32,
) -> i32 {
    let stream = match resource_id(stream) {
        Ok(stream) => stream,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    submit_operation(handle, output_operation, |instance| {
        instance.submit_data_plane(|session| {
            session.submit_tcp_read(stream, max_len as usize, timeout(timeout_ms))
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_write_submit(
    handle: u64,
    stream: u64,
    data_pointer: u32,
    data_length: u32,
    timeout_ms: u64,
    output_operation: u32,
) -> i32 {
    let stream = match resource_id(stream) {
        Ok(stream) => stream,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    let data = match read_input(data_pointer, data_length, MAX_WRITE_LEN) {
        Ok(data) => data,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    submit_operation(handle, output_operation, |instance| {
        instance.submit_data_plane(|session| {
            session.submit_tcp_write(stream, data, timeout(timeout_ms))
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_udp_bind_submit(
    handle: u64,
    local_port: u32,
    timeout_ms: u64,
    output_operation: u32,
) -> i32 {
    let local_port = match validate_local_port(local_port) {
        Ok(port) => port,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    submit_operation(handle, output_operation, |instance| {
        instance
            .submit_data_plane(|session| session.submit_udp_bind(local_port, timeout(timeout_ms)))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_udp_receive_submit(
    handle: u64,
    socket: u64,
    max_len: u32,
    timeout_ms: u64,
    output_operation: u32,
) -> i32 {
    let socket = match resource_id(socket) {
        Ok(socket) => socket,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    submit_operation(handle, output_operation, |instance| {
        instance.submit_data_plane(|session| {
            session.submit_udp_receive(socket, max_len as usize, timeout(timeout_ms))
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_udp_send_submit(
    handle: u64,
    socket: u64,
    peer_address: u32,
    data_pointer: u32,
    data_length: u32,
    timeout_ms: u64,
    output_operation: u32,
) -> i32 {
    let socket = match resource_id(socket) {
        Ok(socket) => socket,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    let peer_address = match read_ipv4_address(peer_address) {
        Ok(address) => address,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    let data = match read_input(data_pointer, data_length, MAX_WRITE_LEN) {
        Ok(data) => data,
        Err(error) => {
            set_instance_error(handle, error.message());
            return error_status(error.kind());
        }
    };
    submit_operation(handle, output_operation, |instance| {
        instance.submit_data_plane(|session| {
            session.submit_udp_send(socket, peer_address, data, timeout(timeout_ms))
        })
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_operation_cancel(handle: u64, operation: u64) -> i32 {
    data_plane_call(handle, |instance| {
        instance
            .data_plane_session()
            .cancel_operation(operation_id(operation)?);
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_operation_free(handle: u64, operation: u64) -> i32 {
    data_plane_call(handle, |instance| {
        instance
            .data_plane_session()
            .free_operation(operation_id(operation)?);
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_resource_close(handle: u64, resource: u64) -> i32 {
    data_plane_call(handle, |instance| {
        instance
            .data_plane_session()
            .close_resource(resource_id(resource)?);
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_completion_drain(
    handle: u64,
    output: u32,
    capacity: u32,
) -> i32 {
    data_plane_call(handle, |instance| {
        let capacity = usize::try_from(capacity).expect("u32 fits usize on wasm32");
        let required = capacity
            .checked_mul(COMPLETION_LEN)
            .ok_or_else(|| invalid_input("completion output size overflow"))?;
        validate_output(output, required, required)?;
        let completions = instance.data_plane_session().drain_completions(capacity);
        let mut encoded = Vec::with_capacity(completions.len() * COMPLETION_LEN);
        for completion in completions {
            encoded.extend_from_slice(&encode_completion(completion));
        }
        write_output(output, &encoded)?;
        i32::try_from(encoded.len() / COMPLETION_LEN)
            .map_err(|_| invalid_input("completion count exceeds i32"))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_result_size(handle: u64, operation: u64) -> i32 {
    data_plane_call(handle, |instance| {
        let size = instance
            .data_plane_session()
            .result_payload_bytes(operation_id(operation)?)?;
        i32::try_from(size).map_err(|_| invalid_input("data-plane result size exceeds i32"))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_connect_result_take(
    handle: u64,
    operation: u64,
    output: u32,
) -> i32 {
    data_plane_call(handle, |instance| {
        validate_fixed_output(output, TCP_CONNECT_RESULT_LEN)?;
        let session = instance.data_plane_session();
        let wire = take_result(
            &session,
            operation_id(operation)?,
            DataPlaneOperationKind::TcpConnect,
            |result| match result {
                DataPlaneOperationResult::TcpConnected {
                    stream,
                    local_addr,
                    peer_addr,
                } => Ok(encode_stream_addresses(
                    stream.get(),
                    require_ipv4(*local_addr)?,
                    require_ipv4(*peer_addr)?,
                )),
                _ => Err(invalid_input("TCP connect result variant mismatch")),
            },
        )?;
        write_output(output, &wire)?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_bind_result_take(
    handle: u64,
    operation: u64,
    output: u32,
) -> i32 {
    data_plane_call(handle, |instance| {
        validate_fixed_output(output, TCP_BIND_RESULT_LEN)?;
        let session = instance.data_plane_session();
        let wire = take_result(
            &session,
            operation_id(operation)?,
            DataPlaneOperationKind::TcpBind,
            |result| match result {
                DataPlaneOperationResult::TcpBound {
                    listener,
                    local_addr,
                } => Ok(encode_resource_and_address(
                    listener.get(),
                    require_ipv4(*local_addr)?,
                )),
                _ => Err(invalid_input("TCP bind result variant mismatch")),
            },
        )?;
        write_output(output, &wire)?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_accept_result_take(
    handle: u64,
    operation: u64,
    output: u32,
) -> i32 {
    data_plane_call(handle, |instance| {
        validate_fixed_output(output, TCP_ACCEPT_RESULT_LEN)?;
        let session = instance.data_plane_session();
        let wire = take_result(
            &session,
            operation_id(operation)?,
            DataPlaneOperationKind::TcpAccept,
            |result| match result {
                DataPlaneOperationResult::TcpAccepted {
                    stream,
                    local_addr,
                    peer_addr,
                } => Ok(encode_stream_addresses(
                    stream.get(),
                    require_ipv4(*local_addr)?,
                    require_ipv4(*peer_addr)?,
                )),
                _ => Err(invalid_input("TCP accept result variant mismatch")),
            },
        )?;
        write_output(output, &wire)?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_read_result_take(
    handle: u64,
    operation: u64,
    data_output: u32,
    data_capacity: u32,
    metadata_output: u32,
) -> i32 {
    data_plane_call(handle, |instance| {
        let session = instance.data_plane_session();
        let operation = operation_id(operation)?;
        let required = session.result_payload_bytes(operation)?;
        validate_output(data_output, data_capacity as usize, required)?;
        validate_fixed_output(metadata_output, TCP_READ_METADATA_LEN)?;
        take_result(
            &session,
            operation,
            DataPlaneOperationKind::TcpRead,
            |result| match result {
                DataPlaneOperationResult::TcpRead { data, eof } => {
                    write_output(data_output, data)?;
                    write_output(metadata_output, &encode_tcp_read_metadata(*eof))?;
                    i32::try_from(data.len())
                        .map_err(|_| invalid_input("TCP read result exceeds i32"))
                }
                _ => Err(invalid_input("TCP read result variant mismatch")),
            },
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_tcp_write_result_take(handle: u64, operation: u64) -> i32 {
    data_plane_call(handle, |instance| {
        let session = instance.data_plane_session();
        let len = take_result(
            &session,
            operation_id(operation)?,
            DataPlaneOperationKind::TcpWrite,
            |result| match result {
                DataPlaneOperationResult::TcpWritten { len } => Ok(*len),
                _ => Err(invalid_input("TCP write result variant mismatch")),
            },
        )?;
        i32::try_from(len).map_err(|_| invalid_input("TCP write result exceeds i32"))
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_udp_bind_result_take(
    handle: u64,
    operation: u64,
    output: u32,
) -> i32 {
    data_plane_call(handle, |instance| {
        validate_fixed_output(output, UDP_BIND_RESULT_LEN)?;
        let session = instance.data_plane_session();
        let wire = take_result(
            &session,
            operation_id(operation)?,
            DataPlaneOperationKind::UdpBind,
            |result| match result {
                DataPlaneOperationResult::UdpBound { socket, local_addr } => Ok(
                    encode_resource_and_address(socket.get(), require_ipv4(*local_addr)?),
                ),
                _ => Err(invalid_input("UDP bind result variant mismatch")),
            },
        )?;
        write_output(output, &wire)?;
        Ok(0)
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_udp_receive_result_take(
    handle: u64,
    operation: u64,
    data_output: u32,
    data_capacity: u32,
    metadata_output: u32,
) -> i32 {
    data_plane_call(handle, |instance| {
        let session = instance.data_plane_session();
        let operation = operation_id(operation)?;
        let required = session.result_payload_bytes(operation)?;
        validate_output(data_output, data_capacity as usize, required)?;
        validate_fixed_output(metadata_output, UDP_RECEIVE_METADATA_LEN)?;
        take_result(
            &session,
            operation,
            DataPlaneOperationKind::UdpReceive,
            |result| match result {
                DataPlaneOperationResult::UdpReceived {
                    data,
                    peer_addr,
                    truncated,
                } => {
                    write_output(data_output, data)?;
                    write_output(
                        metadata_output,
                        &encode_udp_receive_metadata(require_ipv4(*peer_addr)?, *truncated),
                    )?;
                    i32::try_from(data.len())
                        .map_err(|_| invalid_input("UDP receive result exceeds i32"))
                }
                _ => Err(invalid_input("UDP receive result variant mismatch")),
            },
        )
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_data_plane_udp_send_result_take(handle: u64, operation: u64) -> i32 {
    data_plane_call(handle, |instance| {
        let session = instance.data_plane_session();
        let len = take_result(
            &session,
            operation_id(operation)?,
            DataPlaneOperationKind::UdpSend,
            |result| match result {
                DataPlaneOperationResult::UdpSent { len } => Ok(*len),
                _ => Err(invalid_input("UDP send result variant mismatch")),
            },
        )?;
        i32::try_from(len).map_err(|_| invalid_input("UDP send result exceeds i32"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infinite_timeout_sentinel_is_distinct_from_zero() {
        assert_eq!(timeout(u64::MAX), None);
        assert_eq!(timeout(0), Some(Duration::ZERO));
    }
}
