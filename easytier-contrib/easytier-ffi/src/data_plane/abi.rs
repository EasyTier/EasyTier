use std::{
    ffi::{c_char, c_int, c_uchar},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    ptr,
};

use easytier_core::gateway::DataPlaneErrorKind;

use super::session::{self, NativeDataPlaneError, NativeDataPlaneResult};
use crate::{
    error::set_error_msg,
    strings::c_str_to_string,
    types::{DataPlaneCompletion, DataPlaneSocketAddr},
};

pub const DATA_PLANE_DEADLINE_READ: u32 = 1 << 0;
pub const DATA_PLANE_DEADLINE_WRITE: u32 = 1 << 1;

fn failure(error: NativeDataPlaneError) -> c_int {
    set_error_msg(&error.message);
    -(error.kind as c_int)
}

fn status(result: NativeDataPlaneResult<()>) -> c_int {
    match result {
        Ok(()) => 0,
        Err(error) => failure(error),
    }
}

fn invalid(message: impl Into<String>) -> NativeDataPlaneError {
    NativeDataPlaneError {
        kind: DataPlaneErrorKind::Io,
        message: message.into(),
    }
}

fn socket_addr(address: DataPlaneSocketAddr) -> NativeDataPlaneResult<SocketAddr> {
    let ip = match address.family {
        4 => IpAddr::V4(Ipv4Addr::new(
            address.address[0],
            address.address[1],
            address.address[2],
            address.address[3],
        )),
        6 => {
            return Err(NativeDataPlaneError {
                kind: DataPlaneErrorKind::AddressFamilyUnsupported,
                message: "IPv6 is not supported by data-plane ABI v3".to_string(),
            });
        }
        family => {
            return Err(NativeDataPlaneError {
                kind: DataPlaneErrorKind::AddressFamilyUnsupported,
                message: format!("unsupported address family {family}"),
            });
        }
    };
    Ok(SocketAddr::new(ip, address.port))
}

fn ffi_socket_addr(address: SocketAddr) -> DataPlaneSocketAddr {
    match address.ip() {
        IpAddr::V4(ip) => {
            let mut bytes = [0; 16];
            bytes[..4].copy_from_slice(&ip.octets());
            DataPlaneSocketAddr {
                family: 4,
                port: address.port(),
                address: bytes,
            }
        }
        IpAddr::V6(ip) => DataPlaneSocketAddr {
            family: 6,
            port: address.port(),
            address: ip.octets(),
        },
    }
}

unsafe fn copy_input(ptr: *const c_uchar, len: u32) -> NativeDataPlaneResult<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if ptr.is_null() {
        return Err(invalid("input buffer is null"));
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len as usize) }.to_vec())
}

unsafe fn output_slice<'a>(ptr: *mut c_uchar, len: u32) -> NativeDataPlaneResult<&'a mut [u8]> {
    if len == 0 {
        return Ok(&mut []);
    }
    if ptr.is_null() {
        return Err(invalid("output buffer is null"));
    }
    Ok(unsafe { std::slice::from_raw_parts_mut(ptr, len as usize) })
}

fn write_operation(
    out_operation: *mut u64,
    submit: impl FnOnce() -> NativeDataPlaneResult<u64>,
) -> c_int {
    if out_operation.is_null() {
        return failure(invalid("out_operation is null"));
    }
    match submit() {
        Ok(operation) => {
            unsafe {
                *out_operation = operation;
            }
            0
        }
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// If non-null, `inst_name` must point to a valid NUL-terminated string.
/// `out_session` must be null or point to writable, properly aligned storage
/// for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_session_open(
    inst_name: *const c_char,
    out_session: *mut u64,
) -> c_int {
    if out_session.is_null() {
        return failure(invalid("out_session is null"));
    }
    unsafe {
        *out_session = 0;
    }
    let inst_name = match unsafe { c_str_to_string(inst_name, "inst_name") } {
        Ok(inst_name) => inst_name,
        Err(error) => return failure(invalid(error)),
    };
    match session::open(&inst_name) {
        Ok(handle) => {
            unsafe {
                *out_session = handle;
            }
            0
        }
        Err(error) => failure(error),
    }
}

#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_session_close(session: u64) -> c_int {
    status(super::session::close(session))
}

/// # Safety
///
/// `out_operation` must be null or point to writable, properly aligned
/// storage for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_connect_submit(
    session: u64,
    peer_addr: DataPlaneSocketAddr,
    timeout_ms: u64,
    out_operation: *mut u64,
) -> c_int {
    let peer_addr = match socket_addr(peer_addr) {
        Ok(address) => address,
        Err(error) => return failure(error),
    };
    write_operation(out_operation, || {
        super::session::submit_tcp_connect(session, peer_addr, timeout_ms)
    })
}

/// # Safety
///
/// `out_operation` must be null or point to writable, properly aligned
/// storage for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_bind_submit(
    session: u64,
    local_port: u16,
    timeout_ms: u64,
    out_operation: *mut u64,
) -> c_int {
    write_operation(out_operation, || {
        super::session::submit_tcp_bind(session, local_port, timeout_ms)
    })
}

/// # Safety
///
/// `out_operation` must be null or point to writable, properly aligned
/// storage for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_accept_submit(
    session: u64,
    listener: u64,
    timeout_ms: u64,
    out_operation: *mut u64,
) -> c_int {
    write_operation(out_operation, || {
        super::session::submit_tcp_accept(session, listener, timeout_ms)
    })
}

/// # Safety
///
/// `out_operation` must be null or point to writable, properly aligned
/// storage for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_read_submit(
    session: u64,
    stream: u64,
    max_len: u32,
    out_operation: *mut u64,
) -> c_int {
    write_operation(out_operation, || {
        super::session::submit_tcp_read(session, stream, max_len)
    })
}

/// # Safety
///
/// When `len` is nonzero, `data` must point to `len` readable bytes.
/// `out_operation` must be null or point to writable, properly aligned
/// storage for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_write_submit(
    session: u64,
    stream: u64,
    data: *const c_uchar,
    len: u32,
    out_operation: *mut u64,
) -> c_int {
    let data = match unsafe { copy_input(data, len) } {
        Ok(data) => data,
        Err(error) => return failure(error),
    };
    write_operation(out_operation, || {
        super::session::submit_tcp_write(session, stream, data)
    })
}

/// # Safety
///
/// `out_operation` must be null or point to writable, properly aligned
/// storage for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_bind_submit(
    session: u64,
    local_port: u16,
    timeout_ms: u64,
    out_operation: *mut u64,
) -> c_int {
    write_operation(out_operation, || {
        super::session::submit_udp_bind(session, local_port, timeout_ms)
    })
}

/// # Safety
///
/// `out_operation` must be null or point to writable, properly aligned
/// storage for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_receive_submit(
    session: u64,
    socket: u64,
    max_len: u32,
    out_operation: *mut u64,
) -> c_int {
    write_operation(out_operation, || {
        super::session::submit_udp_receive(session, socket, max_len)
    })
}

/// # Safety
///
/// When `len` is nonzero, `data` must point to `len` readable bytes.
/// `out_operation` must be null or point to writable, properly aligned
/// storage for one `u64`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_send_submit(
    session: u64,
    socket: u64,
    peer_addr: DataPlaneSocketAddr,
    data: *const c_uchar,
    len: u32,
    out_operation: *mut u64,
) -> c_int {
    let peer_addr = match socket_addr(peer_addr) {
        Ok(address) => address,
        Err(error) => return failure(error),
    };
    let data = match unsafe { copy_input(data, len) } {
        Ok(data) => data,
        Err(error) => return failure(error),
    };
    write_operation(out_operation, || {
        super::session::submit_udp_send(session, socket, peer_addr, data)
    })
}

#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_resource_deadline_set(
    session: u64,
    resource: u64,
    direction: u32,
    timeout_ms: u64,
) -> c_int {
    let read = direction & DATA_PLANE_DEADLINE_READ != 0;
    let write = direction & DATA_PLANE_DEADLINE_WRITE != 0;
    if direction == 0 || direction & !(DATA_PLANE_DEADLINE_READ | DATA_PLANE_DEADLINE_WRITE) != 0 {
        return failure(invalid(format!("invalid deadline direction {direction}")));
    }
    status(super::session::set_resource_deadline(
        session, resource, read, write, timeout_ms,
    ))
}

#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_operation_cancel(session: u64, operation: u64) -> c_int {
    status(super::session::cancel_operation(session, operation))
}

#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_operation_free(session: u64, operation: u64) -> c_int {
    status(super::session::free_operation(session, operation))
}

#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_resource_close(session: u64, resource: u64) -> c_int {
    status(super::session::close_resource(session, resource))
}

#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub extern "C" fn data_plane_completion_wait(session: u64, timeout_ms: u64) -> c_int {
    match super::session::completion_wait(session, timeout_ms) {
        Ok(true) => 1,
        Ok(false) => 0,
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// When `capacity` is nonzero, `completions` must point to writable, properly
/// aligned storage for `capacity` consecutive [`DataPlaneCompletion`] values.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_completion_drain(
    session: u64,
    completions: *mut DataPlaneCompletion,
    capacity: u32,
) -> c_int {
    if capacity != 0 && completions.is_null() {
        return failure(invalid("completions is null"));
    }
    let drained = match super::session::drain_completions(session, capacity as usize) {
        Ok(drained) => drained,
        Err(error) => return failure(error),
    };
    for (index, completion) in drained.iter().enumerate() {
        unsafe {
            ptr::write(
                completions.add(index),
                DataPlaneCompletion {
                    operation_id: completion.operation_id.get(),
                    operation_kind: completion.kind as u16,
                    status: completion.status.code(),
                },
            );
        }
    }
    drained.len() as c_int
}

/// # Safety
///
/// `out_size` must be null or point to writable, properly aligned storage for
/// one `u32`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_result_size(
    session: u64,
    operation: u64,
    out_size: *mut u32,
) -> c_int {
    if out_size.is_null() {
        return failure(invalid("out_size is null"));
    }
    match super::session::result_size(session, operation) {
        Ok(size) => match u32::try_from(size) {
            Ok(size) => {
                unsafe {
                    *out_size = size;
                }
                0
            }
            Err(_) => failure(invalid("data-plane result size exceeds u32")),
        },
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// Each output pointer must be null or point to writable, properly aligned
/// storage for its pointee type. Non-null output locations must not overlap.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_connect_result_take(
    session: u64,
    operation: u64,
    out_stream: *mut u64,
    out_local_addr: *mut DataPlaneSocketAddr,
    out_peer_addr: *mut DataPlaneSocketAddr,
) -> c_int {
    if out_stream.is_null() || out_local_addr.is_null() || out_peer_addr.is_null() {
        return failure(invalid("TCP connect result output pointer is null"));
    }
    match super::session::take_tcp_connect(session, operation) {
        Ok(result) => {
            unsafe {
                *out_stream = result.stream;
                *out_local_addr = ffi_socket_addr(result.local_addr);
                *out_peer_addr = ffi_socket_addr(result.peer_addr);
            }
            0
        }
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// Each output pointer must be null or point to writable, properly aligned
/// storage for its pointee type. Non-null output locations must not overlap.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_bind_result_take(
    session: u64,
    operation: u64,
    out_listener: *mut u64,
    out_local_addr: *mut DataPlaneSocketAddr,
) -> c_int {
    if out_listener.is_null() || out_local_addr.is_null() {
        return failure(invalid("TCP bind result output pointer is null"));
    }
    match super::session::take_tcp_bind(session, operation) {
        Ok(result) => {
            unsafe {
                *out_listener = result.listener;
                *out_local_addr = ffi_socket_addr(result.local_addr);
            }
            0
        }
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// Each output pointer must be null or point to writable, properly aligned
/// storage for its pointee type. Non-null output locations must not overlap.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_accept_result_take(
    session: u64,
    operation: u64,
    out_stream: *mut u64,
    out_local_addr: *mut DataPlaneSocketAddr,
    out_peer_addr: *mut DataPlaneSocketAddr,
) -> c_int {
    if out_stream.is_null() || out_local_addr.is_null() || out_peer_addr.is_null() {
        return failure(invalid("TCP accept result output pointer is null"));
    }
    match super::session::take_tcp_accept(session, operation) {
        Ok(result) => {
            unsafe {
                *out_stream = result.stream;
                *out_local_addr = ffi_socket_addr(result.local_addr);
                *out_peer_addr = ffi_socket_addr(result.peer_addr);
            }
            0
        }
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// When `capacity` is nonzero, `data` must point to `capacity` writable bytes.
/// Each scalar output pointer must be null or point to writable, properly
/// aligned storage for its pointee type. Non-null output ranges must not
/// overlap.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_read_result_take(
    session: u64,
    operation: u64,
    data: *mut c_uchar,
    capacity: u32,
    out_len: *mut u32,
    out_eof: *mut bool,
) -> c_int {
    if out_len.is_null() || out_eof.is_null() {
        return failure(invalid("TCP read result output pointer is null"));
    }
    let data = match unsafe { output_slice(data, capacity) } {
        Ok(data) => data,
        Err(error) => return failure(error),
    };
    match super::session::take_tcp_read(session, operation, data) {
        Ok(result) => {
            unsafe {
                *out_len = result.len as u32;
                *out_eof = result.eof;
            }
            0
        }
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// `out_len` must be null or point to writable, properly aligned storage for
/// one `u32`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_tcp_write_result_take(
    session: u64,
    operation: u64,
    out_len: *mut u32,
) -> c_int {
    if out_len.is_null() {
        return failure(invalid("out_len is null"));
    }
    match super::session::take_tcp_write(session, operation) {
        Ok(len) => match u32::try_from(len) {
            Ok(len) => {
                unsafe {
                    *out_len = len;
                }
                0
            }
            Err(_) => failure(invalid("TCP write result exceeds u32")),
        },
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// Each output pointer must be null or point to writable, properly aligned
/// storage for its pointee type. Non-null output locations must not overlap.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_bind_result_take(
    session: u64,
    operation: u64,
    out_socket: *mut u64,
    out_local_addr: *mut DataPlaneSocketAddr,
) -> c_int {
    if out_socket.is_null() || out_local_addr.is_null() {
        return failure(invalid("UDP bind result output pointer is null"));
    }
    match super::session::take_udp_bind(session, operation) {
        Ok(result) => {
            unsafe {
                *out_socket = result.socket;
                *out_local_addr = ffi_socket_addr(result.local_addr);
            }
            0
        }
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// When `capacity` is nonzero, `data` must point to `capacity` writable bytes.
/// Each scalar output pointer must be null or point to writable, properly
/// aligned storage for its pointee type. Non-null output ranges must not
/// overlap.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_receive_result_take(
    session: u64,
    operation: u64,
    data: *mut c_uchar,
    capacity: u32,
    out_len: *mut u32,
    out_peer_addr: *mut DataPlaneSocketAddr,
    out_truncated: *mut bool,
) -> c_int {
    if out_len.is_null() || out_peer_addr.is_null() || out_truncated.is_null() {
        return failure(invalid("UDP receive result output pointer is null"));
    }
    let data = match unsafe { output_slice(data, capacity) } {
        Ok(data) => data,
        Err(error) => return failure(error),
    };
    match super::session::take_udp_receive(session, operation, data) {
        Ok(result) => {
            unsafe {
                *out_len = result.len as u32;
                *out_peer_addr = ffi_socket_addr(result.peer_addr);
                *out_truncated = result.truncated;
            }
            0
        }
        Err(error) => failure(error),
    }
}

/// # Safety
///
/// `out_len` must be null or point to writable, properly aligned storage for
/// one `u32`.
#[cfg_attr(feature = "c-abi", unsafe(no_mangle))]
pub unsafe extern "C" fn data_plane_udp_send_result_take(
    session: u64,
    operation: u64,
    out_len: *mut u32,
) -> c_int {
    if out_len.is_null() {
        return failure(invalid("out_len is null"));
    }
    match super::session::take_udp_send(session, operation) {
        Ok(len) => match u32::try_from(len) {
            Ok(len) => {
                unsafe {
                    *out_len = len;
                }
                0
            }
            Err(_) => failure(invalid("UDP send result exceeds u32")),
        },
        Err(error) => failure(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_address_round_trip() {
        let address = "127.0.0.1:1234".parse::<SocketAddr>().unwrap();
        assert_eq!(socket_addr(ffi_socket_addr(address)).unwrap(), address);
    }

    #[test]
    fn ipv6_is_rejected_by_v3() {
        let error = socket_addr(ffi_socket_addr(
            "[2001:db8::1]:4321".parse::<SocketAddr>().unwrap(),
        ))
        .unwrap_err();
        assert_eq!(error.kind, DataPlaneErrorKind::AddressFamilyUnsupported);
    }

    #[test]
    fn invalid_address_family_is_stable() {
        let error = socket_addr(DataPlaneSocketAddr {
            family: 9,
            ..Default::default()
        })
        .unwrap_err();
        assert_eq!(error.kind, DataPlaneErrorKind::AddressFamilyUnsupported);
    }

    #[test]
    fn invalid_deadline_direction_is_rejected_before_session_lookup() {
        let invalid = -(DataPlaneErrorKind::Io as c_int);
        assert_eq!(data_plane_resource_deadline_set(u64::MAX, 1, 0, 0), invalid);
        assert_eq!(data_plane_resource_deadline_set(u64::MAX, 1, 4, 0), invalid);
    }

    #[test]
    fn null_operation_output_does_not_submit() {
        let submitted = std::cell::Cell::new(false);

        assert_eq!(
            write_operation(std::ptr::null_mut(), || {
                submitted.set(true);
                Ok(1)
            }),
            -(DataPlaneErrorKind::Io as c_int)
        );
        assert!(!submitted.get());
    }
}
