//! Protobuf RPC guest exports bound to one WASI core instance.

use crate::{
    rpc::operation::{RpcAccessError, RpcOperationId, RpcSubmitError},
    wasi::abi::{RPC_ABI_VERSION, RPC_STATUS_PENDING},
};

use super::{
    ASYNC_ERROR, BUSY, INVALID_INPUT, MAX_RPC_MESSAGE_LEN, WasiInstance, read_guest_buffer,
    set_instance_error, with_abi_state, with_abi_state_mut, with_instance,
};

const OPERATION_ID_LEN: usize = 8;

impl WasiInstance {
    fn submit_rpc(&self, encoded_request: &[u8]) -> Result<RpcOperationId, RpcSubmitError> {
        let execution = self.execution.lock().unwrap();
        let _domain = crate::foundation::time::enter_domain(self.domain);
        let _runtime = execution.runtime.enter();
        self.rpc_operations.submit_encoded(encoded_request)
    }
}

fn operation_id(raw: u64) -> anyhow::Result<RpcOperationId> {
    RpcOperationId::from_raw(raw).ok_or_else(|| anyhow::anyhow!("invalid RPC operation ID"))
}

fn validate_output(pointer: u32, capacity: usize) -> anyhow::Result<()> {
    if pointer == 0 {
        anyhow::bail!("guest RPC output buffer pointer is zero");
    }
    with_abi_state(|state| {
        let buffer = state
            .buffers
            .get(&pointer)
            .ok_or_else(|| anyhow::anyhow!("unknown guest buffer: {pointer}"))?;
        if capacity > buffer.len() {
            anyhow::bail!(
                "guest RPC output capacity {capacity} exceeds allocation {}",
                buffer.len()
            );
        }
        Ok(())
    })
}

fn write_output(pointer: u32, bytes: &[u8]) -> anyhow::Result<()> {
    with_abi_state_mut(|state| {
        let buffer = state
            .buffers
            .get_mut(&pointer)
            .ok_or_else(|| anyhow::anyhow!("unknown guest buffer: {pointer}"))?;
        if bytes.len() > buffer.len() {
            anyhow::bail!(
                "RPC response requires {} bytes, allocation has {}",
                bytes.len(),
                buffer.len()
            );
        }
        buffer[..bytes.len()].copy_from_slice(bytes);
        Ok(())
    })
}

fn submit_status(error: &RpcSubmitError) -> i32 {
    match error {
        RpcSubmitError::AtCapacity | RpcSubmitError::IdExhausted => BUSY,
        RpcSubmitError::ExecutorUnavailable => ASYNC_ERROR,
        RpcSubmitError::Decode(_) | RpcSubmitError::MissingMethod => INVALID_INPUT,
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn easytier_rpc_abi_version() -> u32 {
    RPC_ABI_VERSION
}

/// Submits one serialized `common.DirectRpcRequest`.
///
/// The full protobuf method name is mandatory. On success, writes the opaque
/// operation ID as one big-endian `u64` to `output_operation`.
#[unsafe(no_mangle)]
pub extern "C" fn easytier_rpc_request_submit(
    handle: u64,
    request_pointer: u32,
    request_length: u32,
    output_operation: u32,
) -> i32 {
    with_instance(handle, |instance| {
        if let Err(error) = validate_output(output_operation, OPERATION_ID_LEN) {
            set_instance_error(handle, error);
            return Ok(INVALID_INPUT);
        }
        let request = match read_guest_buffer(request_pointer, request_length, MAX_RPC_MESSAGE_LEN)
        {
            Ok(request) => request,
            Err(error) => {
                set_instance_error(handle, error);
                return Ok(INVALID_INPUT);
            }
        };
        let operation = match instance.submit_rpc(&request) {
            Ok(operation) => operation,
            Err(error) => {
                let status = submit_status(&error);
                set_instance_error(handle, error);
                return Ok(status);
            }
        };
        if let Err(error) = write_output(output_operation, &operation.get().to_be_bytes()) {
            instance.rpc_operations.free(operation);
            set_instance_error(handle, error);
            return Ok(INVALID_INPUT);
        }
        Ok(0)
    })
}

/// Probes or consumes one serialized `common.RpcResponse`.
///
/// Returns [`RPC_STATUS_PENDING`] while the operation is running. Passing
/// `(output, capacity) == (0, 0)` returns the required byte length without
/// consuming the response. If `capacity` is too small, the required length is
/// returned and the response remains available. Otherwise the response is
/// copied, consumed, and its byte length is returned.
#[unsafe(no_mangle)]
pub extern "C" fn easytier_rpc_response_take(
    handle: u64,
    operation: u64,
    output: u32,
    capacity: u32,
) -> i32 {
    with_instance(handle, |instance| {
        let operation = match operation_id(operation) {
            Ok(operation) => operation,
            Err(error) => {
                set_instance_error(handle, error);
                return Ok(INVALID_INPUT);
            }
        };
        let required = match instance.rpc_operations.response_len(operation) {
            Ok(required) => required,
            Err(RpcAccessError::Pending) => return Ok(RPC_STATUS_PENDING),
            Err(error) => {
                set_instance_error(handle, error);
                return Ok(INVALID_INPUT);
            }
        };
        let required_i32 = match i32::try_from(required) {
            Ok(required) => required,
            Err(_) => {
                set_instance_error(handle, "RPC response length exceeds i32");
                return Ok(ASYNC_ERROR);
            }
        };
        if output == 0 && capacity == 0 {
            return Ok(required_i32);
        }
        let capacity = usize::try_from(capacity).expect("u32 fits usize on wasm32");
        if let Err(error) = validate_output(output, capacity) {
            set_instance_error(handle, error);
            return Ok(INVALID_INPUT);
        }
        if capacity < required {
            return Ok(required_i32);
        }

        let mut write_error = None;
        let taken = instance
            .rpc_operations
            .take_response_with(operation, |response| {
                if let Err(error) = write_output(output, response) {
                    write_error = Some(error);
                    return None;
                }
                Some(())
            });
        if let Some(error) = write_error {
            set_instance_error(handle, error);
            return Ok(INVALID_INPUT);
        }
        match taken {
            Ok(Some(())) => Ok(required_i32),
            Ok(None) => {
                set_instance_error(handle, "RPC response could not be consumed");
                Ok(ASYNC_ERROR)
            }
            Err(RpcAccessError::Pending) => Ok(RPC_STATUS_PENDING),
            Err(error) => {
                set_instance_error(handle, error);
                Ok(INVALID_INPUT)
            }
        }
    })
}

/// Cancels and discards a pending operation, or discards an untaken response.
#[unsafe(no_mangle)]
pub extern "C" fn easytier_rpc_operation_free(handle: u64, operation: u64) -> i32 {
    with_instance(handle, |instance| {
        let operation = match operation_id(operation) {
            Ok(operation) => operation,
            Err(error) => {
                set_instance_error(handle, error);
                return Ok(INVALID_INPUT);
            }
        };
        if !instance.rpc_operations.free(operation) {
            set_instance_error(handle, "unknown RPC operation");
            return Ok(INVALID_INPUT);
        }
        Ok(0)
    })
}
