//! Stable ABI contract between the EasyTier WASI guest and its runtime.
//!
//! A runtime must provide every function in the `easytier_host` import module
//! and call the guest lifecycle exports listed in [`GUEST_EXPORTS`]. The raw
//! import declarations live in the target-only `imports` Module.
//! Rust visibility does not define this cross-language contract; the imported
//! and exported WebAssembly symbol names and signatures do.
//!
//! Every `u32` pointer is an offset in wasm32 guest linear memory, never a
//! native host pointer. The runtime must copy input bytes before an import
//! returns and may write result bytes only during the matching `take_*` call.
//! An operation ID belongs to core until a terminal `take_*` call consumes it
//! or the runtime receives the `cancel_operation` import.

/// WebAssembly import module a WASI runtime must implement.
pub const HOST_IMPORT_MODULE: &str = "easytier_host";

/// AEAD algorithm identifiers accepted by the optional crypto imports.
pub const AEAD_AES_128_GCM: u32 = 1;
pub const AEAD_AES_256_GCM: u32 = 2;
pub const AEAD_CHACHA20_POLY1305: u32 = 3;

/// The Host could not authenticate an AEAD record.
///
/// Unlike other non-zero crypto statuses, this must not fall back to the
/// built-in implementation because an in-place open may have changed bytes.
pub const HOST_CRYPTO_AUTH_FAILED: i32 = -10;

/// Version of the JSON document accepted by `easytier_instance_create`.
pub const CORE_INSTANCE_CONFIG_VERSION: u32 = 14;

/// Version of the public data-plane guest export contract.
pub const DATA_PLANE_ABI_VERSION: u32 = 3;

/// The guest exposes an instance-scoped data-plane operation broker.
pub const DATA_PLANE_CAPABILITY: u64 = 1 << 0;
/// The guest data plane supports TCP streams and listeners.
pub const DATA_PLANE_TCP_CAPABILITY: u64 = 1 << 1;
/// The guest data plane supports UDP sockets.
pub const DATA_PLANE_UDP_CAPABILITY: u64 = 1 << 2;
/// Update the read deadline in `easytier_data_plane_resource_deadline_set`.
pub const DATA_PLANE_DEADLINE_READ: u32 = 1 << 0;
/// Update the write deadline in `easytier_data_plane_resource_deadline_set`.
pub const DATA_PLANE_DEADLINE_WRITE: u32 = 1 << 1;

/// Guest exports a WASI runtime calls to manage a core instance.
///
/// Buffer allocation precedes config, packet, and error-copy calls. Instance
/// creation and lifecycle use the returned instance handle. A runtime drives
/// all asynchronous guest work through `easytier_instance_drive` and host
/// completion notifications.
pub const GUEST_EXPORTS: &[&str] = &[
    // Guest-memory buffers.
    "easytier_buffer_alloc",
    "easytier_buffer_free",
    // Instance lifecycle and external runtime driving.
    "easytier_instance_create",
    "easytier_instance_start",
    "easytier_instance_stop",
    "easytier_instance_drive",
    "easytier_instance_notify_completions",
    "easytier_instance_state",
    "easytier_instance_next_deadline_millis",
    // Raw IP packet ingress and error retrieval.
    "easytier_instance_send_packet",
    "easytier_instance_drop",
    "easytier_instance_error_len",
    "easytier_instance_error_copy",
];

/// Guest exports present when the core is built with the smoltcp data plane.
#[cfg(feature = "proxy-smoltcp-stack")]
pub const DATA_PLANE_GUEST_EXPORTS: &[&str] = &[
    // ABI discovery.
    "easytier_data_plane_abi_version",
    "easytier_data_plane_capabilities",
    // Data-plane operation submission.
    "easytier_data_plane_tcp_connect_submit",
    "easytier_data_plane_tcp_bind_submit",
    "easytier_data_plane_tcp_accept_submit",
    "easytier_data_plane_tcp_read_submit",
    "easytier_data_plane_tcp_write_submit",
    "easytier_data_plane_udp_bind_submit",
    "easytier_data_plane_udp_receive_submit",
    "easytier_data_plane_udp_send_submit",
    "easytier_data_plane_resource_deadline_set",
    // Completion, result, and resource lifecycle.
    "easytier_data_plane_completion_drain",
    "easytier_data_plane_result_size",
    "easytier_data_plane_tcp_connect_result_take",
    "easytier_data_plane_tcp_bind_result_take",
    "easytier_data_plane_tcp_accept_result_take",
    "easytier_data_plane_tcp_read_result_take",
    "easytier_data_plane_tcp_write_result_take",
    "easytier_data_plane_udp_bind_result_take",
    "easytier_data_plane_udp_receive_result_take",
    "easytier_data_plane_udp_send_result_take",
    "easytier_data_plane_operation_cancel",
    "easytier_data_plane_operation_free",
    "easytier_data_plane_resource_close",
];
