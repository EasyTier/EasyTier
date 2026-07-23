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

/// Version of the JSON document accepted by `easytier_instance_create`.
pub const CORE_INSTANCE_CONFIG_VERSION: u32 = 14;

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
