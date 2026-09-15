//! Raw `easytier_host` imports, compiled only for the WASI guest.
//!
//! [`crate::wasi::abi`] declares the shared contract metadata; each import
//! below documents its own ownership and completion rules. Concrete adapters
//! call these functions directly.

pub(crate) const HOST_PENDING: i32 = -1;
pub(crate) const HOST_WOULD_BLOCK: i32 = -5;
#[cfg(feature = "wasm-host-tunnel")]
pub(crate) const HOST_TUNNEL_CLOSED: i32 = -10;

#[link(wasm_import_module = "easytier_host")]
unsafe extern "C" {
    /// Emits one best-effort instance event after the host copies both strings.
    ///
    /// The host must not block the guest. A non-zero status drops this event
    /// without affecting core execution.
    pub(crate) fn emit_event(
        handle: u64,
        kind: u32,
        kind_len: u32,
        message: u32,
        message_len: u32,
    ) -> i32;

    /// Encrypts `text_len` bytes in place and writes the AEAD tag immediately
    /// after them.
    ///
    /// The guest reserves the algorithm's tag size in linear memory before
    /// calling. Every non-zero result except
    /// [`crate::wasi::abi::HOST_CRYPTO_AUTH_FAILED`] must leave the buffer
    /// unchanged so the guest can use its built-in implementation.
    #[cfg(feature = "wasi-crypto-offload")]
    pub(crate) fn crypto_aead_seal(
        algorithm: u32,
        key: u32,
        key_len: u32,
        nonce: u32,
        nonce_len: u32,
        aad: u32,
        aad_len: u32,
        buffer: u32,
        text_len: u32,
    ) -> i32;

    /// Authenticates and decrypts `text_len` bytes in place using the AEAD tag
    /// immediately after them.
    ///
    /// Authentication failure may change the buffer and must return
    /// [`crate::wasi::abi::HOST_CRYPTO_AUTH_FAILED`]. Every other non-zero
    /// result must leave the buffer unchanged so the guest can fall back.
    #[cfg(feature = "wasi-crypto-offload")]
    pub(crate) fn crypto_aead_open(
        algorithm: u32,
        key: u32,
        key_len: u32,
        nonce: u32,
        nonce_len: u32,
        aad: u32,
        aad_len: u32,
        buffer: u32,
        text_len: u32,
    ) -> i32;

    /// Starts one TCP read into a host-owned pending operation.
    ///
    /// The host records at most `capacity` bytes for `operation` and must not
    /// write guest memory until [`take_read`] supplies a destination buffer.
    pub(crate) fn start_read(handle: u64, operation: u64, capacity: u32) -> i32;

    /// Copies a completed TCP read into `destination`, returning its byte count.
    ///
    /// Returns [`HOST_PENDING`] while the operation is incomplete. A completed
    /// read, including EOF with a zero length, consumes `operation`.
    pub(crate) fn take_read(operation: u64, destination: u32, capacity: u32) -> i32;

    /// Starts one TCP write after copying `source[..length]` from guest memory.
    pub(crate) fn start_write(handle: u64, operation: u64, source: u32, length: u32) -> i32;

    /// Reports completion of a TCP write and consumes `operation` on success or error.
    pub(crate) fn take_write(operation: u64) -> i32;

    /// Starts receipt of one UDP datagram of at most `capacity` bytes.
    pub(crate) fn start_udp_recv(handle: u64, operation: u64, capacity: u32) -> i32;

    /// Copies one completed UDP datagram and its metadata into guest memory.
    ///
    /// A non-pending result consumes `operation`; `metadata` has exactly
    /// `metadata_len` bytes allocated by core for the socket wire format.
    pub(crate) fn take_udp_recv(
        operation: u64,
        destination: u32,
        capacity: u32,
        metadata: u32,
        metadata_len: u32,
    ) -> i32;

    /// Attempts to enqueue one complete UDP datagram after copying its bytes and metadata.
    ///
    /// [`HOST_WOULD_BLOCK`] means the datagram was not accepted and has no
    /// side effects. Any other success means the host owns a complete copy.
    pub(crate) fn try_udp_send(
        handle: u64,
        source: u32,
        length: u32,
        metadata: u32,
        metadata_len: u32,
    ) -> i32;

    /// Starts waiting until another UDP send attempt may succeed.
    pub(crate) fn start_udp_send_ready(handle: u64, operation: u64) -> i32;

    /// Reports UDP write readiness; readiness never sends a datagram itself.
    pub(crate) fn take_udp_send_ready(operation: u64) -> i32;

    /// Starts a TCP connection using an encoded `TcpConnectOptions` document.
    /// Requested socket protection must complete before the host connects.
    pub(crate) fn start_tcp_connect(operation: u64, options: u32, options_len: u32) -> i32;

    /// Copies the completed TCP connection handle and addresses into `result`.
    pub(crate) fn take_tcp_connect(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts a UDP bind using an encoded `UdpBindOptions` document. Requested
    /// socket protection must complete before bind or datagram I/O.
    pub(crate) fn start_udp_bind(operation: u64, options: u32, options_len: u32) -> i32;

    /// Copies the completed UDP socket handle and local address into `result`.
    pub(crate) fn take_udp_bind(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts a TCP listener bind using an encoded `TcpListenOptions` document.
    /// Requested socket protection must complete before bind/listen.
    pub(crate) fn start_tcp_bind(operation: u64, options: u32, options_len: u32) -> i32;

    /// Copies the completed listener handle and local address into `result`.
    pub(crate) fn take_tcp_bind(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts accepting one TCP stream from a listener handle. A protected
    /// listener's accepted child must be protected before it is exposed.
    pub(crate) fn start_tcp_accept(handle: u64, operation: u64) -> i32;

    /// Copies the accepted TCP stream handle and addresses into `result`.
    pub(crate) fn take_tcp_accept(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts an address-record DNS lookup for an encoded [`crate::host::dns::DnsQuery`].
    /// When VPN bypass is active, the host must protect every underlying DNS
    /// socket before sending a query or opening a DNS TCP connection.
    pub(crate) fn start_dns_resolve(operation: u64, query: u32, query_len: u32) -> i32;

    /// Probes or copies the encoded DNS address result for `operation`.
    ///
    /// A zero-capacity call probes the required result length without consuming
    /// it; a subsequent call with enough capacity copies and consumes it.
    pub(crate) fn take_dns_resolve(operation: u64, result: u32, result_capacity: u32) -> i32;

    /// Starts a TXT-record DNS lookup for an encoded query.
    pub(crate) fn start_dns_txt(operation: u64, query: u32, query_len: u32) -> i32;

    /// Probes or copies the encoded DNS TXT result using the DNS result protocol.
    pub(crate) fn take_dns_txt(operation: u64, result: u32, result_capacity: u32) -> i32;

    /// Starts an SRV-record DNS lookup for an encoded query.
    pub(crate) fn start_dns_srv(operation: u64, query: u32, query_len: u32) -> i32;

    /// Probes or copies the encoded DNS SRV result using the DNS result protocol.
    pub(crate) fn take_dns_srv(operation: u64, result: u32, result_capacity: u32) -> i32;

    /// Starts finding the local address and source context needed to reach `remote_addr`.
    /// When VPN bypass is active, the host must protect the underlying route-
    /// probe socket before connecting or sending through it.
    pub(crate) fn start_local_addr_for_remote(
        operation: u64,
        remote_addr: u32,
        remote_addr_len: u32,
        context: u32,
        context_len: u32,
    ) -> i32;

    /// Copies the resolved local socket address into the fixed-size `result` buffer.
    pub(crate) fn take_local_addr_for_remote(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts one process-level WebClient management call after copying its request.
    #[cfg(feature = "management")]
    pub(crate) fn start_management_call(operation: u64, request: u32, request_len: u32) -> i32;

    /// Probes or copies the process-level management response for `operation`.
    #[cfg(feature = "management")]
    pub(crate) fn take_management_call(operation: u64, result: u32, result_capacity: u32) -> i32;

    /// Attempts to deliver one raw IP packet to a host packet sink.
    ///
    /// On success the host owns a complete copy. [`HOST_WOULD_BLOCK`] leaves
    /// the packet unaccepted and requires core to wait for write readiness.
    pub(crate) fn try_packet_write(handle: u64, packet: u32, packet_len: u32) -> i32;

    /// Starts waiting until another packet-sink admission attempt may succeed.
    pub(crate) fn start_packet_write_ready(handle: u64, operation: u64) -> i32;

    /// Reports packet-sink write readiness; it never accepts a packet itself.
    pub(crate) fn take_packet_write_ready(operation: u64) -> i32;

    #[cfg(feature = "wasm-host-tunnel")]
    /// Starts receiving one complete host tunnel payload.
    pub(crate) fn start_tunnel_receive(handle: u64, operation: u64, capacity: u32) -> i32;

    #[cfg(feature = "wasm-host-tunnel")]
    /// Probes or copies one payload, or returns the closed sentinel.
    ///
    /// A null destination with zero capacity returns the payload length without
    /// consuming it. A second call copies and consumes the payload.
    pub(crate) fn take_tunnel_receive(operation: u64, destination: u32, capacity: u32) -> i32;

    #[cfg(feature = "wasm-host-tunnel")]
    /// Starts sending one complete host tunnel payload.
    pub(crate) fn start_tunnel_send(handle: u64, operation: u64, source: u32, length: u32) -> i32;

    #[cfg(feature = "wasm-host-tunnel")]
    /// Reports completion of one host tunnel send.
    pub(crate) fn take_tunnel_send(operation: u64) -> i32;

    #[cfg(feature = "wasm-host-tunnel-outbound")]
    /// Starts opening one outbound host tunnel for the requested URL.
    pub(crate) fn start_tunnel_connect(operation: u64, url: u32, url_len: u32) -> i32;

    #[cfg(feature = "wasm-host-tunnel-outbound")]
    /// Returns the connected tunnel handle, or a negative host status.
    pub(crate) fn take_tunnel_connect(operation: u64) -> i64;

    /// Cancels a pending or completed-but-unread operation and releases host state.
    ///
    /// Cancellation must be idempotent when the operation is already absent.
    pub(crate) fn cancel_operation(operation: u64) -> i32;

    /// Closes a host socket or listener handle. Closing an already-closed handle is valid.
    pub(crate) fn close(handle: u64) -> i32;
}
