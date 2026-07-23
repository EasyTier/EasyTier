//! Raw `easytier_host` imports, compiled only for the WASI guest.
//!
//! [`crate::wasi::abi`] declares the shared contract metadata; each import
//! below documents its own ownership and completion rules. Concrete adapters
//! call these functions directly.

pub(crate) const HOST_PENDING: i32 = -1;
pub(crate) const HOST_WOULD_BLOCK: i32 = -5;

#[link(wasm_import_module = "easytier_host")]
unsafe extern "C" {
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
    pub(crate) fn start_tcp_connect(operation: u64, options: u32, options_len: u32) -> i32;

    /// Copies the completed TCP connection handle and addresses into `result`.
    pub(crate) fn take_tcp_connect(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts a UDP bind using an encoded `UdpBindOptions` document.
    pub(crate) fn start_udp_bind(operation: u64, options: u32, options_len: u32) -> i32;

    /// Copies the completed UDP socket handle and local address into `result`.
    pub(crate) fn take_udp_bind(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts a TCP listener bind using an encoded `TcpListenOptions` document.
    pub(crate) fn start_tcp_bind(operation: u64, options: u32, options_len: u32) -> i32;

    /// Copies the completed listener handle and local address into `result`.
    pub(crate) fn take_tcp_bind(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts accepting one TCP stream from a listener handle.
    pub(crate) fn start_tcp_accept(handle: u64, operation: u64) -> i32;

    /// Copies the accepted TCP stream handle and addresses into `result`.
    pub(crate) fn take_tcp_accept(operation: u64, result: u32, result_len: u32) -> i32;

    /// Starts an address-record DNS lookup for an encoded [`crate::host::dns::DnsQuery`].
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
    pub(crate) fn start_local_addr_for_remote(
        operation: u64,
        remote_addr: u32,
        remote_addr_len: u32,
        context: u32,
        context_len: u32,
    ) -> i32;

    /// Copies the resolved local socket address into the fixed-size `result` buffer.
    pub(crate) fn take_local_addr_for_remote(operation: u64, result: u32, result_len: u32) -> i32;

    /// Attempts to deliver one raw IP packet to a host packet sink.
    ///
    /// On success the host owns a complete copy. [`HOST_WOULD_BLOCK`] leaves
    /// the packet unaccepted and requires core to wait for write readiness.
    pub(crate) fn try_packet_write(handle: u64, packet: u32, packet_len: u32) -> i32;

    /// Starts waiting until another packet-sink admission attempt may succeed.
    pub(crate) fn start_packet_write_ready(handle: u64, operation: u64) -> i32;

    /// Reports packet-sink write readiness; it never accepts a packet itself.
    pub(crate) fn take_packet_write_ready(operation: u64) -> i32;

    /// Cancels a pending or completed-but-unread operation and releases host state.
    ///
    /// Cancellation must be idempotent when the operation is already absent.
    pub(crate) fn cancel_operation(operation: u64) -> i32;

    /// Closes a host socket or listener handle. Closing an already-closed handle is valid.
    pub(crate) fn close(handle: u64) -> i32;
}
