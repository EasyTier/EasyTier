# Native data-plane ABI v2

The native data-plane ABI is a thin adapter over the instance-owned
`DataPlaneSession`. It does not own sockets, operation state, completion
queues, routing policy, or timeouts.

## Conventions

- Every immediate call returns `0` on success or a negative
  `DataPlaneErrorKind` value on failure.
- `data_plane_completion_wait` returns `1` when a completion is ready, `0` on
  timeout or session close, and a negative error value on failure.
- `data_plane_completion_drain` returns a non-negative descriptor count or a
  negative error value.
- Handle zero is invalid.
- `timeout_ms == UINT64_MAX` means no deadline. Every other timeout starts when
  submission is accepted, including time spent waiting for an I/O direction
  lock.
- Request and write bytes are copied before a submit call returns.
- Socket-address fields use native-endian integers. Address bytes are in
  network order. ABI v2 accepts IPv4 only.

`DataPlaneSocketAddr` is:

```c
typedef struct {
    uint16_t family;      /* 4 */
    uint16_t port;
    uint8_t address[16];  /* IPv4 uses the first four bytes */
} DataPlaneSocketAddr;
```

`DataPlaneCompletion` is:

```c
typedef struct {
    uint64_t operation_id;
    uint16_t operation_kind;
    uint16_t status; /* 0 or DataPlaneErrorKind */
} DataPlaneCompletion;
```

## Lifecycle

One native session may be open for an EasyTier instance at a time:

```text
data_plane_session_open
  -> submit operations
  -> completion_wait
  -> completion_drain
  -> typed result_take
  -> resource_close / operation_free
data_plane_session_close
```

Closing a native session cancels and discards its outstanding operations and
resources and wakes a thread blocked in `data_plane_completion_wait`.

The resource and operation IDs returned by the ABI belong to that session.
They must always be passed together with the same session handle.

## Completion and result ownership

Submission returns an operation ID immediately. Completion descriptors carry
only the operation ID, operation kind, and terminal status. Draining a
descriptor makes its typed result available but does not consume it.

`data_plane_result_size` reports the TCP-read or UDP-receive payload size.
Typed result-take functions consume the result exactly once. If a supplied
buffer is too small, they return `-BufferTooSmall` and leave the result
available for a later call.

Call `data_plane_operation_free` when a drained result is intentionally
abandoned. Call `data_plane_resource_close` for TCP streams, listeners, and
UDP sockets.

## Operation kinds

| Value | Operation |
| ---: | --- |
| 1 | TCP connect |
| 2 | TCP bind |
| 3 | TCP accept |
| 4 | TCP read |
| 5 | TCP write |
| 6 | UDP bind |
| 7 | UDP receive |
| 8 | UDP send |

The exported function families are:

- `data_plane_tcp_*_submit`
- `data_plane_udp_*_submit`
- `data_plane_completion_wait`
- `data_plane_completion_drain`
- `data_plane_*_result_take`
- `data_plane_operation_cancel`
- `data_plane_operation_free`
- `data_plane_resource_close`
