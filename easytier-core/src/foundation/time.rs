//! Tokio time facade.
//!
//! Native builds use Tokio directly. WASI builds use the deadline-tracking
//! implementation in [`crate::wasi::time`] so an external runtime can drive
//! the guest without polling.

#[cfg(not(any(test, target_os = "wasi")))]
pub use tokio::time::{Duration, Instant, Interval, error, interval, sleep, timeout};

#[cfg(any(test, target_os = "wasi"))]
pub use crate::wasi::time::{Duration, Instant, Interval, error, interval, sleep, timeout};

#[cfg(target_os = "wasi")]
pub(crate) use crate::wasi::time::{clear_domain, enter_domain, next_deadline_millis};
