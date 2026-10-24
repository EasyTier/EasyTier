//! One instrumentation API with compile-time selected implementations.
//! See README.md for the feature matrix and async timing semantics.

#[cfg(all(feature = "hotpath", feature = "tracing"))]
compile_error!("select either hotpath or tracing/lttng profiling, not both");
#[cfg(all(feature = "lttng", not(target_os = "linux")))]
compile_error!("LTTng profiling requires a Linux target");

pub use easytier_profiling_macros::instrument;

#[cfg(all(feature = "lttng", target_os = "linux"))]
pub mod lttng;

#[doc(hidden)]
pub mod __private {
    #[cfg(feature = "hotpath")]
    pub use hotpath;
    #[cfg(feature = "tracing")]
    pub use tracing;
}

#[cfg(feature = "hotpath-alloc")]
pub use hotpath::CountingAllocator;
#[cfg(feature = "hotpath")]
pub use hotpath::{HotpathGuard, HotpathGuardBuilder};

/// Native endpoint and lock types when profiling, ordinary types otherwise.
#[cfg(feature = "hotpath")]
pub use hotpath::wrap;
#[cfg(not(feature = "hotpath"))]
pub mod wrap {
    pub use parking_lot;
    pub use std;
    pub use tokio;
}

/// These specialized wrappers intentionally become identity expressions without hotpath.
#[cfg(feature = "hotpath")]
pub use hotpath::{channel, future, mutex, rw_lock, stream};

#[cfg(not(feature = "hotpath"))]
#[macro_export]
macro_rules! channel {
    ($value:expr $(, $($options:tt)*)?) => {
        $value
    };
}
#[cfg(not(feature = "hotpath"))]
pub use channel as future;
#[cfg(not(feature = "hotpath"))]
pub use channel as mutex;
#[cfg(not(feature = "hotpath"))]
pub use channel as rw_lock;
#[cfg(not(feature = "hotpath"))]
pub use channel as stream;

/// Measure a synchronous block. Never put an `.await` inside this macro.
#[cfg(feature = "hotpath")]
#[macro_export]
macro_rules! scope {
    ($name:expr, $body:expr) => {
        $crate::__private::hotpath::measure_block!($name, $body)
    };
}
#[cfg(all(feature = "tracing", not(feature = "hotpath")))]
#[macro_export]
macro_rules! scope {
    ($name:expr, $body:expr) => {{
        let span = $crate::__private::tracing::trace_span!(target: "easytier::profiling", $name);
        let _entered = span.enter();
        $body
    }};
}
#[cfg(not(any(feature = "hotpath", feature = "tracing")))]
#[macro_export]
macro_rules! scope {
    ($name:expr, $body:expr) => {
        $body
    };
}

/// Wrap a Future; tracing enters/exits on every poll, never across suspension.
#[cfg(feature = "hotpath")]
#[macro_export]
macro_rules! scope_async {
    ($name:expr, $future:expr) => {
        $crate::__private::hotpath::functions::measure_async_future($name, $future)
    };
}
#[cfg(all(feature = "tracing", not(feature = "hotpath")))]
#[macro_export]
macro_rules! scope_async {
    ($name:expr, $future:expr) => {
        $crate::__private::tracing::Instrument::instrument(
            $future,
            $crate::__private::tracing::trace_span!(target: "easytier::profiling", $name),
        )
    };
}
#[cfg(not(any(feature = "hotpath", feature = "tracing")))]
#[macro_export]
macro_rules! scope_async {
    ($name:expr, $future:expr) => {
        $future
    };
}

/// Record named Debug values without imposing backend-specific call-site syntax.
#[cfg(feature = "hotpath")]
#[macro_export]
macro_rules! event {
    ($name:literal, $($field:ident = $value:expr),+ $(,)?) => {{
        $($crate::__private::hotpath::val!(concat!($name, ".", stringify!($field))).set(&$value);)+
    }};
}
#[cfg(all(feature = "tracing", not(feature = "hotpath")))]
#[macro_export]
macro_rules! event {
    ($name:literal, $($field:ident = $value:expr),+ $(,)?) => {
        $crate::__private::tracing::trace!(target: "easytier::profiling", name = $name, $($field = ?$value),+)
    };
}
#[cfg(not(any(feature = "hotpath", feature = "tracing")))]
#[macro_export]
macro_rules! event {
    ($name:literal, $($field:ident = $value:expr),+ $(,)?) => {};
}
