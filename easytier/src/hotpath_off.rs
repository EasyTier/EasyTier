//! No-op stand-in for the `hotpath` macros used by this crate, selected when
//! the `hotpath` feature is disabled.
//!
//! Keeping `hotpath` as an optional dependency means default builds do not pull
//! the profiler (or any of its transitive dependencies) into the dependency
//! graph. These macros expand to their input unchanged, mirroring `hotpath`'s
//! own disabled mode so call sites compile identically with or without the
//! feature.
//!
//! The macros are `#[macro_export]`-ed so that `lib.rs`' `extern crate self as
//! hotpath` alias exposes them through the same `hotpath::...` paths used when
//! the feature is enabled.

/// No-op mirroring `hotpath::channel!`: returns the channel expression
/// unchanged (dropping any optional trailing `label`/`log`/`capacity` args).
#[doc(hidden)]
#[macro_export]
macro_rules! channel {
    ($expr:expr $(, $($rest:tt)*)?) => {
        $expr
    };
}

/// No-op mirroring `hotpath::mutex!`: returns the expression unchanged.
#[doc(hidden)]
#[macro_export]
macro_rules! mutex {
    ($expr:expr $(, $($rest:tt)*)?) => {
        $expr
    };
}

/// No-op mirroring `hotpath::rw_lock!`: returns the expression unchanged.
#[doc(hidden)]
#[macro_export]
macro_rules! rw_lock {
    ($expr:expr $(, $($rest:tt)*)?) => {
        $expr
    };
}
