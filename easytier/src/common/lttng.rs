#[cfg(feature = "lttng")]
lttng_ust::import_tracepoints!(
    concat!(env!("OUT_DIR"), "/lttng_tracepoints.rs"),
    tracepoints
);

#[cfg(feature = "lttng")]
pub fn mark(name: &str, value: u64) {
    tracepoints::easytier::mark(name, value);
}

#[cfg(not(feature = "lttng"))]
#[inline(always)]
pub fn mark(_name: &str, _value: u64) {}

#[cfg(feature = "lttng")]
pub fn duration_micros(name: &str, duration_micros: u64) {
    tracepoints::easytier::duration_micros(name, duration_micros);
}

#[cfg(not(feature = "lttng"))]
#[inline(always)]
pub fn duration_micros(_name: &str, _duration_micros: u64) {}
