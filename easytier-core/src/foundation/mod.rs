//! Infrastructure Modules with no domain dependency.
//!
//! Everything in `foundation` may be used by any layer, and nothing here may
//! depend on a domain Module. See `CONTEXT.md` "Module layers".

pub mod expiring_set;
#[cfg(any(target_os = "wasi", test))]
pub(crate) mod logger;
#[cfg(any(
    feature = "proxy-smoltcp-stack",
    test,
    all(feature = "management-rpc", target_os = "wasi")
))]
pub(crate) mod operation_broker;
pub mod stats;
pub(crate) mod task;
pub(crate) mod time;
pub(crate) mod token_bucket;

// Each network and peer owns several small maps. Cap their shard arrays to
// avoid multiplying empty-map overhead on public servers, while retaining
// DashMap's smaller default on single-CPU machines.
pub(crate) fn small_map_shard_amount() -> usize {
    static SHARDS: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        (std::thread::available_parallelism().map_or(1, usize::from) * 4)
            .next_power_of_two()
            .min(8)
    });
    *SHARDS
}
