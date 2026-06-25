use easytier::core;

#[cfg(all(
    feature = "hotpath-alloc",
    any(feature = "jemalloc", feature = "mimalloc")
))]
compile_error!("feature `hotpath-alloc` cannot be enabled together with `jemalloc` or `mimalloc`");

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
use mimalloc::MiMalloc;

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
#[global_allocator]
static GLOBAL_MIMALLOC: MiMalloc = MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[cfg(feature = "jemalloc-prof")]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19,retain:false\0";

#[cfg(not(feature = "jemalloc-prof"))]
#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] = b"retain:false\0";

rust_i18n::i18n!("locales", fallback = "en");

#[tokio::main(flavor = "current_thread")]
#[cfg_attr(
    all(
        feature = "hotpath",
        not(all(
            feature = "hotpath-alloc",
            any(feature = "jemalloc", feature = "mimalloc")
        ))
    ),
    hotpath::main
)]
async fn main() -> std::process::ExitCode {
    core::main().await
}
