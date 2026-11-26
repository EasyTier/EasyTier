use easytier::core;

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
use mimalloc::MiMalloc;

#[cfg(all(feature = "mimalloc", not(feature = "jemalloc")))]
#[global_allocator]
static GLOBAL_MIMALLOC: MiMalloc = MiMalloc;

#[cfg(feature = "jemalloc")]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

#[allow(non_upper_case_globals)]
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] = concat!(
    cfg_select! {
        feature = "jemalloc-prof" => { "prof:true,prof_active:true,lg_prof_sample:19," }
        _ => { "" }
    },
    "dirty_decay_ms:1000,muzzy_decay_ms:1000,",
    cfg_select! {
        all(feature = "jemalloc", target_os = "linux", target_pointer_width = "64") => {
            "retain:true,background_thread:true"
        }
        _ => { "retain:false" }
    },
    "\0",
)
.as_bytes();

rust_i18n::i18n!("locales", fallback = "en");

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::process::ExitCode {
    core::main().await
}
