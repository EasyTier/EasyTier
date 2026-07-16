use time::util::refresh_tz;

pub mod config;
pub mod constants;
pub mod credential_manager;
pub mod dns;
pub mod env_parser;
pub mod error;
pub mod global_ctx;
pub mod ifcfg;
pub mod log;
pub mod machine_id;
pub mod netns;
pub mod network;
pub mod os_info;
pub mod stun;
pub mod tracing_rolling_appender;
pub mod upnp;

pub use machine_id::{MachineIdOptions, resolve_machine_id};

pub fn get_logger_timer<F: time::formatting::Formattable>(
    format: F,
) -> tracing_subscriber::fmt::time::OffsetTime<F> {
    refresh_tz();
    let local_offset = time::UtcOffset::current_local_offset()
        .unwrap_or(time::UtcOffset::from_whole_seconds(0).unwrap());
    tracing_subscriber::fmt::time::OffsetTime::new(local_offset, format)
}

pub fn get_logger_timer_rfc3339()
-> tracing_subscriber::fmt::time::OffsetTime<time::format_description::well_known::Rfc3339> {
    get_logger_timer(time::format_description::well_known::Rfc3339)
}

pub fn shrink_dashmap<K: Eq + std::hash::Hash, V>(
    map: &dashmap::DashMap<K, V>,
    threshold: Option<usize>,
) {
    let threshold = threshold.unwrap_or(16);
    if map.capacity() - map.len() > threshold {
        map.shrink_to_fit();
    }
}
