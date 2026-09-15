pub mod config;
pub mod constants;
#[cfg(feature = "management")]
pub mod credential_manager;
pub mod dns;
#[cfg(feature = "management")]
pub mod env_parser;
pub mod error;
pub mod global_ctx;
pub mod ifcfg;
#[cfg(feature = "logging")]
pub mod log;
pub mod machine_id;
pub mod netns;
pub mod network;
#[cfg(feature = "management")]
pub mod os_info;
pub mod stun;
#[cfg(feature = "management")]
pub mod tracing_rolling_appender;
#[cfg(feature = "upnp")]
pub mod upnp;

pub use machine_id::{MachineIdOptions, resolve_machine_id};

pub fn shrink_dashmap<K: Eq + std::hash::Hash, V>(
    map: &dashmap::DashMap<K, V>,
    threshold: Option<usize>,
) {
    let threshold = threshold.unwrap_or(16);
    if map.capacity() - map.len() > threshold {
        map.shrink_to_fit();
    }
}
