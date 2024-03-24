pub mod config;
pub mod constants;
pub mod error;
pub mod global_ctx;
pub mod ifcfg;
pub mod netns;
pub mod network;
pub mod rkyv_util;
pub mod stun;
pub mod stun_codec_ext;

pub fn get_logger_timer<F: time::formatting::Formattable>(
    format: F,
) -> tracing_subscriber::fmt::time::OffsetTime<F> {
    unsafe {
        time::util::local_offset::set_soundness(time::util::local_offset::Soundness::Unsound)
    };
    let local_offset = time::UtcOffset::current_local_offset()
        .unwrap_or(time::UtcOffset::from_whole_seconds(0).unwrap());
    tracing_subscriber::fmt::time::OffsetTime::new(local_offset, format)
}

pub fn get_logger_timer_rfc3339(
) -> tracing_subscriber::fmt::time::OffsetTime<time::format_description::well_known::Rfc3339> {
    get_logger_timer(time::format_description::well_known::Rfc3339)
}

pub type PeerId = u32;

pub fn new_peer_id() -> PeerId {
    rand::random()
}
