pub const PI_LEN: usize = 4;

#[cfg(target_os = "linux")]
pub mod segmenter;
#[cfg(target_os = "linux")]
pub mod virtio;

#[cfg(target_os = "linux")]
pub use segmenter::*;
#[cfg(target_os = "linux")]
pub use virtio::*;
