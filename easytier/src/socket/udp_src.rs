#[cfg(unix)]
#[path = "udp_src/unix.rs"]
mod platform;

#[cfg(windows)]
#[path = "udp_src/windows.rs"]
mod platform;

#[cfg(not(any(unix, windows)))]
#[path = "udp_src/fallback.rs"]
mod platform;

pub(crate) use platform::*;
