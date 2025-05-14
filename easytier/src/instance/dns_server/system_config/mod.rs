#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "windows")]
pub mod windows;
