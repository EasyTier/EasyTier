macro_rules! define_global_var {
    ($name:ident, $type:ty, $init:expr) => {
        pub static $name: once_cell::sync::Lazy<tokio::sync::Mutex<$type>> =
            once_cell::sync::Lazy::new(|| tokio::sync::Mutex::new($init));
    };
}

#[macro_export]
macro_rules! use_global_var {
    ($name:ident) => {
        crate::common::constants::$name.lock().await.to_owned()
    };
}

#[macro_export]
macro_rules! set_global_var {
    ($name:ident, $val:expr) => {
        *crate::common::constants::$name.lock().await = $val
    };
}

define_global_var!(MANUAL_CONNECTOR_RECONNECT_INTERVAL_MS, u64, 1000);

define_global_var!(OSPF_UPDATE_MY_GLOBAL_FOREIGN_NETWORK_INTERVAL_SEC, u64, 10);

pub const UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID: u32 = 2;

pub const WIN_SERVICE_WORK_DIR_REG_KEY: &str = "SOFTWARE\\EasyTier\\Service\\WorkDir";

pub const EASYTIER_VERSION: &str = git_version::git_version!(
    args = ["--abbrev=8", "--always", "--dirty=~"],
    prefix = concat!(env!("CARGO_PKG_VERSION"), "-"),
    suffix = "",
    fallback = env!("CARGO_PKG_VERSION")
);
