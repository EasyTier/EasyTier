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

pub const UDP_HOLE_PUNCH_CONNECTOR_SERVICE_ID: u32 = 2;
