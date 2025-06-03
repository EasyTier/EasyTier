use easytier::launcher::SOCKET_CREATE_CALLBACK;
use lazy_static::lazy_static;
use ohos_hilog_binding::{hilog_info, set_global_options, LogOptions};
use std::ffi::c_int;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{atomic, Mutex};

lazy_static! {
    pub static ref PROTECT_FN: Mutex<Option<extern "C" fn(i32) -> bool>> =
            Mutex::new(None);
    pub static ref TUN_FD: atomic::AtomicI32 = atomic::AtomicI32::new(-1);
}

pub fn socket_create_callback(fd:i32, addr:&SocketAddr)-> bool {
    let protect_fn = PROTECT_FN.lock().unwrap();
    if let Some(callback) = protect_fn.as_ref() {
        if callback(fd) {
            hilog_info!("protect socket {} to {}.", fd, addr);
            true;
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn init_protect_fn(func: extern "C" fn(i32) -> bool) {
    // 初始化protect 回调方法
    let mut guard = PROTECT_FN.lock().unwrap();
    *guard = Some(func);
    let mut guard = SOCKET_CREATE_CALLBACK.lock().unwrap();
    *guard = Some(socket_create_callback);
}

#[no_mangle]
pub extern "C" fn hilog_global_options(domain: u32, raw: *const std::ffi::c_char) {
    let tag: &'static str = Box::leak(
        unsafe {
            std::ffi::CStr::from_ptr(raw)
                .to_string_lossy()
                .into_owned()
        }.into_boxed_str()
    );
    set_global_options(LogOptions{
        domain,
        tag,
    })
}

#[no_mangle]
pub extern "C" fn set_global_tun(fd: c_int) {
    TUN_FD.store(fd, Ordering::SeqCst);
}