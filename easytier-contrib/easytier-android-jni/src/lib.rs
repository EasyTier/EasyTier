use easytier::proto::api::manage::{NetworkInstanceRunningInfo, NetworkInstanceRunningInfoMap};
use jni::objects::{JClass, JObjectArray, JString};
use jni::sys::{jint, jstring};
use jni::JNIEnv;
use once_cell::sync::Lazy;
use std::ffi::{CStr, CString};
use std::ptr;

// 定义 KeyValuePair 结构体
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KeyValuePair {
    pub key: *const std::ffi::c_char,
    pub value: *const std::ffi::c_char,
}

// 声明外部 C 函数
extern "C" {
    fn set_tun_fd(inst_name: *const std::ffi::c_char, fd: std::ffi::c_int) -> std::ffi::c_int;
    fn get_error_msg(out: *mut *const std::ffi::c_char);
    fn free_string(s: *const std::ffi::c_char);
    fn parse_config(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int;
    fn run_network_instance(cfg_str: *const std::ffi::c_char) -> std::ffi::c_int;
    fn retain_network_instance(
        inst_names: *const *const std::ffi::c_char,
        length: usize,
    ) -> std::ffi::c_int;
    fn collect_network_infos(infos: *mut KeyValuePair, max_length: usize) -> std::ffi::c_int;
}

// 初始化 Android 日志
static LOGGER_INIT: Lazy<()> = Lazy::new(|| {
    android_logger::init_once(
        android_logger::Config::default()
            .with_max_level(log::LevelFilter::Debug)
            .with_tag("EasyTier-JNI"),
    );
});

// 辅助函数：从 Java String 转换为 CString
fn jstring_to_cstring(env: &mut JNIEnv, jstr: &JString) -> Result<CString, String> {
    let java_str = env
        .get_string(jstr)
        .map_err(|e| format!("Failed to get string: {:?}", e))?;
    let rust_str = java_str.to_str().map_err(|_| "Invalid UTF-8".to_string())?;
    CString::new(rust_str).map_err(|_| "String contains null byte".to_string())
}

// 辅助函数：获取错误消息
fn get_last_error() -> Option<String> {
    unsafe {
        let mut error_ptr: *const std::ffi::c_char = ptr::null();
        get_error_msg(&mut error_ptr);
        if error_ptr.is_null() {
            None
        } else {
            let error_cstr = CStr::from_ptr(error_ptr);
            let error_str = error_cstr.to_string_lossy().into_owned();
            free_string(error_ptr);
            Some(error_str)
        }
    }
}

// 辅助函数：抛出 Java 异常
fn throw_exception(env: &mut JNIEnv, message: &str) {
    let _ = env.throw_new("java/lang/RuntimeException", message);
}

/// 设置 TUN 文件描述符
#[no_mangle]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_setTunFd(
    mut env: JNIEnv,
    _class: JClass,
    inst_name: JString,
    fd: jint,
) -> jint {
    Lazy::force(&LOGGER_INIT);

    let inst_name_cstr = match jstring_to_cstring(&mut env, &inst_name) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid instance name: {}", e));
            return -1;
        }
    };

    unsafe {
        let result = set_tun_fd(inst_name_cstr.as_ptr(), fd);
        if result != 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
        }
        result
    }
}

/// 解析配置
#[no_mangle]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_parseConfig(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
) -> jint {
    Lazy::force(&LOGGER_INIT);

    let config_cstr = match jstring_to_cstring(&mut env, &config) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid config string: {}", e));
            return -1;
        }
    };

    unsafe {
        let result = parse_config(config_cstr.as_ptr());
        if result != 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
        }
        result
    }
}

/// 运行网络实例
#[no_mangle]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_runNetworkInstance(
    mut env: JNIEnv,
    _class: JClass,
    config: JString,
) -> jint {
    Lazy::force(&LOGGER_INIT);

    let config_cstr = match jstring_to_cstring(&mut env, &config) {
        Ok(cstr) => cstr,
        Err(e) => {
            throw_exception(&mut env, &format!("Invalid config string: {}", e));
            return -1;
        }
    };

    unsafe {
        let result = run_network_instance(config_cstr.as_ptr());
        if result != 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
        }
        result
    }
}

/// 保持网络实例
#[no_mangle]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_retainNetworkInstance(
    mut env: JNIEnv,
    _class: JClass,
    instance_names: JObjectArray,
) -> jint {
    Lazy::force(&LOGGER_INIT);

    // 处理 null 数组的情况
    if instance_names.is_null() {
        unsafe {
            let result = retain_network_instance(ptr::null(), 0);
            if result != 0 {
                if let Some(error) = get_last_error() {
                    throw_exception(&mut env, &error);
                }
            }
            return result;
        }
    }

    // 获取数组长度
    let array_length = match env.get_array_length(&instance_names) {
        Ok(len) => len as usize,
        Err(e) => {
            throw_exception(&mut env, &format!("Failed to get array length: {:?}", e));
            return -1;
        }
    };

    // 如果数组为空，停止所有实例
    if array_length == 0 {
        unsafe {
            let result = retain_network_instance(ptr::null(), 0);
            if result != 0 {
                if let Some(error) = get_last_error() {
                    throw_exception(&mut env, &error);
                }
            }
            return result;
        }
    }

    // 转换 Java 字符串数组为 C 字符串数组
    let mut c_strings = Vec::with_capacity(array_length);
    let mut c_string_ptrs = Vec::with_capacity(array_length);

    for i in 0..array_length {
        let java_string = match env.get_object_array_element(&instance_names, i as i32) {
            Ok(obj) => obj,
            Err(e) => {
                throw_exception(
                    &mut env,
                    &format!("Failed to get array element {}: {:?}", i, e),
                );
                return -1;
            }
        };

        if java_string.is_null() {
            continue; // 跳过 null 元素
        }

        let jstring = JString::from(java_string);
        let c_string = match jstring_to_cstring(&mut env, &jstring) {
            Ok(cstr) => cstr,
            Err(e) => {
                throw_exception(
                    &mut env,
                    &format!("Invalid instance name at index {}: {}", i, e),
                );
                return -1;
            }
        };

        c_string_ptrs.push(c_string.as_ptr());
        c_strings.push(c_string); // 保持 CString 的所有权
    }

    unsafe {
        let result = retain_network_instance(c_string_ptrs.as_ptr(), c_string_ptrs.len());
        if result != 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
        }
        result
    }
}

/// 收集网络信息
#[no_mangle]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_collectNetworkInfos(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    Lazy::force(&LOGGER_INIT);

    const MAX_INFOS: usize = 100;
    let mut infos = vec![
        KeyValuePair {
            key: ptr::null(),
            value: ptr::null(),
        };
        MAX_INFOS
    ];

    unsafe {
        let count = collect_network_infos(infos.as_mut_ptr(), MAX_INFOS);
        if count < 0 {
            if let Some(error) = get_last_error() {
                throw_exception(&mut env, &error);
            }
            return ptr::null_mut();
        }

        let mut ret = NetworkInstanceRunningInfoMap::default();

        // 使用 serde_json 构建 JSON
        for info in infos.iter().take(count as usize) {
            let key_ptr = info.key;
            let val_ptr = info.value;
            if key_ptr.is_null() || val_ptr.is_null() {
                break;
            }

            let key = CStr::from_ptr(key_ptr).to_string_lossy();
            let val = CStr::from_ptr(val_ptr).to_string_lossy();
            let value = match serde_json::from_str::<NetworkInstanceRunningInfo>(val.as_ref()) {
                Ok(v) => v,
                Err(_) => {
                    throw_exception(&mut env, "Failed to parse JSON");
                    continue;
                }
            };
            ret.map.insert(key.to_string(), value);
        }

        let json_str = serde_json::to_string(&ret).unwrap_or_else(|_| "{}".to_string());

        match env.new_string(&json_str) {
            Ok(jstr) => jstr.into_raw(),
            Err(_) => {
                throw_exception(&mut env, "Failed to create JSON string");
                ptr::null_mut()
            }
        }
    }
}

/// 获取最后的错误信息
#[no_mangle]
pub extern "system" fn Java_com_easytier_jni_EasyTierJNI_getLastError(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    match get_last_error() {
        Some(error) => match env.new_string(&error) {
            Ok(jstr) => jstr.into_raw(),
            Err(_) => ptr::null_mut(),
        },
        None => ptr::null_mut(),
    }
}
