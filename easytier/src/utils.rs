use std::{fs::OpenOptions, str::FromStr};

use anyhow::Context;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer, Registry,
};
use url::Url;

use crate::common::{
    config::LoggingConfigLoader, get_logger_timer_rfc3339, tracing_rolling_appender::*,
};

pub type PeerRoutePair = crate::proto::api::instance::PeerRoutePair;

pub fn cost_to_str(cost: i32) -> String {
    if cost == 1 {
        "p2p".to_string()
    } else {
        format!("relay({})", cost)
    }
}

pub fn float_to_str(f: f64, precision: usize) -> String {
    format!("{:.1$}", f, precision)
}

pub type NewFilterSender = std::sync::mpsc::Sender<String>;

pub fn init_logger(
    config: impl LoggingConfigLoader,
    need_reload: bool,
) -> Result<Option<NewFilterSender>, anyhow::Error> {
    use crate::rpc_service::logger::{CURRENT_LOG_LEVEL, LOGGER_LEVEL_SENDER};

    let file_config = config.get_file_logger_config();
    let file_level = file_config
        .level
        .map(|s| s.parse().unwrap())
        .unwrap_or(LevelFilter::OFF);

    let mut ret_sender: Option<NewFilterSender> = None;

    // logger to rolling file
    let mut file_layer = None;
    if file_level != LevelFilter::OFF || need_reload {
        let mut l = tracing_subscriber::fmt::layer();
        l.set_ansi(false);
        let file_filter = EnvFilter::builder()
            .with_default_directive(file_level.into())
            .from_env()
            .with_context(|| "failed to create file filter")?;
        let (file_filter, file_filter_reloader) =
            tracing_subscriber::reload::Layer::new(file_filter);

        if need_reload {
            let (sender, recver) = std::sync::mpsc::channel();
            ret_sender = Some(sender.clone());

            // 初始化全局状态
            let _ = LOGGER_LEVEL_SENDER.set(std::sync::Mutex::new(sender));
            let _ = CURRENT_LOG_LEVEL.set(std::sync::Mutex::new(file_level.to_string()));

            std::thread::spawn(move || {
                println!("Start log filter reloader");
                while let Ok(lf) = recver.recv() {
                    let e = file_filter_reloader.modify(|f| {
                        if let Ok(nf) = EnvFilter::builder()
                            .with_default_directive(lf.parse::<LevelFilter>().unwrap().into())
                            .from_env()
                            .with_context(|| "failed to create file filter")
                        {
                            println!("Reload log filter succeed, new filter level: {:?}", lf);
                            *f = nf;
                        }
                    });
                    if e.is_err() {
                        println!("Failed to reload log filter: {:?}", e);
                    }
                }
                println!("Stop log filter reloader");
            });
        }

        let dir = file_config.dir.as_deref().unwrap_or(".");
        let file = file_config.file.as_deref().unwrap_or("easytier.log");
        let path = std::path::Path::new(dir).join(file);
        let path_str = path.to_string_lossy().into_owned();

        let builder = RollingFileAppenderBase::builder();
        let file_appender = builder
            .filename(path_str)
            .condition_daily()
            .max_filecount(file_config.count.unwrap_or(10))
            .condition_max_file_size(file_config.size_mb.unwrap_or(100) * 1024 * 1024)
            .build()
            .unwrap();

        let wrapper = FileAppenderWrapper::new(file_appender);

        // Create a simple wrapper that implements MakeWriter
        file_layer = Some(
            l.with_writer(wrapper)
                .with_timer(get_logger_timer_rfc3339())
                .with_filter(file_filter),
        );
    }

    // logger to console
    let console_config = config.get_console_logger_config();
    let console_level = console_config
        .level
        .map(|s| s.parse().unwrap())
        .unwrap_or(LevelFilter::OFF);

    let console_filter = EnvFilter::builder()
        .with_default_directive(console_level.into())
        .from_env()
        .unwrap();

    let console_layer = tracing_subscriber::fmt::layer()
        .pretty()
        .with_timer(get_logger_timer_rfc3339())
        .with_writer(std::io::stderr)
        .with_filter(console_filter);

    let registry = Registry::default();

    #[cfg(not(feature = "tracing"))]
    {
        registry.with(console_layer).with(file_layer).init();
    }

    #[cfg(feature = "tracing")]
    {
        let console_subscriber_layer = console_subscriber::ConsoleLayer::builder().spawn();
        registry
            .with(console_layer)
            .with(file_layer)
            .with(console_subscriber_layer)
            .init();
    }

    Ok(ret_sender)
}

#[cfg(target_os = "windows")]
pub fn utf8_or_gbk_to_string(s: &[u8]) -> String {
    use encoding::{all::GBK, DecoderTrap, Encoding};
    if let Ok(utf8_str) = String::from_utf8(s.to_vec()) {
        utf8_str
    } else {
        // 如果解码失败，则尝试使用GBK解码
        if let Ok(gbk_str) = GBK.decode(s, DecoderTrap::Strict) {
            gbk_str
        } else {
            String::from_utf8_lossy(s).to_string()
        }
    }
}

thread_local! {
    static PANIC_COUNT : std::cell::RefCell<u32> = const { std::cell::RefCell::new(0) };
}

pub fn setup_panic_handler() {
    use std::backtrace;
    use std::io::Write;
    std::panic::set_hook(Box::new(|info| {
        PANIC_COUNT.with(|c| {
            let mut count = c.borrow_mut();
            *count += 1;
        });
        let panic_count = PANIC_COUNT.with(|c| *c.borrow());
        if panic_count > 1 {
            println!("panic happened more than once, exit immediately");
            std::process::exit(1);
        }

        let payload = info.payload();
        let payload_str: Option<&str> = if let Some(s) = payload.downcast_ref::<&str>() {
            Some(s)
        } else if let Some(s) = payload.downcast_ref::<String>() {
            Some(s)
        } else {
            None
        };
        let payload_str = payload_str.unwrap_or("<unknown panic info>");
        // The current implementation always returns `Some`.
        let location = info.location().unwrap();
        let thread = std::thread::current();
        let thread = thread.name().unwrap_or("<unnamed>");

        let tmp_path = std::env::temp_dir().join("easytier-panic.log");
        let candidate_path = [
            std::path::PathBuf::from_str("easytier-panic.log").ok(),
            Some(tmp_path),
        ];
        let mut file = None;
        let mut file_path = None;
        for path in candidate_path.iter().filter_map(|p| p.clone()) {
            file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path.clone())
                .ok();
            if file.is_some() {
                file_path = Some(path);
                break;
            }
        }

        println!("{}", rust_i18n::t!("core_app.panic_backtrace_save"));

        // write str to stderr & file
        let write_err = |s: String| {
            let mut stderr = std::io::stderr();
            let content = format!("{}: {}", chrono::Local::now(), s);
            let _ = writeln!(stderr, "{}", content);
            if let Some(mut f) = file.as_ref() {
                let _ = writeln!(f, "{}", content);
            }
        };

        write_err("panic occurred, if this is a bug, please report this issue on github (https://github.com/easytier/easytier/issues)".to_string());
        write_err(format!("easytier version: {}", crate::VERSION));
        write_err(format!("os version: {}", std::env::consts::OS));
        write_err(format!("arch: {}", std::env::consts::ARCH));
        write_err(format!(
            "panic is recorded in: {}",
            file_path
                .and_then(|p| p.to_str().map(|x| x.to_string()))
                .unwrap_or("<no file>".to_string())
        ));
        write_err(format!("thread: {}", thread));
        write_err(format!("time: {}", chrono::Local::now()));
        write_err(format!("location: {}", location));
        write_err(format!("panic info: {}", payload_str));

        // backtrace is risky, so use it last
        let backtrace = backtrace::Backtrace::force_capture();
        write_err(format!("backtrace: {:#?}", backtrace));

        std::process::exit(1);
    }));
}

pub fn check_tcp_available(port: u16) -> bool {
    use std::net::TcpListener;
    let s = std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), port);
    TcpListener::bind(s).is_ok()
}

pub fn find_free_tcp_port(mut range: std::ops::Range<u16>) -> Option<u16> {
    range.find(|&port| check_tcp_available(port))
}

pub fn weak_upgrade<T>(weak: &std::sync::Weak<T>) -> anyhow::Result<std::sync::Arc<T>> {
    weak.upgrade()
        .ok_or_else(|| anyhow::anyhow!("{} not available", std::any::type_name::<T>()))
}

/// 处理URL中的特殊端口
/// 如果协议是ws且端口号是80，或者协议是wss且端口号是443，就把端口改成0
/// 必须在解析前检查原始字符串，因为解析后默认端口会被修剪
pub fn process_url_port(url_str: &str) -> Result<Url, anyhow::Error> {
    // 检查ws协议的80端口或wss协议的443端口
    let use_port_zero = if let Some(host_part) = url_str.strip_prefix("ws://") {
        host_part.split('/').next().unwrap_or("").ends_with(":80")
    } else if let Some(host_part) = url_str.strip_prefix("wss://") {
        host_part.split('/').next().unwrap_or("").ends_with(":443")
    } else {
        false
    };

    // 解析URL
    let mut url = url_str
        .parse::<Url>()
        .with_context(|| format!("failed to parse uri: {}", url_str))?;

    // 如果需要，将端口设置为0（unwrap安全，因为URL已成功解析）
    if use_port_zero {
        url.set_port(Some(0)).unwrap();
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use crate::common::config::{self};

    use super::*;

    async fn test_logger_reload() {
        println!("current working dir: {:?}", std::env::current_dir());
        let config = config::LoggingConfigBuilder::default().build().unwrap();
        let s = init_logger(&config, true).unwrap();
        tracing::debug!("test not display debug");
        s.unwrap().send(LevelFilter::DEBUG.to_string()).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        tracing::debug!("test display debug");
    }

    // 辅助函数：测试URL端口处理
    fn test_url_port_helper(
        url_str: &str,
        expected_scheme: &str,
        expected_host: Option<&str>,
        expected_port: Option<u16>,
        expected_path: Option<&str>,
    ) -> anyhow::Result<()> {
        let url = process_url_port(url_str)?;
        assert_eq!(
            url.scheme(),
            expected_scheme,
            "Scheme mismatch for {}",
            url_str
        );
        assert_eq!(
            url.host_str(),
            expected_host,
            "Host mismatch for {}",
            url_str
        );
        assert_eq!(url.port(), expected_port, "Port mismatch for {}", url_str);
        if let Some(expected_path) = expected_path {
            assert_eq!(url.path(), expected_path, "Path mismatch for {}", url_str);
        }
        Ok(())
    }

    #[test]
    fn test_process_url_port() -> anyhow::Result<()> {
        // 核心功能测试
        test_url_port_helper(
            "ws://example.com:80",
            "ws",
            Some("example.com"),
            Some(0),
            None,
        )?;
        test_url_port_helper(
            "wss://example.com:443",
            "wss",
            Some("example.com"),
            Some(0),
            None,
        )?;

        // 带路径的情况
        test_url_port_helper(
            "ws://example.com:80/path",
            "ws",
            Some("example.com"),
            Some(0),
            Some("/path"),
        )?;
        test_url_port_helper(
            "ws://example.com:80/path:80",
            "ws",
            Some("example.com"),
            Some(0),
            Some("/path:80"),
        )?;
        test_url_port_helper(
            "wss://example.com:443/path:443",
            "wss",
            Some("example.com"),
            Some(0),
            Some("/path:443"),
        )?;
        test_url_port_helper(
            "ws://example.com:80//double-slash/path",
            "ws",
            Some("example.com"),
            Some(0),
            Some("//double-slash/path"),
        )?;
        test_url_port_helper(
            "wss://example.com:443//double-slash/path",
            "wss",
            Some("example.com"),
            Some(0),
            Some("//double-slash/path"),
        )?;
        test_url_port_helper(
            "wss://example.com:443/",
            "wss",
            Some("example.com"),
            Some(0),
            Some("/"),
        )?;

        // 非标准端口保持不变
        test_url_port_helper(
            "ws://example.com:8080/path",
            "ws",
            Some("example.com"),
            Some(8080),
            Some("/path"),
        )?;

        // 其他协议保持不变
        test_url_port_helper(
            "tcp://example.com:80/path",
            "tcp",
            Some("example.com"),
            Some(80),
            Some("/path"),
        )?;

        // 无端口情况保持不变
        test_url_port_helper(
            "ws://example.com/path",
            "ws",
            Some("example.com"),
            None,
            Some("/path"),
        )?;
        test_url_port_helper(
            "wss://example.com/path",
            "wss",
            Some("example.com"),
            None,
            Some("/path"),
        )?;

        // IPv6地址测试
        test_url_port_helper(
            "ws://[2001:80::80]",
            "ws",
            Some("[2001:80::80]"),
            None,
            None,
        )?;
        test_url_port_helper(
            "ws://[2001:80::80]:80",
            "ws",
            Some("[2001:80::80]"),
            Some(0),
            None,
        )?;
        test_url_port_helper(
            "wss://[2001::443]:443/path",
            "wss",
            Some("[2001::443]"),
            Some(0),
            Some("/path"),
        )?;
        test_url_port_helper(
            "wss://[2001:443::443]/path",
            "wss",
            Some("[2001:443::443]"),
            None,
            Some("/path"),
        )?;

        // 路径中包含80的情况
        test_url_port_helper(
            "ws://example.com/path:80/",
            "ws",
            Some("example.com"),
            None,
            Some("/path:80/"),
        )?;

        Ok(())
    }

    #[test]
    fn test_process_url_port_invalid_url() {
        let url_str = "invalid-url";
        let result = process_url_port(url_str);
        assert!(result.is_err(), "Invalid URL should return error");
    }
}
