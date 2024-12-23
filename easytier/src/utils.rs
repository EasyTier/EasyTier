use anyhow::Context;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};

use crate::common::{config::ConfigLoader, get_logger_timer_rfc3339};

pub type PeerRoutePair = crate::proto::cli::PeerRoutePair;

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
    config: impl ConfigLoader,
    need_reload: bool,
) -> Result<Option<NewFilterSender>, anyhow::Error> {
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
            ret_sender = Some(sender);
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

        let file_appender = tracing_appender::rolling::Builder::new()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .max_log_files(5)
            .filename_prefix(file_config.file.unwrap_or("easytier".to_string()))
            .filename_suffix("log")
            .build(file_config.dir.unwrap_or("./".to_string()))
            .with_context(|| "failed to initialize rolling file appender")?;
        file_layer = Some(
            l.with_writer(file_appender)
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

    tracing_subscriber::Registry::default()
        .with(console_layer)
        .with(file_layer)
        .init();

    Ok(ret_sender)
}

#[cfg(target_os = "windows")]
pub fn utf8_or_gbk_to_string(s: &[u8]) -> String {
    use encoding::{all::GBK, DecoderTrap, Encoding};
    if let Ok(utf8_str) = String::from_utf8(s.to_vec()) {
        utf8_str
    } else {
        // 如果解码失败，则尝试使用GBK解码
        if let Ok(gbk_str) = GBK.decode(&s, DecoderTrap::Strict) {
            gbk_str
        } else {
            String::from_utf8_lossy(s).to_string()
        }
    }
}

pub fn setup_panic_handler() {
    use std::backtrace;
    use std::io::Write;
    std::panic::set_hook(Box::new(|info| {
        let backtrace = backtrace::Backtrace::force_capture();
        let payload = info.payload();
        let payload_str: Option<&str> = if let Some(s) = payload.downcast_ref::<&str>() {
            Some(s)
        } else if let Some(s) = payload.downcast_ref::<String>() {
            Some(s)
        } else {
            None
        };

        if let Some(payload_str) = payload_str {
            println!(
                "panic occurred: payload:{}, location: {:?}, backtrace: {:#?}",
                payload_str,
                info.location(),
                backtrace
            );
        } else {
            println!(
                "panic occurred: location: {:?}, backtrace: {:#?}",
                info.location(),
                backtrace
            );
        }
        println!("{}", rust_i18n::t!("core_app.panic_backtrace_save"));
        let _ = std::fs::File::create("easytier-panic.log")
            .and_then(|mut f| f.write_all(format!("{:?}\n{:#?}", info, backtrace).as_bytes()));
        std::process::exit(1);
    }));
}

#[cfg(test)]
mod tests {
    use crate::common::config::{self};

    use super::*;

    async fn test_logger_reload() {
        println!("current working dir: {:?}", std::env::current_dir());
        let config = config::TomlConfigLoader::default();
        let s = init_logger(&config, true).unwrap();
        tracing::debug!("test not display debug");
        s.unwrap().send(LevelFilter::DEBUG.to_string()).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        tracing::debug!("test display debug");
    }
}
