use crate::common::config::LoggingConfigLoader;
use crate::common::get_logger_timer_rfc3339;
use crate::common::tracing_rolling_appender::{FileAppenderWrapper, RollingFileAppenderBase};
use crate::rpc_service::logger::{CURRENT_LOG_LEVEL, LOGGER_LEVEL_SENDER};
use anyhow::Context;
use regex::Regex;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::{Layer, Registry};

const LOG_TARGET_CORE: &str = "CORE";

fn parse_env_filter(default_level: LevelFilter) -> Result<EnvFilter, anyhow::Error> {
    let mut filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env()
        .with_context(|| "failed to create env filter")?;

    let pattern = Regex::new(&format!(r"(^|,){}\s*=", regex::escape(LOG_TARGET_CORE)))?;
    if !pattern.is_match(&filter.to_string()) {
        filter = filter.add_directive(format!("{}=info", LOG_TARGET_CORE).parse()?);
    }

    Ok(filter)
}

pub type NewFilterSender = std::sync::mpsc::Sender<String>;

pub fn init(
    config: impl LoggingConfigLoader,
    need_reload: bool,
) -> Result<Option<NewFilterSender>, anyhow::Error> {
    let file_config = config.get_file_logger_config();
    let file_level = file_config
        .level
        .map(|s| s.parse().unwrap())
        .unwrap_or(LevelFilter::OFF);

    let mut ret_sender: Option<NewFilterSender> = None;

    // logger to a rolling file
    let mut file_layer = None;
    if file_level != LevelFilter::OFF || need_reload {
        let mut l = tracing_subscriber::fmt::layer();
        l.set_ansi(false);
        let file_filter = parse_env_filter(file_level)?;
        let (file_filter, file_filter_reloader) =
            tracing_subscriber::reload::Layer::new(file_filter);

        if need_reload {
            let (sender, recver) = std::sync::mpsc::channel();
            ret_sender = Some(sender.clone());

            // 初始化全局状态
            let _ = LOGGER_LEVEL_SENDER.set(std::sync::Mutex::new(sender));
            let _ = CURRENT_LOG_LEVEL.set(std::sync::Mutex::new(file_level.to_string()));

            std::thread::spawn(move || {
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

    let console_filter = parse_env_filter(console_level)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::{self};

    async fn test_logger_reload() {
        println!("current working dir: {:?}", std::env::current_dir());
        let config = config::LoggingConfigBuilder::default().build().unwrap();
        let s = init(&config, true).unwrap();
        tracing::debug!("test not display debug");
        s.unwrap().send(LevelFilter::DEBUG.to_string()).unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        tracing::debug!("test display debug");
    }
}
