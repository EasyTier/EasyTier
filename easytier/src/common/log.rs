use crate::common::config::LoggingConfigLoader;
use crate::common::get_logger_timer_rfc3339;
use crate::common::tracing_rolling_appender::{FileAppenderWrapper, RollingFileAppenderBase};
use crate::rpc_service::logger::{CURRENT_LOG_LEVEL, LOGGER_LEVEL_SENDER};
use anyhow::Context;
use paste::paste;
use regex::Regex;
use tracing::level_filters::LevelFilter;
use tracing::Metadata;
use tracing_subscriber::filter::{filter_fn, FilterExt};
use tracing_subscriber::fmt::layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Registry;
use tracing_subscriber::{EnvFilter, Layer};

macro_rules! __log__ {
    (const $var:ident = $target:expr) => {
        const $var: &'static str = $target;
        __log__!(@impl $target, $);
    };

    (@impl $target:expr, $_:tt) => {
        __log__!(@impl $_, $target, error, warn, info, debug, trace);
    };

    (@impl $_:tt, $target:expr, $($lvl:ident),+) => {
        paste! {
            $(
                macro_rules! [< __ $lvl __ >] {
                    (category: $cat:expr, $_ ($arg:tt)+) => {
                        tracing::$lvl!(target: concat!($target, "::", $cat), $_ ($arg)+)
                    };
                    ($_ ($arg:tt)+) => {
                        tracing::$lvl!(target: $target, $_ ($arg)+)
                    };
                }

                #[allow(unused_imports)]
                pub(crate) use [< __ $lvl __ >] as $lvl;
            )+
        }
    };
}

__log__!(const LOG_TARGET = "CORE");

fn parse_env_filter(default_level: LevelFilter) -> Result<EnvFilter, anyhow::Error> {
    let mut filter = EnvFilter::builder()
        .with_default_directive(default_level.into())
        .from_env()
        .with_context(|| "failed to create env filter")?;

    let pattern = Regex::new(&format!(r"(^|,){}\s*=", regex::escape(LOG_TARGET)))?;
    if !pattern.is_match(&filter.to_string()) {
        filter = filter.add_directive(format!("{LOG_TARGET}=info").parse()?);
    }

    Ok(filter)
}

fn is_log(meta: &Metadata) -> bool {
    meta.target() == LOG_TARGET || meta.target().starts_with(&format!("{LOG_TARGET}::"))
}

pub type NewFilterSender = std::sync::mpsc::Sender<String>;
macro_rules! layers {
    ($layer:expr) => {{
        vec![
            $layer.with_filter(filter_fn(is_log).not()).boxed(),
            $layer
                .with_file(false)
                .with_line_number(false)
                .with_ansi(true)
                .with_filter(filter_fn(is_log))
                .boxed(),
        ]
    }};
}

pub fn init(
    config: impl LoggingConfigLoader,
    need_reload: bool,
) -> Result<Option<NewFilterSender>, anyhow::Error> {
    let mut layers = Vec::new();

    let file_config = config.get_file_logger_config();
    let file_level = file_config
        .level
        .map(|s| s.parse().unwrap())
        .unwrap_or(LevelFilter::OFF);

    let mut ret_sender: Option<NewFilterSender> = None;

    // logger to a rolling file
    if file_level != LevelFilter::OFF || need_reload {
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

        // Create a simple wrapper that implements MakeWriter
        let wrapper = FileAppenderWrapper::new(file_appender);

        let (file_filter, file_filter_reloader) =
            tracing_subscriber::reload::Layer::<_, Registry>::new(parse_env_filter(file_level)?);

        let layer = |wrapper| {
            layer()
                .with_ansi(false)
                .with_writer(wrapper)
                .with_timer(get_logger_timer_rfc3339())
        };

        layers.push(
            layers!(layer(wrapper.clone()))
                .with_filter(file_filter)
                .boxed(),
        );

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
                            info!("Reload log filter succeed, new filter level: {:?}", lf);
                            *f = nf;
                        }
                    });
                    if e.is_err() {
                        error!("Failed to reload log filter: {:?}", e);
                    }
                }
                info!("Stop log filter reloader");
            });
        }
    }

    // logger to console
    let console_config = config.get_console_logger_config();
    let console_level = console_config
        .level
        .map(|s| s.parse().unwrap())
        .unwrap_or(LevelFilter::OFF);

    let (console_filter, _) =
        tracing_subscriber::reload::Layer::new(parse_env_filter(console_level)?);

    let layer = || {
        layer()
            .pretty()
            .with_timer(get_logger_timer_rfc3339())
            .with_writer(std::io::stderr)
    };

    layers.push(layers!(layer()).with_filter(console_filter).boxed());

    #[cfg(feature = "tracing")]
    {
        layers.push(console_subscriber::ConsoleLayer::builder().spawn().boxed());
    }

    Registry::default().with(layers).init();

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
