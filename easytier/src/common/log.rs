use crate::common::config::{FileLoggerConfig, LoggingConfigLoader};
use crate::common::get_logger_timer_rfc3339;
use crate::common::tracing_rolling_appender::{FileAppenderWrapper, RollingFileAppenderBase};
use crate::rpc_service::logger::{CURRENT_LOG_LEVEL, LOGGER_LEVEL_SENDER};
use anyhow::Context;
use cfg_if::cfg_if;
use paste::paste;
use std::io::IsTerminal;
use tracing::level_filters::LevelFilter;
use tracing::{Level, Metadata};
use tracing_subscriber::Registry;
use tracing_subscriber::filter::{FilterExt, filter_fn};
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::layer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
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

fn parse_env_filter(default_level: Option<LevelFilter>) -> Result<EnvFilter, anyhow::Error> {
    let directive = match default_level {
        Some(level) => level.into(),
        None => format!("{LOG_TARGET}=info").parse()?,
    };

    EnvFilter::builder()
        .with_default_directive(directive)
        .from_env()
        .with_context(|| "failed to create env filter")
}

fn is_log(meta: &Metadata) -> bool {
    meta.target() == LOG_TARGET || meta.target().starts_with(&format!("{LOG_TARGET}::"))
}

pub type NewFilterSender = std::sync::mpsc::Sender<String>;

macro_rules! tracing_layer {
    ($layer:expr) => {
        $layer.with_filter(filter_fn(is_log).not()).boxed()
    };
}

macro_rules! log_layer {
    ($layer:expr) => {
        $layer
            .with_file(false)
            .with_line_number(false)
            .with_filter(filter_fn(is_log))
            .boxed()
    };
}

pub fn init(
    config: impl LoggingConfigLoader,
    reload: bool,
) -> Result<Option<NewFilterSender>, anyhow::Error> {
    let mut layers = Vec::new();

    let console_layers = console_layers(
        config
            .get_console_logger_config()
            .level
            .map(|s| s.parse().unwrap()),
    )?;
    layers.extend(console_layers);

    let sender = if cfg!(not(test)) {
        let (file_layers, sender) = file_layers(config.get_file_logger_config(), reload)?;
        layers.extend(file_layers);
        sender
    } else {
        None
    };

    Registry::default()
        .with(layers)
        .try_init()
        .map(|_| sender)
        .map_err(Into::into)
}

type BoxLayer = Box<dyn Layer<Registry> + Send + Sync>;

fn console_layers(default_level: Option<LevelFilter>) -> anyhow::Result<Vec<BoxLayer>> {
    let mut layers = Vec::new();
    if matches!(default_level, Some(LevelFilter::OFF)) {
        return Ok(layers);
    }

    let (console_filter, _) =
        tracing_subscriber::reload::Layer::new(parse_env_filter(default_level)?);

    cfg_if! {
        if #[cfg(test)] {
            let w = tracing_subscriber::fmt::TestWriter::new;
            let (stdout, stderr) = (w, w);
        } else {
            let (stdout, stderr) = (std::io::stdout, std::io::stderr);
        }
    }

    let ansi = std::io::stderr().is_terminal() || cfg!(test);

    let layer = || {
        layer()
            .compact()
            .with_timer(get_logger_timer_rfc3339())
            .with_ansi(ansi)
            .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
            .with_writer(stderr)
    };

    layers.push(
        vec![
            tracing_layer!(layer()),
            log_layer!(layer()).with_filter(LevelFilter::WARN).boxed(),
            log_layer!(layer().with_writer(stdout))
                .with_filter(filter_fn(|metadata| *metadata.level() > Level::WARN))
                .boxed(),
        ]
        .with_filter(console_filter)
        .boxed(),
    );

    #[cfg(feature = "tracing")]
    {
        layers.push(console_subscriber::ConsoleLayer::builder().spawn().boxed());
    }

    Ok(layers)
}

fn file_layers(
    config: FileLoggerConfig,
    reload: bool,
) -> anyhow::Result<(Vec<BoxLayer>, Option<NewFilterSender>)> {
    let mut layers = Vec::new();

    let level = config.level.map(|s| s.parse().unwrap());

    if matches!(level, Some(LevelFilter::OFF)) && !reload {
        return Ok((layers, None));
    }

    let (file_filter, file_filter_reloader) =
        tracing_subscriber::reload::Layer::<_, Registry>::new(parse_env_filter(level)?);

    let layer = |wrapper| {
        layer()
            .with_ansi(false)
            .with_writer(wrapper)
            .with_timer(get_logger_timer_rfc3339())
    };

    let wrapper = {
        let path = {
            let dir = config.dir.as_deref().unwrap_or(".");
            let file = config.file.as_deref().unwrap_or("easytier.log");
            let path = std::path::Path::new(dir).join(file);
            path.to_string_lossy().into_owned()
        };

        let builder = RollingFileAppenderBase::builder();
        let file_appender = builder
            .filename(path)
            .condition_daily()
            .max_filecount(config.count.unwrap_or(10))
            .condition_max_file_size(config.size_mb.unwrap_or(100) * 1024 * 1024)
            .build()
            .with_context(|| "failed to initialize rolling file appender")?;

        FileAppenderWrapper::new(file_appender)
    };

    layers.push(
        vec![
            tracing_layer!(layer(wrapper.clone())),
            log_layer!(layer(wrapper.clone())),
        ]
        .with_filter(file_filter)
        .boxed(),
    );

    if !reload {
        return Ok((layers, None));
    }

    let (tx, rx) = std::sync::mpsc::channel();

    // 初始化全局状态
    let _ = LOGGER_LEVEL_SENDER.set(std::sync::Mutex::new(tx.clone()));
    if let Some(level) = level {
        let _ = CURRENT_LOG_LEVEL.set(std::sync::Mutex::new(level.to_string()));
    }

    std::thread::spawn(move || {
        while let Ok(lf) = rx.recv() {
            let parsed_level = match lf.parse::<LevelFilter>() {
                Ok(level) => level,
                Err(e) => {
                    error!("Failed to parse new log level {:?}: {}", lf, e);
                    continue;
                }
            };

            let mut new_filter = match EnvFilter::builder()
                .with_default_directive(parsed_level.into())
                .from_env()
                .with_context(|| "failed to create file filter")
            {
                Ok(filter) => Some(filter),
                Err(e) => {
                    error!("Failed to build new log filter for {:?}: {:?}", lf, e);
                    continue;
                }
            };

            match file_filter_reloader.modify(|f| {
                *f = new_filter
                    .take()
                    .expect("log filter reloader only applies one filter per reload");
            }) {
                Ok(()) => {
                    info!("Reload log filter succeed, new filter level: {:?}", lf);
                }
                Err(e) => {
                    error!("Failed to reload log filter: {:?}", e);
                }
            }
        }
        info!("Stop log filter reloader");
    });

    Ok((layers, Some(tx)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::config::FileLoggerConfig;

    #[ctor::ctor]
    fn init() {
        let _ = Registry::default()
            .with(console_layers(Some(LevelFilter::WARN)).unwrap())
            .try_init();
    }

    #[test]
    fn test_logger_reload() {
        let temp_dir = tempfile::tempdir().unwrap();
        let log_file_name = "reload-test.log".to_string();
        let log_path = temp_dir.path().join(&log_file_name);

        let cfg = FileLoggerConfig {
            level: Some(LevelFilter::INFO.to_string()),
            file: Some(log_file_name),
            dir: Some(temp_dir.path().to_string_lossy().to_string()),
            size_mb: Some(10),
            count: Some(1),
        };

        let (layers, sender) = file_layers(cfg, true).unwrap();
        let sender = sender.expect("reload=true should return a sender");

        let before_marker = "reload-before-debug-marker";
        let after_marker = "reload-after-debug-marker";
        let subscriber = Registry::default().with(layers);

        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("{}", before_marker);

            sender.send(LevelFilter::DEBUG.to_string()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));

            tracing::debug!("{}", after_marker);
            std::thread::sleep(std::time::Duration::from_millis(300));
        });

        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            !content.contains(before_marker),
            "debug log should be filtered before reload"
        );
        assert!(
            content.contains(after_marker),
            "debug log should be visible after reload"
        );
    }
}
