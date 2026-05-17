use crate::common::config::{FileLoggerConfig, LoggingConfigLoader};
use crate::common::get_logger_timer_rfc3339;
use crate::common::tracing_rolling_appender::{FileAppenderWrapper, RollingFileAppenderBase};
use crate::rpc_service::logger::{CURRENT_LOG_LEVEL, LOGGER_LEVEL_SENDER};
use anyhow::Context;
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

fn parse_static_filter(level: LevelFilter) -> Result<EnvFilter, anyhow::Error> {
    EnvFilter::builder()
        .with_default_directive(level.into())
        .parse("")
        .with_context(|| "failed to create static filter")
}

fn parse_file_filter(level: LevelFilter) -> Result<EnvFilter, anyhow::Error> {
    if matches!(level, LevelFilter::OFF) {
        parse_static_filter(level)
    } else {
        parse_env_filter(Some(level))
    }
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

    let (stdout, stderr) = cfg_select! {
        test => {{
            let w = tracing_subscriber::fmt::TestWriter::new;
            (w, w)
        }}
        _ => (std::io::stdout, std::io::stderr),
    };

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

    let level = config
        .level
        .map(|s| s.parse().unwrap())
        .unwrap_or(LevelFilter::OFF);

    if matches!(level, LevelFilter::OFF) && !reload {
        return Ok((layers, None));
    }

    let (file_filter, file_filter_reloader) =
        tracing_subscriber::reload::Layer::<_, Registry>::new(parse_file_filter(level)?);

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
    let _ = CURRENT_LOG_LEVEL.set(std::sync::Mutex::new(level.to_string()));

    std::thread::spawn(move || {
        while let Ok(lf) = rx.recv() {
            let parsed_level = match lf.parse::<LevelFilter>() {
                Ok(level) => level,
                Err(e) => {
                    error!("Failed to parse new log level {:?}: {}", lf, e);
                    continue;
                }
            };

            let mut new_filter = match parse_file_filter(parsed_level) {
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

    const RUST_LOG: &str = "RUST_LOG";

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::set_var(key, value) };
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            unsafe { std::env::remove_var(key) };
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => unsafe { std::env::set_var(self.key, value) },
                None => unsafe { std::env::remove_var(self.key) },
            }
        }
    }

    #[ctor::ctor]
    fn init() {
        let _ = Registry::default()
            .with(console_layers(Some(LevelFilter::WARN)).unwrap())
            .try_init();
    }

    #[test]
    fn default_file_logger_level_is_off_without_reload() {
        let (layers, sender) = file_layers(FileLoggerConfig::default(), false).unwrap();

        assert!(layers.is_empty());
        assert!(sender.is_none());
    }

    #[test]
    #[serial_test::serial]
    fn default_file_logger_level_filters_info_with_reload() {
        let _guard = EnvVarGuard::set(RUST_LOG, "info");
        let temp_dir = tempfile::tempdir().unwrap();
        let log_file_name = "default-off-test.log".to_string();
        let log_path = temp_dir.path().join(&log_file_name);

        let cfg = FileLoggerConfig {
            file: Some(log_file_name),
            dir: Some(temp_dir.path().to_string_lossy().to_string()),
            ..Default::default()
        };

        let (layers, _sender) = file_layers(cfg, true).unwrap();
        let marker = "default-file-logger-off-marker";
        let subscriber = Registry::default().with(layers);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(target: LOG_TARGET, "{}", marker);
            std::thread::sleep(std::time::Duration::from_millis(300));
        });

        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            !content.contains(marker),
            "default file logger level should filter info logs"
        );
    }

    #[test]
    #[serial_test::serial]
    fn file_logger_level_uses_env_filter_when_enabled() {
        let _guard = EnvVarGuard::set(RUST_LOG, "debug");
        let temp_dir = tempfile::tempdir().unwrap();
        let log_file_name = "env-filter-test.log".to_string();
        let log_path = temp_dir.path().join(&log_file_name);

        let cfg = FileLoggerConfig {
            level: Some(LevelFilter::INFO.to_string()),
            file: Some(log_file_name),
            dir: Some(temp_dir.path().to_string_lossy().to_string()),
            ..Default::default()
        };

        let (layers, _sender) = file_layers(cfg, true).unwrap();
        let marker = "file-logger-env-filter-marker";
        let subscriber = Registry::default().with(layers);

        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!(target: LOG_TARGET, "{}", marker);
            std::thread::sleep(std::time::Duration::from_millis(300));
        });

        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            content.contains(marker),
            "enabled file logger should use RUST_LOG directives"
        );
    }

    #[test]
    #[serial_test::serial]
    fn file_logger_reload_uses_env_filter_when_enabled() {
        let _guard = EnvVarGuard::set(RUST_LOG, "debug");
        let temp_dir = tempfile::tempdir().unwrap();
        let log_file_name = "reload-env-filter-test.log".to_string();
        let log_path = temp_dir.path().join(&log_file_name);

        let cfg = FileLoggerConfig {
            file: Some(log_file_name),
            dir: Some(temp_dir.path().to_string_lossy().to_string()),
            ..Default::default()
        };

        let (layers, sender) = file_layers(cfg, true).unwrap();
        let sender = sender.expect("reload=true should return a sender");
        let marker = "file-logger-reload-env-filter-marker";
        let subscriber = Registry::default().with(layers);

        tracing::subscriber::with_default(subscriber, || {
            sender.send(LevelFilter::INFO.to_string()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));

            tracing::debug!(target: LOG_TARGET, "{}", marker);
            std::thread::sleep(std::time::Duration::from_millis(300));
        });

        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            content.contains(marker),
            "file logger enabled by reload should use RUST_LOG directives"
        );
    }

    #[test]
    #[serial_test::serial]
    fn file_logger_reload_off_ignores_env_filter() {
        let _guard = EnvVarGuard::set(RUST_LOG, "info");
        let temp_dir = tempfile::tempdir().unwrap();
        let log_file_name = "reload-off-test.log".to_string();
        let log_path = temp_dir.path().join(&log_file_name);

        let cfg = FileLoggerConfig {
            level: Some(LevelFilter::INFO.to_string()),
            file: Some(log_file_name),
            dir: Some(temp_dir.path().to_string_lossy().to_string()),
            ..Default::default()
        };

        let (layers, sender) = file_layers(cfg, true).unwrap();
        let sender = sender.expect("reload=true should return a sender");
        let marker = "file-logger-reload-off-marker";
        let subscriber = Registry::default().with(layers);

        tracing::subscriber::with_default(subscriber, || {
            sender.send(LevelFilter::OFF.to_string()).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(300));

            tracing::info!(target: LOG_TARGET, "{}", marker);
            std::thread::sleep(std::time::Duration::from_millis(300));
        });

        let content = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            !content.contains(marker),
            "disabled file logger should ignore RUST_LOG directives"
        );
    }

    #[test]
    #[serial_test::serial]
    fn test_logger_reload() {
        let _guard = EnvVarGuard::unset(RUST_LOG);
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
