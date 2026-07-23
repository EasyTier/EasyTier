use std::{
    fmt::{self, Write as _},
    io::{self, IsTerminal, Write as _},
    sync::{
        OnceLock,
        atomic::{AtomicU8, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use log::{Level, LevelFilter, Metadata as LogMetadata, Record as LogRecord};
use paste::paste;
use tracing::{
    Event,
    field::{Field, Visit},
};

#[cfg(feature = "management")]
mod file;
#[cfg(not(feature = "management"))]
#[path = "file_disabled.rs"]
mod file;
#[cfg(feature = "management")]
mod management;
#[cfg(feature = "management")]
pub use management::init;
#[cfg(feature = "tracing")]
#[path = "tracing_console.rs"]
mod tracing_backend;
#[cfg(not(feature = "tracing"))]
#[path = "tracing_default.rs"]
mod tracing_backend;

use file::FileSink;

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

static LOGGER: OnceLock<Logger> = OnceLock::new();

pub fn init_console() -> anyhow::Result<()> {
    install(Logger::new(
        TargetFilter::console(Some(LevelFilter::Info))?,
        FileSink::disabled(),
    ))
}

pub fn set_file_level(level: &str) -> anyhow::Result<()> {
    let level = parse_level(level).context("invalid file log level")?;
    LOGGER
        .get()
        .context("logger is not initialized")?
        .set_file_level(level)
}

pub fn file_level() -> String {
    LOGGER
        .get()
        .map(Logger::file_level)
        .unwrap_or(LevelFilter::Info)
        .to_string()
        .to_ascii_lowercase()
}

fn install(logger: Logger) -> anyhow::Result<()> {
    LOGGER
        .set(logger)
        .map_err(|_| anyhow::anyhow!("logger is already initialized"))?;
    let logger = LOGGER.get().expect("logger was just initialized");

    log::set_logger(logger).map_err(|_| anyhow::anyhow!("a log logger is already installed"))?;
    log::set_max_level(logger.max_level());
    tracing_backend::install(logger).context("failed to install tracing subscriber")
}

fn parse_level(level: &str) -> anyhow::Result<LevelFilter> {
    level
        .parse()
        .map_err(|error| anyhow::anyhow!("{error}: {level:?}"))
}

#[derive(Clone, Debug)]
struct TargetFilter {
    default: LevelFilter,
    targets: Vec<(Box<str>, LevelFilter)>,
}

impl TargetFilter {
    fn console(level: Option<LevelFilter>) -> anyhow::Result<Self> {
        if level == Some(LevelFilter::Off) {
            return Ok(Self::off());
        }

        let fallback = match level {
            Some(level) => Self::with_default(level),
            None => Self {
                default: LevelFilter::Off,
                targets: vec![(LOG_TARGET.into(), LevelFilter::Info)],
            },
        };
        Self::from_environment(fallback)
    }

    fn off() -> Self {
        Self::with_default(LevelFilter::Off)
    }

    fn with_default(default: LevelFilter) -> Self {
        Self {
            default,
            targets: Vec::new(),
        }
    }

    fn from_environment(fallback: Self) -> anyhow::Result<Self> {
        let spec = std::env::var("RUST_LOG").unwrap_or_default();
        Self::parse(&spec).map(|filter| filter.unwrap_or(fallback))
    }

    fn parse(spec: &str) -> anyhow::Result<Option<Self>> {
        let mut filter = Self::off();
        let mut found = false;

        for directive in spec.split(',').map(str::trim).filter(|s| !s.is_empty()) {
            found = true;
            if directive.contains(['[', ']', '{', '}']) {
                anyhow::bail!(
                    "span and field filters are not supported in RUST_LOG: {directive:?}"
                );
            }

            if let Some((target, level)) = directive.rsplit_once('=') {
                let target = target.trim();
                if target.is_empty() {
                    anyhow::bail!("missing target in RUST_LOG directive: {directive:?}");
                }
                filter
                    .targets
                    .push((target.into(), parse_level(level.trim())?));
            } else if let Ok(level) = directive.parse() {
                filter.default = level;
            } else {
                if directive.chars().any(char::is_whitespace) {
                    anyhow::bail!("invalid RUST_LOG directive: {directive:?}");
                }
                filter.targets.push((directive.into(), LevelFilter::Trace));
            }
        }

        Ok(found.then_some(filter))
    }

    fn enabled(&self, target: &str, level: Level) -> bool {
        let mut selected = self.default;
        let mut selected_len = 0;
        for (prefix, filter) in &self.targets {
            if prefix.len() >= selected_len && target.starts_with(prefix.as_ref()) {
                selected = *filter;
                selected_len = prefix.len();
            }
        }
        selected >= level.to_level_filter()
    }

    fn max_level(&self) -> LevelFilter {
        self.targets
            .iter()
            .map(|(_, level)| *level)
            .fold(self.default, std::cmp::max)
    }
}

struct Logger {
    console: TargetFilter,
    console_max_level: u8,
    active_max_level: AtomicU8,
    color: bool,
    file: FileSink,
}

impl Logger {
    fn new(console: TargetFilter, file: FileSink) -> Self {
        let console_max_level = level_rank(console.max_level());
        let active_max_level = console_max_level.max(file.max_level_rank());
        Self {
            console,
            console_max_level,
            active_max_level: AtomicU8::new(active_max_level),
            color: io::stderr().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
            file,
        }
    }

    fn enabled(&self, target: &str, level: Level) -> bool {
        level_is_enabled(self.active_max_level.load(Ordering::Acquire), level)
            && (self.console_enabled(target, level) || self.file.enabled(target, level))
    }

    fn console_enabled(&self, target: &str, level: Level) -> bool {
        level_is_enabled(self.console_max_level, level) && self.console.enabled(target, level)
    }

    fn max_level(&self) -> LevelFilter {
        self.console.max_level().max(self.file.max_level())
    }

    fn emit(&self, level: Level, target: &str, message: &str) {
        let console_enabled = self.console_enabled(target, level);
        let file_enabled = self.file.enabled(target, level);
        if !console_enabled && !file_enabled {
            return;
        }

        let timestamp = timestamp_rfc3339_utc();
        if console_enabled {
            let line = format_line(&timestamp, level, target, message, self.color);
            let _ = if matches!(level, Level::Error | Level::Warn) {
                io::stderr().lock().write_all(line.as_bytes())
            } else {
                io::stdout().lock().write_all(line.as_bytes())
            };
        }

        if file_enabled {
            self.file.emit(&timestamp, level, target, message);
        }
    }

    fn set_file_level(&self, level: LevelFilter) -> anyhow::Result<()> {
        self.file
            .set_level(level, self.console.max_level(), &self.active_max_level)
    }

    fn file_level(&self) -> LevelFilter {
        self.file.level()
    }

    fn flush_file(&self) {
        self.file.flush();
    }
}

fn level_rank(level: LevelFilter) -> u8 {
    match level {
        LevelFilter::Off => 0,
        LevelFilter::Error => 1,
        LevelFilter::Warn => 2,
        LevelFilter::Info => 3,
        LevelFilter::Debug => 4,
        LevelFilter::Trace => 5,
    }
}

fn level_is_enabled(max_level: u8, level: Level) -> bool {
    max_level >= level_rank(level.to_level_filter())
}

impl log::Log for Logger {
    fn enabled(&self, metadata: &LogMetadata<'_>) -> bool {
        self.enabled(metadata.target(), metadata.level())
    }

    fn log(&self, record: &LogRecord<'_>) {
        if self.enabled(record.target(), record.level()) {
            self.emit(record.level(), record.target(), &record.args().to_string());
        }
    }

    fn flush(&self) {
        self.flush_file();
    }
}

fn format_line(timestamp: &str, level: Level, target: &str, message: &str, color: bool) -> String {
    let mut line = String::with_capacity(timestamp.len() + target.len() + message.len() + 32);
    if color {
        let color = match level {
            Level::Error => "\x1b[31m",
            Level::Warn => "\x1b[33m",
            Level::Info => "\x1b[32m",
            Level::Debug => "\x1b[34m",
            Level::Trace => "\x1b[90m",
        };
        let _ = writeln!(
            line,
            "{timestamp} {color}{level:<5}\x1b[0m {target}: {message}"
        );
    } else {
        let _ = writeln!(line, "{timestamp} {level:<5} {target}: {message}");
    }
    line
}

fn timestamp_rfc3339_utc() -> String {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let seconds = duration.as_secs();
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_date_from_unix_days((seconds / 86_400) as i64);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;

    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        duration.subsec_millis()
    )
}

fn civil_date_from_unix_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = if days >= 0 { days } else { days - 146_096 } / 146_097;
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month, day)
}

fn tracing_level(level: &tracing::Level) -> Level {
    match *level {
        tracing::Level::ERROR => Level::Error,
        tracing::Level::WARN => Level::Warn,
        tracing::Level::INFO => Level::Info,
        tracing::Level::DEBUG => Level::Debug,
        tracing::Level::TRACE => Level::Trace,
    }
}

fn emit_event(logger: &Logger, event: &Event<'_>) {
    let metadata = event.metadata();
    let level = tracing_level(metadata.level());
    if !logger.enabled(metadata.target(), level) {
        return;
    }

    let mut fields = EventFields::default();
    event.record(&mut fields);
    logger.emit(level, metadata.target(), &fields.finish());
}

#[derive(Default)]
struct EventFields {
    message: Option<String>,
    fields: String,
}

impl EventFields {
    fn write_field(&mut self, field: &Field, value: impl fmt::Display) {
        if !self.fields.is_empty() {
            self.fields.push(' ');
        }
        let _ = write!(self.fields, "{}={value}", field.name());
    }

    fn finish(self) -> String {
        match (self.message, self.fields.is_empty()) {
            (Some(message), false) => format!("{message} {}", self.fields),
            (Some(message), true) => message,
            (None, _) => self.fields,
        }
    }
}

impl Visit for EventFields {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            self.write_field(field, format_args!("{value:?}"));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_owned());
        } else {
            self.write_field(field, format_args!("{value:?}"));
        }
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.write_field(field, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "management")]
    use crate::common::config::FileLoggerConfig;

    struct EnvVarGuard {
        previous: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(value: Option<&str>) -> Self {
            let previous = std::env::var_os("RUST_LOG");
            match value {
                Some(value) => unsafe { std::env::set_var("RUST_LOG", value) },
                None => unsafe { std::env::remove_var("RUST_LOG") },
            }
            Self { previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => unsafe { std::env::set_var("RUST_LOG", value) },
                None => unsafe { std::env::remove_var("RUST_LOG") },
            }
        }
    }

    #[test]
    #[serial_test::serial]
    fn default_console_only_enables_core_info() {
        let _env = EnvVarGuard::set(None);
        let filter = TargetFilter::console(None).unwrap();

        assert!(filter.enabled("CORE::peer", Level::Info));
        assert!(!filter.enabled("CORE", Level::Debug));
        assert!(!filter.enabled("other", Level::Error));
    }

    #[test]
    fn rust_log_supports_global_and_target_levels() {
        let filter = TargetFilter::parse("warn,easytier_core=debug,hyper=off")
            .unwrap()
            .unwrap();

        assert!(filter.enabled("easytier_core::peers", Level::Debug));
        assert!(!filter.enabled("hyper::client", Level::Error));
        assert!(!filter.enabled("other", Level::Info));
        assert!(filter.enabled("other", Level::Warn));
    }

    #[test]
    fn rust_log_target_without_level_enables_trace() {
        let filter = TargetFilter::parse("easytier_core").unwrap().unwrap();

        assert!(filter.enabled("easytier_core::peer", Level::Trace));
        assert!(!filter.enabled("other", Level::Error));
    }

    #[test]
    fn formatting_is_compact_and_color_is_optional() {
        let plain = format_line(
            "2026-07-22T12:00:00+08:00",
            Level::Info,
            "CORE",
            "ready",
            false,
        );
        let colored = format_line(
            "2026-07-22T12:00:00+08:00",
            Level::Info,
            "CORE",
            "ready",
            true,
        );

        assert_eq!(plain, "2026-07-22T12:00:00+08:00 INFO  CORE: ready\n");
        assert!(colored.contains("\x1b[32mINFO \x1b[0m"));
    }

    #[test]
    fn unix_day_conversion_matches_known_dates() {
        assert_eq!(civil_date_from_unix_days(0), (1970, 1, 1));
        assert_eq!(civil_date_from_unix_days(20_656), (2026, 7, 22));
    }

    #[test]
    #[cfg(feature = "management")]
    fn default_file_logger_is_not_opened_without_reload() {
        let file = FileSink::from_config(FileLoggerConfig::default(), false).unwrap();
        assert!(!file.is_open());
    }

    #[test]
    #[cfg(feature = "management")]
    #[serial_test::serial]
    fn file_logger_uses_rust_log_when_enabled() {
        let _env = EnvVarGuard::set(Some("debug"));
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("env-filter.log");
        let config = FileLoggerConfig {
            level: Some("info".to_owned()),
            file: Some("env-filter.log".to_owned()),
            dir: Some(temp_dir.path().to_string_lossy().into_owned()),
            ..Default::default()
        };
        let file = FileSink::from_config(config, true).unwrap();
        let logger = Logger::new(TargetFilter::off(), file);

        logger.emit(Level::Debug, LOG_TARGET, "env-filter-marker");
        logger.flush_file();

        let content = std::fs::read_to_string(log_path).unwrap();
        assert!(content.contains("env-filter-marker"));
    }

    #[test]
    #[cfg(feature = "management")]
    #[serial_test::serial]
    fn reloading_file_logger_preserves_rust_log_and_supports_off() {
        let _env = EnvVarGuard::set(Some("debug"));
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("reload.log");
        let config = FileLoggerConfig {
            file: Some("reload.log".to_owned()),
            dir: Some(temp_dir.path().to_string_lossy().into_owned()),
            ..Default::default()
        };
        let file = FileSink::from_config(config, true).unwrap();
        let logger = std::sync::Arc::new(Logger::new(TargetFilter::off(), file));

        assert_eq!(
            logger.active_max_level.load(Ordering::Relaxed),
            level_rank(LevelFilter::Off)
        );

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
        let threads = (0..8)
            .map(|thread_index| {
                let logger = logger.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    for iteration in 0..500 {
                        let level = if (thread_index + iteration) % 2 == 0 {
                            LevelFilter::Info
                        } else {
                            LevelFilter::Off
                        };
                        logger.set_file_level(level).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }

        logger.file.assert_level_state(
            logger.console_max_level,
            logger.active_max_level.load(Ordering::Relaxed),
        );

        logger.set_file_level(LevelFilter::Info).unwrap();
        assert_eq!(
            logger.active_max_level.load(Ordering::Relaxed),
            level_rank(LevelFilter::Debug)
        );
        assert_eq!(logger.file.max_level_rank(), level_rank(LevelFilter::Debug));
        logger.emit(Level::Debug, LOG_TARGET, "enabled-by-env");
        logger.set_file_level(LevelFilter::Off).unwrap();
        assert_eq!(
            logger.active_max_level.load(Ordering::Relaxed),
            level_rank(LevelFilter::Off)
        );
        logger.emit(Level::Error, LOG_TARGET, "disabled-despite-env");
        logger.flush_file();

        let content = std::fs::read_to_string(log_path).unwrap();
        assert!(content.contains("enabled-by-env"));
        assert!(!content.contains("disabled-despite-env"));
        assert_eq!(logger.file_level(), LevelFilter::Off);
    }

    #[test]
    #[cfg(all(feature = "management", not(feature = "tracing")))]
    #[serial_test::serial]
    fn tracing_events_and_direct_log_records_share_the_file_sink() {
        let _env = EnvVarGuard::set(None);
        let temp_dir = tempfile::tempdir().unwrap();
        let log_path = temp_dir.path().join("shared-sink.log");
        let config = FileLoggerConfig {
            level: Some("info".to_owned()),
            file: Some("shared-sink.log".to_owned()),
            dir: Some(temp_dir.path().to_string_lossy().into_owned()),
            ..Default::default()
        };
        let file = FileSink::from_config(config, false).unwrap();
        let logger = Box::leak(Box::new(Logger::new(TargetFilter::off(), file)));
        let dispatch = tracing::Dispatch::new(tracing_backend::EventSubscriber::new(logger));

        tracing::dispatcher::with_default(&dispatch, || {
            let span = tracing::info_span!(target: LOG_TARGET, "ignored-span", peer = 7);
            let _entered = span.enter();
            tracing::info!(target: LOG_TARGET, answer = 42, "tracing-event");
        });
        log::Log::log(
            logger,
            &LogRecord::builder()
                .level(Level::Info)
                .target("dependency")
                .args(format_args!("direct-log-record"))
                .build(),
        );
        logger.flush_file();

        let content = std::fs::read_to_string(log_path).unwrap();
        assert!(content.contains("tracing-event answer=42"));
        assert!(content.contains("direct-log-record"));
        assert!(!content.contains("ignored-span"));
    }
}
