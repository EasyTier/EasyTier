//! Module-wide logging, initialized before any instance or WebClient is created.

use std::{
    fmt::Write as _,
    io::{self, Write},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, Ordering},
    },
};

#[cfg(target_os = "wasi")]
use std::sync::OnceLock;

use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    level_filters::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

// These values also match api.logger.LogLevel. Keep the basic WASI logger
// independent of the optional management protobuf API.
const LEVELS: [LevelFilter; 6] = [
    LevelFilter::OFF,
    LevelFilter::ERROR,
    LevelFilter::WARN,
    LevelFilter::INFO,
    LevelFilter::DEBUG,
    LevelFilter::TRACE,
];

struct Logger<W> {
    level: AtomicU8,
    writer: Mutex<W>,
}

impl<W> Logger<W> {
    fn new(writer: W) -> Self {
        Self {
            level: AtomicU8::new(3),
            writer: Mutex::new(writer),
        }
    }

    fn set_level(&self, level: u32) -> bool {
        if level >= LEVELS.len() as u32 {
            return false;
        }
        self.level.store(level as u8, Ordering::Relaxed);
        true
    }

    fn level(&self) -> u32 {
        u32::from(self.level.load(Ordering::Relaxed))
    }
}

impl<W: Write + Send + 'static> Subscriber for Logger<W> {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_event() && *metadata.level() <= LEVELS[self.level() as usize]
    }

    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if metadata.is_event() {
            Interest::sometimes()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        // The host can enable trace after a callsite has already been visited.
        Some(LevelFilter::TRACE)
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        struct Fields(String);

        impl Visit for Fields {
            fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
                let _ = write!(self.0, " {}={value:?}", field.name());
            }
        }

        let mut fields = Fields(String::new());
        event.record(&mut fields);
        // A host logging sink may fail; that must not trap the guest runtime.
        let _ = writeln!(
            self.writer.lock().unwrap(),
            "[{}] {}{}",
            event.metadata().level(),
            event.metadata().target(),
            fields.0,
        );
    }
}

#[cfg(target_os = "wasi")]
fn logger() -> &'static Arc<Logger<io::Stdout>> {
    static LOGGER: OnceLock<Arc<Logger<io::Stdout>>> = OnceLock::new();
    LOGGER.get_or_init(|| {
        let logger = Arc::new(Logger::new(io::stdout()));
        tracing::subscriber::set_global_default(logger.clone())
            .expect("WASI runtime owns the tracing subscriber");
        logger
    })
}

#[cfg(target_os = "wasi")]
pub(super) fn init() {
    logger();
}

/// Sets the module-wide level without requiring an instance handle.
/// Values 0..=5 mean off, error, warn, info, debug, and trace.
/// Invalid values return -3 and leave the current level unchanged.
#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn easytier_logger_set_level(level: u32) -> i32 {
    if logger().set_level(level) { 0 } else { -3 }
}

/// Returns the module-wide level using the same values as the setter.
#[cfg(target_os = "wasi")]
#[unsafe(no_mangle)]
pub extern "C" fn easytier_logger_level() -> u32 {
    logger().level()
}

#[cfg(feature = "management")]
impl<W: Write + Send + 'static> crate::management::LoggerControl for Logger<W> {
    fn set_level(&self, name: &str) -> anyhow::Result<()> {
        let filter = name.parse::<LevelFilter>()?;
        let level = LEVELS
            .iter()
            .position(|level| *level == filter)
            .expect("every tracing level has an ABI value");
        self.set_level(level as u32);
        Ok(())
    }

    fn level(&self) -> String {
        LEVELS[self.level() as usize]
            .to_string()
            .to_ascii_lowercase()
    }
}

#[cfg(all(target_os = "wasi", feature = "management"))]
pub(super) fn control() -> Arc<dyn crate::management::LoggerControl> {
    logger().clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Default)]
    struct Output(Arc<Mutex<Vec<u8>>>);

    impl Write for Output {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn emit() {
        tracing::error!(target: "logger_test", "error");
        tracing::info!(target: "logger_test", "info");
        tracing::trace!(target: "logger_test", "trace");
    }

    #[test]
    fn changing_level_rechecks_existing_callsites() {
        let output = Output::default();
        let logger = Arc::new(Logger::new(output.clone()));
        tracing::subscriber::with_default(logger.clone(), || {
            for (level, expected) in [
                (3, vec!["error", "info"]),
                (5, vec!["error", "info", "trace"]),
                (0, vec![]),
                (3, vec!["error", "info"]),
            ] {
                assert!(logger.set_level(level));
                output.0.lock().unwrap().clear();
                emit();
                let bytes = output.0.lock().unwrap();
                let text = std::str::from_utf8(&bytes).unwrap();
                let messages = text
                    .lines()
                    .map(|line| line.split_once("message=").unwrap().1)
                    .collect::<Vec<_>>();
                assert_eq!(messages, expected);
            }
        });
    }

    #[test]
    fn invalid_level_preserves_current_filter() {
        let logger = Logger::new(io::sink());
        assert_eq!(logger.level(), 3);
        for level in [6, 256, u32::MAX] {
            assert!(!logger.set_level(level));
            assert_eq!(logger.level(), 3);
        }
    }

    #[test]
    fn output_errors_do_not_panic() {
        struct BrokenWriter;

        impl Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        tracing::subscriber::with_default(Logger::new(BrokenWriter), emit);
    }

    #[cfg(feature = "management")]
    #[test]
    fn management_control_uses_the_same_filter() {
        let logger = Logger::new(io::sink());
        let control: &dyn crate::management::LoggerControl = &logger;
        control.set_level("trace").unwrap();
        assert_eq!(logger.level(), 5);
        assert!(logger.set_level(0));
        assert_eq!(control.level(), "off");
        assert!(control.set_level("invalid").is_err());
        assert_eq!(logger.level(), 0);
    }
}
