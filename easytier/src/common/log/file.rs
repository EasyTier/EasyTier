use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::Context as _;
use log::{Level, LevelFilter};

use crate::common::{
    config::FileLoggerConfig,
    tracing_rolling_appender::{FileAppenderWrapper, RollingFileAppenderBase},
};

use super::{TargetFilter, format_line, level_is_enabled, level_rank, parse_level};

pub(super) struct FileSink {
    output: Option<FileOutput>,
    reload: bool,
}

struct FileOutput {
    appender: FileAppenderWrapper,
    max_level: AtomicU8,
    state: parking_lot::RwLock<FileState>,
}

struct FileState {
    level: LevelFilter,
    filter: TargetFilter,
}

impl FileSink {
    pub(super) fn disabled() -> Self {
        Self {
            output: None,
            reload: false,
        }
    }

    pub(super) fn from_config(config: FileLoggerConfig, reload: bool) -> anyhow::Result<Self> {
        let level = config
            .level
            .as_deref()
            .map(parse_level)
            .transpose()
            .context("invalid file log level")?
            .unwrap_or(LevelFilter::Off);
        if level == LevelFilter::Off && !reload {
            return Ok(Self::disabled());
        }

        let dir = config.dir.as_deref().unwrap_or(".");
        let file = config.file.as_deref().unwrap_or("easytier.log");
        let path = std::path::Path::new(dir).join(file);
        let file_appender = RollingFileAppenderBase::builder()
            .filename(path.to_string_lossy().into_owned())
            .condition_daily()
            .max_filecount(config.count.unwrap_or(10))
            .condition_max_file_size(config.size_mb.unwrap_or(100) * 1024 * 1024)
            .build()
            .context("failed to initialize rolling file appender")?;

        let filter = file_filter(level)?;
        let max_level = AtomicU8::new(level_rank(filter.max_level()));
        Ok(Self {
            output: Some(FileOutput {
                appender: FileAppenderWrapper::new(file_appender),
                max_level,
                state: parking_lot::RwLock::new(FileState { level, filter }),
            }),
            reload,
        })
    }

    pub(super) fn enabled(&self, target: &str, level: Level) -> bool {
        self.output.as_ref().is_some_and(|output| {
            level_is_enabled(output.max_level.load(Ordering::Acquire), level)
                && output.state.read().filter.enabled(target, level)
        })
    }

    pub(super) fn max_level(&self) -> LevelFilter {
        self.output
            .as_ref()
            .map(|output| output.state.read().filter.max_level())
            .unwrap_or(LevelFilter::Off)
    }

    pub(super) fn max_level_rank(&self) -> u8 {
        self.output
            .as_ref()
            .map(|output| output.max_level.load(Ordering::Relaxed))
            .unwrap_or_else(|| level_rank(LevelFilter::Off))
    }

    pub(super) fn dynamic(&self) -> bool {
        self.reload && self.output.is_some()
    }

    pub(super) fn emit(&self, timestamp: &str, level: Level, target: &str, message: &str) {
        if let Some(output) = &self.output {
            let line = format_line(timestamp, level, target, message, false);
            let _ = output.appender.write_all(line.as_bytes());
        }
    }

    pub(super) fn set_level(
        &self,
        level: LevelFilter,
        console_max_level: LevelFilter,
        active_max_level: &AtomicU8,
    ) -> anyhow::Result<()> {
        let output = self
            .output
            .as_ref()
            .filter(|_| self.reload)
            .context("logger reloader is not initialized")?;
        let filter = file_filter(level)?;
        let file_max_filter = filter.max_level();
        let file_max_level = level_rank(file_max_filter);
        let active_max_filter = console_max_level.max(file_max_filter);

        let mut state = output.state.write();
        *state = FileState { level, filter };
        output.max_level.store(file_max_level, Ordering::Release);
        active_max_level.store(level_rank(active_max_filter), Ordering::Release);
        log::set_max_level(active_max_filter);
        drop(state);
        Ok(())
    }

    pub(super) fn level(&self) -> LevelFilter {
        self.output
            .as_ref()
            .map(|output| output.state.read().level)
            .unwrap_or(LevelFilter::Info)
    }

    pub(super) fn flush(&self) {
        if let Some(output) = &self.output {
            let _ = output.appender.flush();
        }
    }

    #[cfg(test)]
    pub(super) fn is_open(&self) -> bool {
        self.output.is_some()
    }

    #[cfg(test)]
    pub(super) fn assert_level_state(&self, console_max_level: u8, active_max_level: u8) {
        let output = self.output.as_ref().expect("file logger is open");
        let state = output.state.read();
        let file_max_level = level_rank(state.filter.max_level());
        assert_eq!(output.max_level.load(Ordering::Relaxed), file_max_level);
        assert_eq!(active_max_level, console_max_level.max(file_max_level));
        assert_eq!(
            level_rank(log::max_level()),
            console_max_level.max(file_max_level)
        );
    }
}

fn file_filter(level: LevelFilter) -> anyhow::Result<TargetFilter> {
    if level == LevelFilter::Off {
        Ok(TargetFilter::off())
    } else {
        TargetFilter::from_environment(TargetFilter::with_default(level))
    }
}
