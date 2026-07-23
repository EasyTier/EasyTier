use std::sync::atomic::AtomicU8;

use log::{Level, LevelFilter};

use super::level_rank;

pub(super) struct FileSink;

impl FileSink {
    pub(super) fn disabled() -> Self {
        Self
    }

    pub(super) fn enabled(&self, _target: &str, _level: Level) -> bool {
        false
    }

    pub(super) fn max_level(&self) -> LevelFilter {
        LevelFilter::Off
    }

    pub(super) fn max_level_rank(&self) -> u8 {
        level_rank(LevelFilter::Off)
    }

    pub(super) fn dynamic(&self) -> bool {
        false
    }

    pub(super) fn emit(&self, _timestamp: &str, _level: Level, _target: &str, _message: &str) {}

    pub(super) fn set_level(
        &self,
        _level: LevelFilter,
        _console_max_level: LevelFilter,
        _active_max_level: &AtomicU8,
    ) -> anyhow::Result<()> {
        anyhow::bail!("file logging is not available in this build")
    }

    pub(super) fn level(&self) -> LevelFilter {
        LevelFilter::Info
    }

    pub(super) fn flush(&self) {}
}
