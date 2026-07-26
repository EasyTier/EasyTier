use easytier_core::management::LoggerControl;

#[derive(Clone, Default)]
pub struct NativeLoggerControl;

impl LoggerControl for NativeLoggerControl {
    fn set_level(&self, level: &str) -> anyhow::Result<()> {
        crate::common::log::set_file_level(level)
    }

    fn level(&self) -> String {
        crate::common::log::file_level()
    }
}
