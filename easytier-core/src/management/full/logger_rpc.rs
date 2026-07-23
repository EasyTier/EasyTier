use std::sync::Arc;

use easytier_proto::{
    api::logger::{
        GetLoggerConfigRequest, GetLoggerConfigResponse, LogLevel, LoggerRpc,
        SetLoggerConfigRequest, SetLoggerConfigResponse,
    },
    rpc_types::{self, controller::BaseController},
};

pub trait LoggerControl: Send + Sync + 'static {
    fn set_level(&self, level: &str) -> anyhow::Result<()>;

    fn level(&self) -> String;
}

#[derive(Default)]
pub struct UnsupportedLoggerControl;

impl LoggerControl for UnsupportedLoggerControl {
    fn set_level(&self, _level: &str) -> anyhow::Result<()> {
        anyhow::bail!("logger control is unsupported by this Host")
    }

    fn level(&self) -> String {
        "info".to_owned()
    }
}

#[derive(Clone)]
pub struct LoggerManagementRpc {
    control: Arc<dyn LoggerControl>,
}

impl LoggerManagementRpc {
    pub fn new(control: Arc<dyn LoggerControl>) -> Self {
        Self { control }
    }
}

pub fn log_level_name(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Disabled => "off",
        LogLevel::Error => "error",
        LogLevel::Warning => "warn",
        LogLevel::Info => "info",
        LogLevel::Debug => "debug",
        LogLevel::Trace => "trace",
    }
}

pub fn parse_log_level(level: &str) -> LogLevel {
    match level.to_ascii_lowercase().as_str() {
        "off" | "disabled" => LogLevel::Disabled,
        "error" => LogLevel::Error,
        "warn" | "warning" => LogLevel::Warning,
        "debug" => LogLevel::Debug,
        "trace" => LogLevel::Trace,
        _ => LogLevel::Info,
    }
}

#[async_trait::async_trait]
impl LoggerRpc for LoggerManagementRpc {
    type Controller = BaseController;

    async fn set_logger_config(
        &self,
        _: BaseController,
        request: SetLoggerConfigRequest,
    ) -> rpc_types::error::Result<SetLoggerConfigResponse> {
        self.control.set_level(log_level_name(request.level()))?;
        Ok(SetLoggerConfigResponse {})
    }

    async fn get_logger_config(
        &self,
        _: BaseController,
        _: GetLoggerConfigRequest,
    ) -> rpc_types::error::Result<GetLoggerConfigResponse> {
        Ok(GetLoggerConfigResponse {
            level: parse_log_level(&self.control.level()).into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct TestLoggerControl(Mutex<String>);

    impl LoggerControl for TestLoggerControl {
        fn set_level(&self, level: &str) -> anyhow::Result<()> {
            *self.0.lock().unwrap() = level.to_owned();
            Ok(())
        }

        fn level(&self) -> String {
            self.0.lock().unwrap().clone()
        }
    }

    #[tokio::test]
    async fn logger_rpc_delegates_process_effects_to_host_control() {
        let rpc = LoggerManagementRpc::new(Arc::new(TestLoggerControl::default()));

        rpc.set_logger_config(
            BaseController::default(),
            SetLoggerConfigRequest {
                level: LogLevel::Debug.into(),
            },
        )
        .await
        .unwrap();
        let response = rpc
            .get_logger_config(BaseController::default(), GetLoggerConfigRequest {})
            .await
            .unwrap();

        assert_eq!(response.level(), LogLevel::Debug);
    }
}
