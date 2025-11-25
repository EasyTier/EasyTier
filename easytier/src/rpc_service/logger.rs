use std::sync::{mpsc::Sender, Mutex, OnceLock};

use crate::proto::{
    api::logger::{
        GetLoggerConfigRequest, GetLoggerConfigResponse, LogLevel, LoggerRpc,
        SetLoggerConfigRequest, SetLoggerConfigResponse,
    },
    rpc_types::{self, controller::BaseController},
};

pub static LOGGER_LEVEL_SENDER: std::sync::OnceLock<Mutex<Sender<String>>> = OnceLock::new();
pub static CURRENT_LOG_LEVEL: std::sync::OnceLock<Mutex<String>> = OnceLock::new();

#[derive(Clone, Default)]
pub struct LoggerRpcService;

impl LoggerRpcService {
    fn log_level_to_string(level: LogLevel) -> String {
        match level {
            LogLevel::Disabled => "off".to_string(),
            LogLevel::Error => "error".to_string(),
            LogLevel::Warning => "warn".to_string(),
            LogLevel::Info => "info".to_string(),
            LogLevel::Debug => "debug".to_string(),
            LogLevel::Trace => "trace".to_string(),
        }
    }

    pub fn string_to_log_level(level_str: &str) -> LogLevel {
        match level_str.to_lowercase().as_str() {
            "off" | "disabled" => LogLevel::Disabled,
            "error" => LogLevel::Error,
            "warn" | "warning" => LogLevel::Warning,
            "info" => LogLevel::Info,
            "debug" => LogLevel::Debug,
            "trace" => LogLevel::Trace,
            _ => LogLevel::Info, // 默认为 Info 级别
        }
    }
}

#[async_trait::async_trait]
impl LoggerRpc for LoggerRpcService {
    type Controller = BaseController;

    async fn set_logger_config(
        &self,
        _: BaseController,
        request: SetLoggerConfigRequest,
    ) -> Result<SetLoggerConfigResponse, rpc_types::error::Error> {
        let level_str = Self::log_level_to_string(request.level());

        // 更新当前日志级别
        if let Some(current_level) = CURRENT_LOG_LEVEL.get() {
            if let Ok(mut level) = current_level.lock() {
                *level = level_str.clone();
            }
        }

        // 发送新的日志级别到 logger 重载器
        if let Some(sender) = LOGGER_LEVEL_SENDER.get() {
            if let Ok(sender) = sender.lock() {
                if let Err(e) = sender.send(level_str) {
                    tracing::warn!("Failed to send new log level to reloader: {}", e);
                    return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                        "Failed to update log level: {}",
                        e
                    )));
                }
            } else {
                return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                    "Logger sender is not available"
                )));
            }
        } else {
            return Err(rpc_types::error::Error::ExecutionError(anyhow::anyhow!(
                "Logger reloader is not initialized"
            )));
        }

        Ok(SetLoggerConfigResponse {})
    }

    async fn get_logger_config(
        &self,
        _: BaseController,
        _request: GetLoggerConfigRequest,
    ) -> Result<GetLoggerConfigResponse, rpc_types::error::Error> {
        let current_level_str = if let Some(current_level) = CURRENT_LOG_LEVEL.get() {
            if let Ok(level) = current_level.lock() {
                level.clone()
            } else {
                "info".to_string() // 默认级别
            }
        } else {
            "info".to_string() // 默认级别
        };

        let level = Self::string_to_log_level(&current_level_str);

        Ok(GetLoggerConfigResponse {
            level: level.into(),
        })
    }
}
