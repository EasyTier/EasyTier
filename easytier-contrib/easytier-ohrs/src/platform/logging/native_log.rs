use super::log_manager;
use napi_derive_ohos::napi;
use std::collections::HashMap;
use std::panic;
use tracing::{Event, Subscriber};
use tracing_core::Level;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

static INITIALIZED: std::sync::Once = std::sync::Once::new();
static TRACING_INITIALIZED: std::sync::Once = std::sync::Once::new();
fn panic_hook(info: &panic::PanicHookInfo) {
    log_manager::record_core_log(5, "RustPanic", &format!("{}", info));
}

#[napi]
pub fn init_panic_hook() {
    INITIALIZED.call_once(|| {
        panic::set_hook(Box::new(panic_hook));
    });
}

#[napi]
pub fn hilog_global_options(domain: u32, tag: String) {
    let _ = domain;
    let _ = tag;
}

#[napi]
pub fn init_tracing_subscriber() {
    TRACING_INITIALIZED.call_once(|| {
        let _ = tracing_subscriber::registry()
            .with(CallbackLayer {
                callback: Box::new(tracing_callback),
            })
            .try_init();
    });
}

fn tracing_callback(event: &Event, fields: HashMap<String, String>) {
    let metadata = event.metadata();
    let loc = metadata
        .target()
        .split("::")
        .last()
        .unwrap_or(metadata.target());
    let level = match *metadata.level() {
        Level::TRACE => 2,
        Level::DEBUG => 3,
        Level::INFO => 4,
        Level::WARN => 6,
        Level::ERROR => 5,
    };
    if !log_manager::core_log_enabled(level) {
        return;
    }
    let values = fields.values().cloned().collect::<Vec<_>>().join(" ");
    log_manager::record_core_log(level, &format!("Rust:{}", loc), &values);
}

struct CallbackLayer {
    callback: Box<dyn Fn(&Event, HashMap<String, String>) + Send + Sync>,
}

impl<S: Subscriber> Layer<S> for CallbackLayer {
    fn on_event(&self, event: &Event, _ctx: Context<S>) {
        let level = match *event.metadata().level() {
            Level::TRACE => 2,
            Level::DEBUG => 3,
            Level::INFO => 4,
            Level::WARN => 6,
            Level::ERROR => 5,
        };
        if !log_manager::core_log_enabled(level) {
            return;
        }
        // 使用 fmt::format::FmtSpan 提取字段值
        let mut fields = HashMap::new();
        let mut visitor = FieldCollector(&mut fields);
        event.record(&mut visitor);
        (self.callback)(event, fields);
    }
}

struct FieldCollector<'a>(&'a mut HashMap<String, String>);

impl<'a> tracing::field::Visit for FieldCollector<'a> {
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{:?}", value));
    }
}
