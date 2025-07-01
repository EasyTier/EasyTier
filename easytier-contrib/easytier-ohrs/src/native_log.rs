use std::collections::HashMap;
use std::panic;
use napi_derive_ohos::napi;
use ohos_hilog_binding::{hilog_debug, hilog_error, hilog_info, hilog_warn, set_global_options, LogOptions};
use tracing::{Event, Subscriber};
use tracing_core::Level;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

static INITIALIZED: std::sync::Once = std::sync::Once::new();
fn panic_hook(info: &panic::PanicHookInfo) {
    hilog_error!("RUST PANIC: {}", info);
}

#[napi]
pub fn init_panic_hook() {
    INITIALIZED.call_once(|| {
        panic::set_hook(Box::new(panic_hook));
    });
}

#[napi]
pub fn hilog_global_options(
    domain: u32,
    tag: String,
) {
    ohos_hilog_binding::forward_stdio_to_hilog();
    set_global_options(LogOptions{
        domain,
        tag: Box::leak(tag.clone().into_boxed_str()),
    })
}

#[napi]
pub fn init_tracing_subscriber() {
    tracing_subscriber::registry()
        .with(
            CallbackLayer {
                callback: Box::new(tracing_callback),
            }
        )
        .init();
}

fn tracing_callback(event: &Event, fields: HashMap<String, String>) {
    let metadata = event.metadata();
    #[cfg(target_env = "ohos")]
    {
        let loc = metadata.target().split("::").last().unwrap();
        match *metadata.level() {
            Level::TRACE => {
                hilog_debug!("[{}] {:?}", loc, fields.values().collect::<Vec<_>>());
            }
            Level::DEBUG => {
                hilog_debug!("[{}] {:?}", loc, fields.values().collect::<Vec<_>>());
            }
            Level::INFO => {
                hilog_info!("[{}] {:?}", loc, fields.values().collect::<Vec<_>>());
            }
            Level::WARN => {
                hilog_warn!("[{}] {:?}", loc, fields.values().collect::<Vec<_>>());
            }
            Level::ERROR => {
                hilog_error!("[{}] {:?}", loc, fields.values().collect::<Vec<_>>());
            }
        }
    }
}

struct CallbackLayer {
    callback: Box<dyn Fn(&Event, HashMap<String, String>) + Send + Sync>,
}

impl<S: Subscriber> Layer<S> for CallbackLayer {
    fn on_event(&self, event: &Event, _ctx: Context<S>) {
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
        self.0.insert(field.name().to_string(), format!("{:?}", value));
    }
}