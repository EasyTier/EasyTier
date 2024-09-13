pub trait Controller: Send + Sync + 'static {
    fn timeout_ms(&self) -> i32 {
        5000
    }

    fn set_timeout_ms(&mut self, _timeout_ms: i32) {}

    fn set_trace_id(&mut self, _trace_id: i32) {}

    fn trace_id(&self) -> i32 {
        0
    }
}

pub struct BaseController {}

impl Controller for BaseController {}
