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

#[derive(Debug)]
pub struct BaseController {
    pub timeout_ms: i32,
    pub trace_id: i32,
}

impl Controller for BaseController {
    fn timeout_ms(&self) -> i32 {
        self.timeout_ms
    }

    fn set_timeout_ms(&mut self, timeout_ms: i32) {
        self.timeout_ms = timeout_ms;
    }

    fn set_trace_id(&mut self, trace_id: i32) {
        self.trace_id = trace_id;
    }

    fn trace_id(&self) -> i32 {
        self.trace_id
    }
}

impl Default for BaseController {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            trace_id: 0,
        }
    }
}
