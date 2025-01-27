use std::sync::{Arc, Mutex};

use bytes::Bytes;

// Controller must impl clone and all cloned controllers share the same data
pub trait Controller: Send + Sync + Clone + 'static {
    fn timeout_ms(&self) -> i32 {
        5000
    }

    fn set_timeout_ms(&mut self, _timeout_ms: i32) {}

    fn set_trace_id(&mut self, _trace_id: i32) {}

    fn trace_id(&self) -> i32 {
        0
    }

    fn set_raw_input(&mut self, _raw_input: Bytes) {}
    fn get_raw_input(&self) -> Option<Bytes> {
        None
    }

    fn set_raw_output(&mut self, _raw_output: Bytes) {}
    fn get_raw_output(&self) -> Option<Bytes> {
        None
    }
}

#[derive(Debug)]
pub struct BaseControllerRawData {
    pub raw_input: Option<Bytes>,
    pub raw_output: Option<Bytes>,
}

#[derive(Debug, Clone)]
pub struct BaseController {
    pub timeout_ms: i32,
    pub trace_id: i32,
    pub raw_data: Arc<Mutex<BaseControllerRawData>>,
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

    fn set_raw_input(&mut self, raw_input: Bytes) {
        self.raw_data.lock().unwrap().raw_input = Some(raw_input);
    }

    fn get_raw_input(&self) -> Option<Bytes> {
        self.raw_data.lock().unwrap().raw_input.clone()
    }

    fn set_raw_output(&mut self, raw_output: Bytes) {
        self.raw_data.lock().unwrap().raw_output = Some(raw_output);
    }

    fn get_raw_output(&self) -> Option<Bytes> {
        self.raw_data.lock().unwrap().raw_output.clone()
    }
}

impl Default for BaseController {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            trace_id: 0,
            raw_data: Arc::new(Mutex::new(BaseControllerRawData {
                raw_input: None,
                raw_output: None,
            })),
        }
    }
}
