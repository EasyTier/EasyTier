use hickory_net::NetError;
use hickory_proto::rr::Record;
use hickory_proto::serialize::binary::BinEncoder;
use hickory_server::server::{ResponseHandler, ResponseInfo};
use hickory_server::zone_handler::MessageResponse;
use parking_lot::Mutex;
use std::sync::Arc;

// ResponseWrapper for serializing DNS responses into a byte buffer.
// Used by the address hijacking NIC packet filter to produce DNS replies in-place.
#[derive(Debug, Clone)]
pub struct ResponseHandle {
    inner: Arc<Mutex<Vec<u8>>>,
}

impl ResponseHandle {
    pub fn new(capacity: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Vec::with_capacity(capacity))),
        }
    }

    pub fn into_inner(self) -> Option<Vec<u8>> {
        Arc::into_inner(self.inner).map(Mutex::into_inner)
    }
}

pub trait RecordIter<'r>: Iterator<Item = &'r Record> + Send + 'r {}

impl<'r, T> RecordIter<'r> for T where T: Iterator<Item = &'r Record> + Send + 'r {}

#[async_trait::async_trait]
impl ResponseHandler for ResponseHandle {
    async fn send_response<'r>(
        &mut self,
        response: MessageResponse<
            '_,
            'r,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
            impl RecordIter<'r>,
        >,
    ) -> Result<ResponseInfo, NetError> {
        let max_size = if let Some(edns) = response.edns() {
            edns.max_payload()
        } else {
            hickory_net::udp::MAX_RECEIVE_BUFFER_SIZE as u16
        };

        let mut inner = self.inner.lock();
        inner.clear();
        let mut encoder = BinEncoder::new(inner.as_mut());
        encoder.set_max_size(max_size);
        response
            .destructive_emit(&mut encoder)
            .map_err(NetError::Proto)
    }
}
