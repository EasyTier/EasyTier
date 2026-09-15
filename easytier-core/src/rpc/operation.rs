//! Asynchronous local RPC operations backed by the shared operation broker.

use std::sync::{Arc, Mutex};

use prost::Message;

use crate::{
    foundation::operation_broker::{
        AccessError as BrokerAccessError, AdmissionError, OperationBroker, OperationId,
    },
    proto::{
        common::{DirectRpcRequest, RpcResponse},
        rpc_types::error,
    },
    rpc::{dispatch::dispatch_payload, service_registry::ServiceRegistry},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct RpcOperationId(OperationId);

impl RpcOperationId {
    #[cfg(target_os = "wasi")]
    pub(crate) fn from_raw(value: u64) -> Option<Self> {
        OperationId::from_raw(value).map(Self)
    }

    #[cfg(target_os = "wasi")]
    pub(crate) fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RpcSubmitError {
    #[error("invalid RPC request protobuf: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("RPC full method name is required")]
    MissingMethod,
    #[error("too many outstanding RPC operations")]
    AtCapacity,
    #[error("RPC operation ID space is exhausted")]
    IdExhausted,
    #[error("RPC submission requires an active Tokio runtime")]
    ExecutorUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RpcAccessError {
    #[error("unknown RPC operation")]
    Missing,
    #[error("RPC response is pending")]
    Pending,
}

struct RpcOperationState {
    broker: OperationBroker<(), Vec<u8>, ()>,
}

pub(crate) struct RpcOperationSession {
    registry: Arc<ServiceRegistry>,
    state: Arc<Mutex<RpcOperationState>>,
    max_response_len: usize,
}

impl RpcOperationSession {
    pub(crate) fn new(
        registry: Arc<ServiceRegistry>,
        max_operations: usize,
        max_response_len: usize,
    ) -> Self {
        Self {
            registry,
            state: Arc::new(Mutex::new(RpcOperationState {
                broker: OperationBroker::new(max_operations),
            })),
            max_response_len,
        }
    }

    pub(crate) fn submit_encoded(
        &self,
        encoded_request: &[u8],
    ) -> Result<RpcOperationId, RpcSubmitError> {
        let request = DirectRpcRequest::decode(encoded_request)?;
        if request.full_method_name.is_empty() {
            return Err(RpcSubmitError::MissingMethod);
        }
        let executor = tokio::runtime::Handle::try_current()
            .map_err(|_| RpcSubmitError::ExecutorUnavailable)?;
        let admission = self
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .broker
            .admit((), ())
            .map_err(|error| match error {
                AdmissionError::AtCapacity => RpcSubmitError::AtCapacity,
                AdmissionError::IdExhausted => RpcSubmitError::IdExhausted,
            })?;
        let operation_id = RpcOperationId(admission.id);
        let cancellation = admission.cancellation;
        let registry = self.registry.clone();
        let state = self.state.clone();
        let max_response_len = self.max_response_len;

        executor.spawn(async move {
            let started = std::time::Instant::now();
            let response = tokio::select! {
                _ = cancellation.cancelled() => None,
                result = async {
                    let descriptor = registry
                        .resolve_method("", &request.full_method_name)
                        .ok_or_else(|| {
                            error::Error::InvalidServiceKey(
                                request.full_method_name.clone(),
                                String::new(),
                            )
                        })?;
                    dispatch_payload(
                        registry.as_ref(),
                        descriptor,
                        request.request.into(),
                        request
                            .timeout_ms
                            .map(std::time::Duration::from_millis),
                        None,
                    )
                    .await
                } => {
                    Some(encode_response(
                        result,
                        started.elapsed().as_micros() as u64,
                        max_response_len,
                    ))
                }
            };
            let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
            state
                .broker
                .complete_with(operation_id.0, |_, _| response.unwrap_or_default());
        });
        Ok(operation_id)
    }

    pub(crate) fn response_len(
        &self,
        operation_id: RpcOperationId,
    ) -> Result<usize, RpcAccessError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.broker.drain(usize::MAX, |_| ());
        state
            .broker
            .with_drained(operation_id.0, |_, _, response| response.len())
            .map_err(map_access_error)
    }

    pub(crate) fn take_response_with<T>(
        &self,
        operation_id: RpcOperationId,
        take: impl FnOnce(&[u8]) -> Option<T>,
    ) -> Result<Option<T>, RpcAccessError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.broker.drain(usize::MAX, |_| ());
        state
            .broker
            .take_with(operation_id.0, |response| take(response))
            .map(|taken| taken.map(|taken| taken.value))
            .map_err(map_access_error)
    }

    pub(crate) fn free(&self, operation_id: RpcOperationId) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .broker
            .free(operation_id.0)
            .is_some()
    }

    #[cfg(target_os = "wasi")]
    pub(crate) fn discard_all(&self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .broker
            .discard_all();
    }
}

fn map_access_error(error: BrokerAccessError) -> RpcAccessError {
    match error {
        BrokerAccessError::Missing => RpcAccessError::Missing,
        BrokerAccessError::NotDrained => RpcAccessError::Pending,
    }
}

fn encode_response(
    result: error::Result<bytes::Bytes>,
    runtime_us: u64,
    max_response_len: usize,
) -> Vec<u8> {
    let mut response = RpcResponse::default();
    match result {
        Ok(bytes) => response.response = bytes.into(),
        Err(error) => response.error = Some((&error).into()),
    }
    response.runtime_us = runtime_us;
    let encoded = response.encode_to_vec();
    if encoded.len() <= max_response_len {
        return encoded;
    }

    let error = error::Error::ExecutionError(anyhow::anyhow!(
        "RPC response length {} exceeds ABI limit {}",
        encoded.len(),
        max_response_len
    ));
    RpcResponse {
        error: Some((&error).into()),
        ..Default::default()
    }
    .encode_to_vec()
}

#[cfg(test)]
mod tests {
    use std::any::TypeId;

    use bytes::Bytes;
    use easytier_proto::rpc_types::{
        controller::BaseController,
        descriptor::{MethodDescriptor, ServiceDescriptor},
        handler::Handler,
    };

    use super::*;

    #[derive(Clone, Copy, Debug)]
    enum TestMethod {
        Echo,
    }

    impl TryFrom<u8> for TestMethod {
        type Error = ();

        fn try_from(index: u8) -> Result<Self, Self::Error> {
            match index {
                0 => Ok(Self::Echo),
                _ => Err(()),
            }
        }
    }

    impl MethodDescriptor for TestMethod {
        fn name(&self) -> &'static str {
            "Echo"
        }

        fn proto_name(&self) -> &'static str {
            "Echo"
        }

        fn input_type(&self) -> TypeId {
            TypeId::of::<Vec<u8>>()
        }

        fn input_proto_type(&self) -> &'static str {
            "bytes"
        }

        fn output_type(&self) -> TypeId {
            TypeId::of::<Vec<u8>>()
        }

        fn output_proto_type(&self) -> &'static str {
            "bytes"
        }

        fn index(&self) -> u8 {
            0
        }
    }

    #[derive(Clone, Debug, Default)]
    struct TestService;

    impl ServiceDescriptor for TestService {
        type Method = TestMethod;

        fn name(&self) -> &'static str {
            "EchoService"
        }

        fn proto_name(&self) -> &'static str {
            "test"
        }

        fn methods(&self) -> &'static [Self::Method] {
            &[TestMethod::Echo]
        }
    }

    #[derive(Clone)]
    struct TestHandler;

    #[async_trait::async_trait]
    impl Handler for TestHandler {
        type Descriptor = TestService;
        type Controller = BaseController;

        async fn call(
            &self,
            _: Self::Controller,
            _: TestMethod,
            input: Bytes,
        ) -> error::Result<Bytes> {
            if input == b"pending"[..] {
                std::future::pending().await
            }
            Ok(input)
        }
    }

    fn request(full_method_name: &str, payload: &[u8]) -> Vec<u8> {
        DirectRpcRequest {
            full_method_name: full_method_name.to_owned(),
            request: payload.to_vec(),
            timeout_ms: None,
        }
        .encode_to_vec()
    }

    fn session(max_operations: usize) -> RpcOperationSession {
        let registry = Arc::new(ServiceRegistry::new());
        registry.register(TestHandler, "");
        RpcOperationSession::new(registry, max_operations, 1024)
    }

    async fn wait_ready(session: &RpcOperationSession, operation: RpcOperationId) -> usize {
        for _ in 0..16 {
            match session.response_len(operation) {
                Ok(length) => return length,
                Err(RpcAccessError::Pending) => tokio::task::yield_now().await,
                Err(error) => panic!("unexpected RPC access error: {error}"),
            }
        }
        panic!("RPC operation did not complete");
    }

    #[tokio::test]
    async fn dispatches_and_consumes_a_protobuf_rpc_response_once() {
        let session = session(4);
        let operation = session
            .submit_encoded(&request("test.Echo", b"hello"))
            .unwrap();
        let expected_len = wait_ready(&session, operation).await;
        assert!(
            session
                .take_response_with(operation, |_| None::<()>)
                .unwrap()
                .is_none()
        );
        assert_eq!(session.response_len(operation), Ok(expected_len));
        let mut encoded_response = Vec::new();
        let taken = session
            .take_response_with(operation, |response| {
                encoded_response.extend_from_slice(response);
                Some(response.len())
            })
            .unwrap();

        assert_eq!(taken, Some(expected_len));
        let response = RpcResponse::decode(encoded_response.as_slice()).unwrap();
        assert_eq!(response.response, b"hello");
        assert!(response.error.is_none());
        assert_eq!(
            session.response_len(operation),
            Err(RpcAccessError::Missing)
        );
    }

    #[tokio::test]
    async fn rpc_dispatch_errors_stay_inside_the_response_envelope() {
        let session = session(4);
        let operation = session
            .submit_encoded(&request("test.Missing", b"request"))
            .unwrap();
        wait_ready(&session, operation).await;
        let mut encoded_response = Vec::new();
        session
            .take_response_with(operation, |response| {
                encoded_response.extend_from_slice(response);
                Some(())
            })
            .unwrap();

        let response = RpcResponse::decode(encoded_response.as_slice()).unwrap();
        assert!(response.error.is_some());
    }

    #[tokio::test]
    async fn freeing_a_pending_operation_releases_capacity_after_cancellation() {
        let session = session(1);
        let operation = session
            .submit_encoded(&request("test.Echo", b"pending"))
            .unwrap();
        assert!(session.free(operation));
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;

        session
            .submit_encoded(&request("test.Echo", b"next"))
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_a_request_without_a_method() {
        let encoded = DirectRpcRequest {
            request: b"hello".to_vec(),
            ..Default::default()
        }
        .encode_to_vec();

        assert!(matches!(
            session(1).submit_encoded(&encoded),
            Err(RpcSubmitError::MissingMethod)
        ));
    }
}
