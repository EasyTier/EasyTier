//! EasyTier message tunnel over a host-upgraded WebSocket.

use std::{io, sync::Arc};

use futures::{sink, stream};
use url::Url;

use crate::{
    host::{
        socket::{HostSocketHandle, HostSocketRuntime},
        websocket::{HostWebSocketIo, HostWebSocketMessage, MAX_HOST_WEBSOCKET_MESSAGE_LEN},
    },
    packet::{ZCPacket, ZCPacketType},
    proto::common::TunnelInfo,
};

use super::{Tunnel, TunnelError, wrapper::TunnelWrapper};

struct HostWebSocketResource {
    io: Arc<dyn HostWebSocketIo>,
    handle: HostSocketHandle,
}

impl Drop for HostWebSocketResource {
    fn drop(&mut self) {
        let _ = self.io.close(self.handle);
    }
}

/// Builds a message-preserving EasyTier tunnel around a host WebSocket.
pub fn new_host_websocket_tunnel(
    runtime: HostSocketRuntime,
    io: Arc<dyn HostWebSocketIo>,
    handle: HostSocketHandle,
    local_url: Url,
    remote_url: Url,
    resolved_remote_url: Option<Url>,
) -> Box<dyn Tunnel> {
    let resource = Arc::new(HostWebSocketResource { io, handle });
    let reader_resource = resource.clone();
    let reader_runtime = runtime.clone();
    let reader = stream::unfold(
        (reader_runtime, reader_resource),
        |(runtime, resource)| async move {
            let result = runtime
                .run_operation(
                    resource.io.clone(),
                    |io, operation| {
                        io.submit_receive(
                            resource.handle,
                            operation,
                            MAX_HOST_WEBSOCKET_MESSAGE_LEN,
                        )
                    },
                    |io, operation| io.take_receive(operation),
                    |io, operation| io.cancel_operation(operation),
                )
                .await;
            let item = match result {
                Ok(HostWebSocketMessage::Binary(message)) => Ok(ZCPacket::new_from_buf(
                    bytes::BytesMut::from(message.as_slice()),
                    ZCPacketType::DummyTunnel,
                )),
                Ok(HostWebSocketMessage::Text) => Err(TunnelError::InvalidPacket(
                    "text WebSocket message".to_owned(),
                )),
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return None,
                Err(error) => Err(TunnelError::IOError(error)),
            };
            Some((item, (runtime, resource)))
        },
    );

    let writer = sink::unfold(
        (runtime, resource),
        |(runtime, resource), packet: ZCPacket| async move {
            let payload = packet.tunnel_payload_bytes();
            runtime
                .run_operation(
                    resource.io.clone(),
                    |io, operation| io.submit_send(resource.handle, operation, &payload),
                    |io, operation| io.take_send(operation),
                    |io, operation| io.cancel_operation(operation),
                )
                .await
                .map_err(TunnelError::IOError)?;
            Ok((runtime, resource))
        },
    );

    let remote_addr = remote_url.clone().into();
    let resolved_remote_addr = resolved_remote_url
        .unwrap_or_else(|| remote_url.clone())
        .into();
    let info = TunnelInfo {
        tunnel_type: local_url.scheme().to_owned(),
        local_addr: Some(local_url.into()),
        remote_addr: Some(remote_addr),
        resolved_remote_addr: Some(resolved_remote_addr),
    };
    Box::new(TunnelWrapper::new(reader, writer, Some(info)))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, VecDeque},
        sync::{
            Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        task::Poll,
    };

    use futures::{SinkExt as _, StreamExt as _};

    use super::*;
    use crate::host::{
        socket::{HostOperationId, HostSocketIo},
        websocket::HostWebSocketMessage,
    };

    #[derive(Default)]
    struct MockWebSocketIo {
        incoming: Mutex<VecDeque<io::Result<HostWebSocketMessage>>>,
        receives: Mutex<HashMap<HostOperationId, io::Result<HostWebSocketMessage>>>,
        sends: Mutex<HashMap<HostOperationId, Vec<u8>>>,
        sent: Mutex<Vec<Vec<u8>>>,
        closes: AtomicUsize,
    }

    impl HostSocketIo for MockWebSocketIo {
        fn cancel_operation(&self, operation: HostOperationId) -> io::Result<()> {
            self.receives.lock().unwrap().remove(&operation);
            self.sends.lock().unwrap().remove(&operation);
            Ok(())
        }

        fn close(&self, _handle: HostSocketHandle) -> io::Result<()> {
            self.closes.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    impl HostWebSocketIo for MockWebSocketIo {
        fn submit_receive(
            &self,
            _handle: HostSocketHandle,
            operation: HostOperationId,
            _capacity: usize,
        ) -> io::Result<()> {
            let result = self.incoming.lock().unwrap().pop_front().unwrap();
            self.receives.lock().unwrap().insert(operation, result);
            Ok(())
        }

        fn take_receive(
            &self,
            operation: HostOperationId,
        ) -> Poll<io::Result<HostWebSocketMessage>> {
            Poll::Ready(self.receives.lock().unwrap().remove(&operation).unwrap())
        }

        fn submit_send(
            &self,
            _handle: HostSocketHandle,
            operation: HostOperationId,
            source: &[u8],
        ) -> io::Result<()> {
            self.sends
                .lock()
                .unwrap()
                .insert(operation, source.to_vec());
            Ok(())
        }

        fn take_send(&self, operation: HostOperationId) -> Poll<io::Result<()>> {
            let message = self.sends.lock().unwrap().remove(&operation).unwrap();
            self.sent.lock().unwrap().push(message);
            Poll::Ready(Ok(()))
        }
    }

    fn tunnel(io: Arc<MockWebSocketIo>) -> Box<dyn Tunnel> {
        new_host_websocket_tunnel(
            HostSocketRuntime::new(),
            io,
            HostSocketHandle(7),
            Url::parse("wss://relay.example/").unwrap(),
            Url::parse("wss://client.example/").unwrap(),
            None,
        )
    }

    #[test]
    fn preserves_websocket_message_boundaries_and_closes_once() {
        let io = Arc::new(MockWebSocketIo::default());
        io.incoming
            .lock()
            .unwrap()
            .push_back(Ok(HostWebSocketMessage::Binary(vec![1, 2, 3])));
        io.incoming
            .lock()
            .unwrap()
            .push_back(Ok(HostWebSocketMessage::Binary(vec![8, 9])));
        let tunnel = tunnel(io.clone());
        let (mut reader, mut writer) = tunnel.split();

        let first = futures::executor::block_on(reader.next()).unwrap().unwrap();
        let second = futures::executor::block_on(reader.next()).unwrap().unwrap();
        assert_eq!(first.tunnel_payload(), &[1, 2, 3]);
        assert_eq!(second.tunnel_payload(), &[8, 9]);

        let packet = ZCPacket::new_from_buf(
            bytes::BytesMut::from(&[4, 5, 6][..]),
            ZCPacketType::DummyTunnel,
        );
        futures::executor::block_on(writer.send(packet)).unwrap();
        assert_eq!(*io.sent.lock().unwrap(), vec![vec![4, 5, 6]]);

        drop(tunnel);
        drop(reader);
        drop(writer);
        assert_eq!(io.closes.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn rejects_text_messages_as_invalid_packets() {
        let io = Arc::new(MockWebSocketIo::default());
        io.incoming
            .lock()
            .unwrap()
            .push_back(Ok(HostWebSocketMessage::Text));
        let tunnel = tunnel(io);
        let (mut reader, _writer) = tunnel.split();

        let error = futures::executor::block_on(reader.next())
            .unwrap()
            .unwrap_err();
        assert!(matches!(error, TunnelError::InvalidPacket(_)));
    }

    #[test]
    fn maps_clean_remote_close_to_stream_eof() {
        let io = Arc::new(MockWebSocketIo::default());
        io.incoming
            .lock()
            .unwrap()
            .push_back(Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed")));
        let tunnel = tunnel(io);
        let (mut reader, _writer) = tunnel.split();

        assert!(futures::executor::block_on(reader.next()).is_none());
    }
}
