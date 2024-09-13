//! Utility functions used by generated code; this is *not* part of the crate's public API!
use bytes;
use prost;

use super::controller;
use super::descriptor;
use super::descriptor::ServiceDescriptor;
use super::error;
use super::handler;
use super::handler::Handler;

/// Efficiently decode a particular message type from a byte buffer.
pub fn decode<M>(buf: bytes::Bytes) -> error::Result<M>
where
    M: prost::Message + Default,
{
    let message = prost::Message::decode(buf)?;
    Ok(message)
}

/// Efficiently encode a particular message into a byte buffer.
pub fn encode<M>(message: M) -> error::Result<bytes::Bytes>
where
    M: prost::Message,
{
    let len = prost::Message::encoded_len(&message);
    let mut buf = ::bytes::BytesMut::with_capacity(len);
    prost::Message::encode(&message, &mut buf)?;
    Ok(buf.freeze())
}

pub async fn call_method<H, I, O>(
    handler: H,
    ctrl: H::Controller,
    method: <H::Descriptor as descriptor::ServiceDescriptor>::Method,
    input: I,
) -> super::error::Result<O>
where
    H: handler::Handler,
    I: prost::Message,
    O: prost::Message + Default,
{
    type Error = super::error::Error;
    let input_bytes = encode(input)?;
    let ret_msg = handler.call(ctrl, method, input_bytes).await?;
    decode(ret_msg)
}

pub trait RpcClientFactory: Clone + Send + Sync + 'static {
    type Descriptor: ServiceDescriptor + Default;
    type ClientImpl;
    type Controller: controller::Controller;

    fn new(
        handler: impl Handler<Descriptor = Self::Descriptor, Controller = Self::Controller>,
    ) -> Self::ClientImpl;
}
