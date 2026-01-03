use crate::gateway::quic::evt::QuicStreamEvtRx;
use anyhow::Error;
use bytes::Bytes;
use quinn_proto::{ConnectionHandle, StreamId};
use std::net::SocketAddr;
use tokio::sync::{mpsc, oneshot};
use crate::gateway::quic::packet::QuicPacket;

#[derive(Debug, Clone, Copy)]
pub(super) struct QuicStreamInfo {
    pub(super) conn_handle: ConnectionHandle,
    pub(super) stream_id: StreamId,
}

#[derive(Debug)]
pub(super) enum QuicCmd {
    // Net
    InputPacket(QuicPacket),
    // Connection
    OpenBiStream {
        addr: SocketAddr,
        stream_tx: oneshot::Sender<Result<(QuicStreamInfo, QuicStreamEvtRx), Error>>,
    },
    CloseConnection {
        conn_handle: ConnectionHandle,
        error_code: u32,
        reason: Bytes,
    },
    // Stream
    StreamWrite {
        stream_info: QuicStreamInfo,
        data: Bytes,
        fin: bool,
    },
    StopStream {
        stream_info: QuicStreamInfo,
        error_code: u32,
    },
    ResetStream {
        stream_info: QuicStreamInfo,
        error_code: u32,
    },
}

pub(super) type QuicCmdTx = mpsc::Sender<QuicCmd>;
pub(super) type QuicCmdRx = mpsc::Receiver<QuicCmd>;
