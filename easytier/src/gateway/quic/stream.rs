use bytes::Bytes;
use futures::SinkExt;
use std::cmp::min;
use std::io::{Error, ErrorKind};
use std::pin::Pin;
use std::task::ready;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::PollSender;

use crate::gateway::quic::cmd::{QuicCmd, QuicCmdTx, QuicStreamInfo};
use crate::gateway::quic::evt::{QuicStreamEvt, QuicStreamEvtRx};
use crate::gateway::quic::QuicBufferPool;

#[derive(Debug)]
pub struct QuicStream {
    stream_info: QuicStreamInfo,

    evt_rx: QuicStreamEvtRx,
    cmd_tx: PollSender<QuicCmd>,

    pending: Option<Bytes>,
    pool: QuicBufferPool,
}

impl QuicStream {
    pub(super) fn new(
        stream_info: QuicStreamInfo,
        evt_rx: QuicStreamEvtRx,
        cmd_tx: QuicCmdTx,
    ) -> Self {
        Self {
            stream_info,
            evt_rx,
            cmd_tx: PollSender::new(cmd_tx),
            pending: None,
            pool: QuicBufferPool::new(8192),
        }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<(), Error>> {
        loop {
            if let Some(mut pending) = self.pending.take() {
                let len = min(pending.len(), buf.remaining());
                buf.put_slice(&pending.split_to(len));
                if !pending.is_empty() {
                    self.pending = Some(pending);
                    return Poll::Ready(Ok(()));
                }
            }

            match self.evt_rx.poll_recv(cx) {
                Poll::Ready(Some(event)) => match event {
                    QuicStreamEvt::Data(data) => {
                        if data.is_empty() {
                            continue;
                        }
                        self.pending = Some(data);
                    }
                    QuicStreamEvt::Fin => return Poll::Ready(Ok(())),
                    QuicStreamEvt::Reset(e) => {
                        return Poll::Ready(Err(Error::new(ErrorKind::ConnectionReset, e)))
                    }
                },
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

macro_rules! check_tx {
    ($e:expr) => {
        match $e {
            Ok(_) => Poll::Ready(Ok::<(), Error>(())),
            Err(_) => {
                return Poll::Ready(Err(Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "actor closed",
                )))
            }
        }
    };
}

macro_rules! ready_tx {
    ($e:expr) => {
        let _ = check_tx!(ready!($e));
    };
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        ready_tx!(self.cmd_tx.poll_ready_unpin(cx));
        let cmd = QuicCmd::StreamWrite {
            stream_info: self.stream_info,
            data: self.pool.buf(buf, (0, 0).into()).freeze(),
            fin: false,
        };
        let _ = check_tx!(self.cmd_tx.start_send_unpin(cmd));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        ready_tx!(self.cmd_tx.poll_flush_unpin(cx));
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        ready_tx!(self.cmd_tx.poll_flush_unpin(cx));
        ready_tx!(self.cmd_tx.poll_ready_unpin(cx));
        let cmd = QuicCmd::StreamWrite {
            stream_info: self.stream_info,
            data: Bytes::new(),
            fin: true,
        };
        check_tx!(self.cmd_tx.start_send_unpin(cmd))
    }
}
