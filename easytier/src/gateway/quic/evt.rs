use crate::gateway::quic::packet::QuicPacket;
use bytes::Bytes;
use tokio::sync::mpsc;

#[derive(Debug)]
pub(super) enum QuicNetEvt {
    OutputPacket(QuicPacket),
}

pub type QuicNetEvtTx = mpsc::Sender<QuicNetEvt>;
pub type QuicNetEvtRx = mpsc::Receiver<QuicNetEvt>;

#[derive(Debug)]
pub(super) enum QuicStreamEvt {
    Data(Bytes),
    Fin,
    Reset(String),
}

pub type QuicStreamEvtTx = mpsc::Sender<QuicStreamEvt>;
pub type QuicStreamEvtRx = mpsc::Receiver<QuicStreamEvt>;
