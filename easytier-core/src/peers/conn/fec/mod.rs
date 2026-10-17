//! Connection-local sliding-window erasure recovery and adaptive byte credit.
//!
//! The existing PeerConn handshake advertises support; there is no independent
//! FEC authentication or negotiation. TX wraps after the business filters and
//! RX restores before them. Receive lifetimes start at adapter receipt, and
//! send counters measure acceptance by the Tunnel Sink, not host socket I/O.

mod budget;
mod codec;
mod feedback;
mod io;
mod recv;
mod send;
mod stats;
mod wire;

#[cfg(test)]
mod tests;

use std::sync::Arc;

use easytier_proto::peer_rpc::{PeerConnFecInfo, PeerConnFecParameters, PeerConnFecStats};
use futures::task::AtomicWaker;
use parking_lot::Mutex;
use tokio::sync::Notify;

use crate::{config::FecConfig, foundation::time::Instant, packet::ZCPacket};

pub use budget::FecInstanceBudget;
pub(crate) use io::PeerConnFecIo;

use budget::{Account, Reservation};
use feedback::{LossEstimator, Report};
use recv::Rx;
use send::{Accepted, PendingSend, Tx};
use stats::Counters;

pub(crate) const FEATURE: &str = "udp-fec-v1";
const FORCE_PEER_FEATURE: &str = "udp-fec-force-peer-v1";

// This charge stays inside the adapter and ends when the Stream yields the
// packet. Transport/application queues have their own bounds, not FEC charges.
struct Received {
    packet: ZCPacket,
    _reservation: Reservation,
}

struct State {
    tx_reason: &'static str,
    handshake_complete: bool,
    peer_requested: bool,
    tx: Option<Tx>,
    rx: Option<Rx>,
    loss: LossEstimator,
}

pub(crate) struct PeerConnFec {
    config: FecConfig,
    advertised: bool,
    account: Option<Arc<Account>>,
    state: Mutex<State>,
    counters: Arc<Counters>,
    writer_wake: Notify,
    reader_wake: AtomicWaker,
}

impl PeerConnFec {
    pub(crate) fn new(
        config: FecConfig,
        supported: bool,
        budget: Option<Arc<FecInstanceBudget>>,
    ) -> Self {
        let counters = Arc::new(Counters::default());
        let mut state = State {
            tx_reason: if supported {
                "resources"
            } else {
                "unsupported"
            },
            handshake_complete: false,
            peer_requested: false,
            tx: None,
            rx: None,
            loss: LossEstimator::default(),
        };
        let mut account = None;
        if supported && let Some(budget) = budget {
            let prepared = Account::new(budget);
            if let Ok(rx) = Rx::new(prepared.clone(), counters.clone()) {
                state.rx = Some(rx);
                state.tx_reason = if config.enabled {
                    "waiting_features"
                } else {
                    "disabled"
                };
            }
            account = Some(prepared);
        }
        Self {
            advertised: state.rx.is_some(),
            config,
            account,
            state: Mutex::new(state),
            counters,
            writer_wake: Notify::new(),
            reader_wake: AtomicWaker::new(),
        }
    }

    pub(crate) fn advertised(&self) -> bool {
        self.advertised
    }

    pub(crate) fn append_features(&self, features: &mut Vec<String>) {
        if self.advertised {
            features.push(FEATURE.to_owned());
            if self.config.force_peer {
                features.push(FORCE_PEER_FEATURE.to_owned());
            }
        }
    }

    pub(crate) fn set_remote_features(&self, features: &[String]) {
        let mut state = self.state.lock();
        if state.handshake_complete || state.tx_reason == "closed" {
            return;
        }
        state.handshake_complete = true;
        if features.iter().any(|feature| feature == FEATURE) {
            state.peer_requested = features.iter().any(|feature| feature == FORCE_PEER_FEATURE);
            if state.rx.is_some() && (self.config.enabled || state.peer_requested) {
                // Validate the effective send policy without changing the captured
                // desired configuration or forwarding this request to other peers.
                let mut config = self.config.clone();
                config.enabled = true;
                state.tx_reason = if config.validate().is_err() {
                    "invalid_config"
                } else if let Ok(tx) = Tx::new(
                    config,
                    self.account.as_ref().unwrap().clone(),
                    self.counters.clone(),
                ) {
                    state.tx = Some(tx);
                    "active"
                } else {
                    "resources"
                };
            }
        } else {
            if state.tx_reason == "waiting_features" {
                state.tx_reason = "remote_unsupported";
            }
            state.rx.take();
        }
        drop(state);
        self.writer_wake.notify_one();
        self.reader_wake.wake();
    }

    fn prepare_send(&self, packet: ZCPacket, now: Instant) -> PendingSend {
        let mut state = self.state.lock();
        if state.tx_reason == "active" {
            return state.tx.as_mut().unwrap().prepare(packet, now);
        }
        PendingSend::passthrough(packet)
    }

    fn on_accepted(&self, accepted: Option<Accepted>, now: Instant) {
        match accepted {
            Some(Accepted::Feedback { bytes }) => {
                stats::add(&self.counters.tx_feedback_packets, 1);
                stats::add(&self.counters.tx_feedback_bytes, bytes);
            }
            Some(accepted) => {
                if let Some(tx) = self.state.lock().tx.as_mut() {
                    tx.on_accepted(accepted, now);
                }
            }
            None => {}
        }
    }

    fn next_feedback(&self, now: Instant) -> Option<PendingSend> {
        let mut state = self.state.lock();
        if !state.handshake_complete || state.rx.is_none() {
            return None;
        }
        let report = state.loss.take_report(now)?;
        let bytes = wire::OVERHEAD + 8;
        let reservation = self.account.as_ref()?.reserve(bytes + 64)?;
        Some(PendingSend {
            packet: report.encode(),
            accepted: Some(Accepted::Feedback { bytes }),
            reservation: Some(reservation),
        })
    }

    fn next_repair(&self, now: Instant) -> Option<PendingSend> {
        let mut state = self.state.lock();
        if state.tx_reason != "active" {
            return None;
        }
        state.tx.as_mut()?.next_repair(now)
    }

    fn receive(&self, packet: ZCPacket, now: Instant) -> Option<Received> {
        let mut state = self.state.lock();
        state.rx.as_ref()?;
        let Some(fragment) = wire::decode(&packet) else {
            stats::add(&self.counters.protocol_errors, 1);
            return None;
        };
        if fragment.header.kind == wire::FEEDBACK {
            if state.handshake_complete {
                if let Some(report) = Report::decode(&fragment) {
                    stats::add(&self.counters.rx_feedback_packets, 1);
                    stats::add(&self.counters.rx_feedback_bytes, wire::OVERHEAD + 8);
                    if let Some(tx) = state.tx.as_mut() {
                        tx.apply_report(report);
                    }
                } else {
                    stats::add(&self.counters.protocol_errors, 1);
                }
            }
            return None;
        }
        if fragment.header.kind == wire::SOURCE && !wire::eligible_peer(fragment.payload) {
            stats::add(&self.counters.protocol_errors, 1);
            return None;
        }
        state.loss.observe(fragment.header.sequence, now);
        let ready = state.handshake_complete;
        let rx = state.rx.as_mut()?;
        let received = rx.receive(packet, now);
        let out = if ready {
            received
        } else {
            if let Some(received) = received {
                rx.queue_received(received);
            }
            None
        };
        drop(state);
        self.writer_wake.notify_one();
        out
    }

    fn take_received(&self) -> Option<Received> {
        let mut state = self.state.lock();
        if !state.handshake_complete {
            return None;
        }
        state.rx.as_mut()?.take_received()
    }

    fn deadline(&self) -> Option<Instant> {
        let state = self.state.lock();
        state
            .tx
            .as_ref()
            .and_then(Tx::deadline)
            .into_iter()
            .chain(state.rx.as_ref().and_then(Rx::deadline))
            .min()
    }

    fn feedback_deadline(&self) -> Option<Instant> {
        let state = self.state.lock();
        (state.handshake_complete && state.rx.is_some())
            .then(|| state.loss.deadline())
            .flatten()
    }

    fn maintain(&self, now: Instant) {
        let mut state = self.state.lock();
        if let Some(tx) = state.tx.as_mut() {
            tx.on_deadline(now);
        }
        if let Some(rx) = state.rx.as_mut() {
            rx.expire(now);
        }
    }

    fn closed(&self) -> bool {
        self.state.lock().tx_reason == "closed"
    }

    pub(crate) fn close(&self) {
        let mut state = self.state.lock();
        state.tx_reason = "closed";
        state.tx.take();
        state.rx.take();
        state.loss = LossEstimator::default();
        drop(state);
        self.writer_wake.notify_one();
        self.reader_wake.wake();
    }

    fn snapshot(&self, state: &State) -> PeerConnFecStats {
        let mut stats = self.counters.snapshot();
        if let Some(account) = &self.account {
            stats.memory_bytes = account.used() as u64;
            stats.peak_memory_bytes = account.peak() as u64;
        }
        stats.tx_window_packets = state.tx.as_ref().map_or(0, Tx::active_symbols) as u64;
        stats.rx_window_packets = state.rx.as_ref().map_or(0, Rx::active_symbols) as u64;
        stats.rx_equations = state.rx.as_ref().map_or(0, Rx::equations) as u64;
        let report = state.loss.snapshot();
        stats.loss_samples = report.samples;
        stats.loss_packets = report.lost;
        stats
    }

    pub(crate) fn info(&self) -> PeerConnFecInfo {
        let state = self.state.lock();
        PeerConnFecInfo {
            desired_enabled: self.config.enabled,
            desired_force_peer: self.config.force_peer,
            peer_requested: state.peer_requested,
            tx_active: state.tx_reason == "active",
            rx_active: state.handshake_complete && state.rx.is_some(),
            tx_reason: state.tx_reason.to_owned(),
            tx_parameters: state.tx.as_ref().map(|tx| PeerConnFecParameters {
                window_packets: Some(codec::WINDOW as u32),
                max_repair_percent: Some(self.config.max_repair_percent),
                current_repair_percent: Some(tx.rate()),
                udp_payload_mtu: Some(self.config.udp_payload_mtu),
            }),
            stats: Some(self.snapshot(&state)),
        }
    }
}
