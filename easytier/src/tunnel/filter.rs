pub use easytier_core::tunnel::filter::*;

#[cfg(test)]
pub mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use crate::tunnel::SinkItem;

    pub struct DropSendTunnelFilter {
        start: AtomicU32,
        end: AtomicU32,
        cur: AtomicU32,
    }

    impl TunnelFilter for DropSendTunnelFilter {
        type FilterOutput = ();

        fn before_send(&self, data: SinkItem) -> Option<SinkItem> {
            self.cur.fetch_add(1, Ordering::SeqCst);
            if self.cur.load(Ordering::SeqCst) >= self.start.load(Ordering::SeqCst)
                && self.cur.load(Ordering::SeqCst) < self.end.load(Ordering::SeqCst)
            {
                tracing::trace!("drop packet: {:?}", data);
                return None;
            }
            Some(data)
        }

        fn filter_output(&self) {}
    }

    impl DropSendTunnelFilter {
        pub fn new(start: u32, end: u32) -> Self {
            Self {
                start: AtomicU32::new(start),
                end: AtomicU32::new(end),
                cur: AtomicU32::new(0),
            }
        }
    }
}
