use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use parking_lot::RwLock;
use tokio_util::task::AbortOnDropHandle;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProxyCidrRule {
    pub cidr: cidr::Ipv4Cidr,
    pub mapped_cidr: Option<cidr::Ipv4Cidr>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyCidrSnapshot {
    pub rules: Vec<ProxyCidrRule>,
}

pub trait ProxyCidrSnapshotProvider: Send + Sync {
    fn proxy_cidr_snapshot(&self) -> ProxyCidrSnapshot;
}

pub struct ProxyCidrTableRuntime<P: ProxyCidrSnapshotProvider + 'static> {
    provider: Arc<P>,
    table: Arc<ProxyCidrTable>,
    updater_task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl<P: ProxyCidrSnapshotProvider + 'static> ProxyCidrTableRuntime<P> {
    pub fn new(provider: Arc<P>) -> Self {
        Self {
            provider,
            table: Arc::new(ProxyCidrTable::new()),
            updater_task: Mutex::new(None),
        }
    }

    pub fn new_started(provider: Arc<P>) -> Self {
        let runtime = Self::new(provider);
        runtime.start_updater();
        runtime
    }

    pub fn start_updater(&self) {
        let mut updater_task = self.updater_task.lock().unwrap();
        if updater_task.is_some() {
            return;
        }
        let mut last_snapshot = self.provider.proxy_cidr_snapshot();
        self.table.update_snapshot(last_snapshot.clone());
        let provider = self.provider.clone();
        let table = self.table.clone();
        updater_task.replace(AbortOnDropHandle::new(tokio::spawn(async move {
            loop {
                let snapshot = provider.proxy_cidr_snapshot();
                if snapshot != last_snapshot {
                    last_snapshot = snapshot.clone();
                    table.update_snapshot(snapshot);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        })));
    }

    pub fn stop_updater(&self) {
        self.updater_task.lock().unwrap().take();
    }

    pub fn contains_v4(&self, ipv4: Ipv4Addr, real_ip: &mut Ipv4Addr) -> bool {
        if let Some(mapped_ip) = self.table.lookup_v4(ipv4) {
            *real_ip = mapped_ip;
            return true;
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }

    pub fn table(&self) -> Arc<ProxyCidrTable> {
        self.table.clone()
    }
}

impl<P: ProxyCidrSnapshotProvider + 'static> std::fmt::Debug for ProxyCidrTableRuntime<P> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProxyCidrTableRuntime")
            .field("table", &self.table)
            .field(
                "updater_running",
                &self.updater_task.lock().unwrap().is_some(),
            )
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProxyCidrEntry {
    real_cidr: cidr::Ipv4Cidr,
    mapped_cidr: cidr::Ipv4Cidr,
}

#[derive(Debug, Default)]
pub struct ProxyCidrTable {
    entries: RwLock<Vec<ProxyCidrEntry>>,
}

impl ProxyCidrTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_snapshot(snapshot: ProxyCidrSnapshot) -> Self {
        let table = Self::new();
        table.update_snapshot(snapshot);
        table
    }

    pub fn update_snapshot(&self, snapshot: ProxyCidrSnapshot) {
        let entries = snapshot
            .rules
            .into_iter()
            .map(|rule| ProxyCidrEntry {
                real_cidr: rule.cidr,
                mapped_cidr: rule.mapped_cidr.unwrap_or(rule.cidr),
            })
            .collect();
        *self.entries.write() = entries;
    }

    pub fn is_empty(&self) -> bool {
        self.entries.read().is_empty()
    }

    pub fn lookup_v4(&self, ipv4: Ipv4Addr) -> Option<Ipv4Addr> {
        self.entries
            .read()
            .iter()
            .find_map(|entry| entry.lookup_v4(ipv4))
    }
}

impl ProxyCidrEntry {
    fn lookup_v4(&self, ipv4: Ipv4Addr) -> Option<Ipv4Addr> {
        if !self.mapped_cidr.contains(&ipv4) {
            return None;
        }

        if self.mapped_cidr == self.real_cidr {
            return Some(ipv4);
        }

        let origin_network_bits = self.real_cidr.first().address().to_bits();
        let network_mask = self.mapped_cidr.mask().to_bits();
        let converted_ip = (ipv4.to_bits() & !network_mask) | origin_network_bits;
        Some(Ipv4Addr::from(converted_ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_returns_original_ip_for_unmapped_cidr() {
        let table = ProxyCidrTable::from_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "127.0.0.0/24".parse().unwrap(),
                mapped_cidr: None,
            }],
        });

        assert_eq!(
            table.lookup_v4("127.0.0.42".parse().unwrap()),
            Some("127.0.0.42".parse().unwrap())
        );
        assert_eq!(table.lookup_v4("127.0.1.42".parse().unwrap()), None);
    }

    #[test]
    fn lookup_converts_mapped_cidr_to_real_cidr() {
        let table = ProxyCidrTable::from_snapshot(ProxyCidrSnapshot {
            rules: vec![ProxyCidrRule {
                cidr: "127.0.0.0/24".parse().unwrap(),
                mapped_cidr: Some("10.10.10.0/24".parse().unwrap()),
            }],
        });

        assert_eq!(
            table.lookup_v4("10.10.10.42".parse().unwrap()),
            Some("127.0.0.42".parse().unwrap())
        );
    }
}
