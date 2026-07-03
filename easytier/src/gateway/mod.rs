use std::sync::Arc;
use tokio::task::JoinSet;

use easytier_core::proxy::cidr_table::{
    ProxyCidrRule, ProxyCidrSnapshot, ProxyCidrSnapshotProvider, ProxyCidrTable,
};

use crate::common::global_ctx::ArcGlobalCtx;

pub mod icmp_proxy;
pub mod ip_reassembler;
pub mod tcp_proxy;
pub mod udp_proxy;

#[cfg(feature = "socks5")]
pub mod fast_socks5;
#[cfg(feature = "socks5")]
pub mod socks5;

#[cfg(feature = "kcp")]
pub mod kcp_proxy;

#[cfg(feature = "quic")]
pub mod quic_proxy;

#[derive(Debug)]
pub(crate) struct CidrSet {
    global_ctx: ArcGlobalCtx,
    table: Arc<ProxyCidrTable>,
    tasks: JoinSet<()>,
}

impl CidrSet {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        let mut ret = Self {
            global_ctx,
            table: Arc::new(ProxyCidrTable::new()),
            tasks: JoinSet::new(),
        };
        ret.run_cidr_updater();
        ret
    }

    fn run_cidr_updater(&mut self) {
        let global_ctx = self.global_ctx.clone();
        let table = self.table.clone();
        self.tasks.spawn(async move {
            let mut last_cidrs = vec![];
            loop {
                let cidrs = global_ctx.config.get_proxy_cidrs();
                if cidrs != last_cidrs {
                    last_cidrs = cidrs.clone();
                    table.update_snapshot(ProxyCidrSnapshot {
                        rules: cidrs
                            .into_iter()
                            .map(|cidr| ProxyCidrRule {
                                cidr: cidr.cidr,
                                mapped_cidr: cidr.mapped_cidr,
                            })
                            .collect(),
                    });
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    pub fn contains_v4(&self, ipv4: std::net::Ipv4Addr, real_ip: &mut std::net::Ipv4Addr) -> bool {
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

impl ProxyCidrSnapshotProvider for CidrSet {
    fn proxy_cidr_snapshot(&self) -> ProxyCidrSnapshot {
        ProxyCidrSnapshot {
            rules: self
                .global_ctx
                .config
                .get_proxy_cidrs()
                .into_iter()
                .map(|cidr| ProxyCidrRule {
                    cidr: cidr.cidr,
                    mapped_cidr: cidr.mapped_cidr,
                })
                .collect(),
        }
    }
}
