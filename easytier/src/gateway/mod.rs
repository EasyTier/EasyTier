use std::sync::{Arc, Mutex};

use tokio_util::task::AbortOnDropHandle;

use easytier_core::proxy::cidr_table::{
    ProxyCidrRule, ProxyCidrSnapshot, ProxyCidrSnapshotProvider, ProxyCidrTable,
};

use crate::common::global_ctx::ArcGlobalCtx;

pub mod icmp_proxy;
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
    updater_task: Mutex<Option<AbortOnDropHandle<()>>>,
}

impl CidrSet {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        let ret = Self::new_without_updater(global_ctx);
        ret.start_updater();
        ret
    }

    pub fn new_without_updater(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            table: Arc::new(ProxyCidrTable::new()),
            updater_task: Mutex::new(None),
        }
    }

    pub fn start_updater(&self) {
        let mut updater_task = self.updater_task.lock().unwrap();
        if updater_task.is_some() {
            return;
        }
        let global_ctx = self.global_ctx.clone();
        let table = self.table.clone();
        let mut last_cidrs = global_ctx.config.get_proxy_cidrs();
        table.update_snapshot(ProxyCidrSnapshot {
            rules: last_cidrs
                .iter()
                .map(|cidr| ProxyCidrRule {
                    cidr: cidr.cidr,
                    mapped_cidr: cidr.mapped_cidr,
                })
                .collect(),
        });
        updater_task.replace(AbortOnDropHandle::new(tokio::spawn(async move {
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
        })));
    }

    pub fn stop_updater(&self) {
        self.updater_task.lock().unwrap().take();
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
