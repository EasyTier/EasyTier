use std::sync::Arc;

use easytier_core::proxy::cidr_table::{
    ProxyCidrRule, ProxyCidrSnapshot, ProxyCidrSnapshotProvider, ProxyCidrTableRuntime,
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

pub(crate) struct RuntimeProxyCidrSnapshotProvider {
    global_ctx: ArcGlobalCtx,
}

impl ProxyCidrSnapshotProvider for RuntimeProxyCidrSnapshotProvider {
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

pub(crate) type CidrSet = ProxyCidrTableRuntime<RuntimeProxyCidrSnapshotProvider>;

pub(crate) fn runtime_cidr_set_without_updater(global_ctx: ArcGlobalCtx) -> CidrSet {
    ProxyCidrTableRuntime::new(Arc::new(RuntimeProxyCidrSnapshotProvider { global_ctx }))
}
