use std::sync::{Arc, Mutex};
use tokio::task::JoinSet;

use crate::common::global_ctx::ArcGlobalCtx;

pub mod icmp_proxy;
pub mod ip_reassembler;
pub mod tcp_proxy;
#[cfg(feature = "smoltcp")]
pub mod tokio_smoltcp;
pub mod udp_proxy;

#[cfg(feature = "socks5")]
pub mod fast_socks5;
#[cfg(feature = "socks5")]
pub mod socks5;

pub mod kcp_proxy;

#[derive(Debug)]
pub(crate) struct CidrSet {
    global_ctx: ArcGlobalCtx,
    cidr_set: Arc<Mutex<Vec<cidr::IpCidr>>>,
    tasks: JoinSet<()>,
}

impl CidrSet {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        let mut ret = Self {
            global_ctx,
            cidr_set: Arc::new(Mutex::new(vec![])),
            tasks: JoinSet::new(),
        };
        ret.run_cidr_updater();
        ret
    }

    fn run_cidr_updater(&mut self) {
        let global_ctx = self.global_ctx.clone();
        let cidr_set = self.cidr_set.clone();
        self.tasks.spawn(async move {
            let mut last_cidrs = vec![];
            loop {
                let cidrs = global_ctx.get_proxy_cidrs();
                if cidrs != last_cidrs {
                    last_cidrs = cidrs.clone();
                    cidr_set.lock().unwrap().clear();
                    for cidr in cidrs.iter() {
                        cidr_set.lock().unwrap().push(cidr.clone());
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    pub fn contains_v4(&self, ip: std::net::Ipv4Addr) -> bool {
        let ip = ip.into();
        let s = self.cidr_set.lock().unwrap();
        for cidr in s.iter() {
            if cidr.contains(&ip) {
                return true;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.cidr_set.lock().unwrap().is_empty()
    }
}
