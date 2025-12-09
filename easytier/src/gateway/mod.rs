use dashmap::DashMap;
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

pub mod quic_proxy;

#[derive(Debug)]
pub(crate) struct CidrSet {
    global_ctx: ArcGlobalCtx,
    cidr_set: Arc<Mutex<Vec<cidr::Ipv4Cidr>>>,
    tasks: JoinSet<()>,

    mapped_to_real: Arc<DashMap<cidr::Ipv4Cidr, cidr::Ipv4Cidr>>,
}

impl CidrSet {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        let mut ret = Self {
            global_ctx,
            cidr_set: Arc::new(Mutex::new(vec![])),
            tasks: JoinSet::new(),

            mapped_to_real: Arc::new(DashMap::new()),
        };
        ret.run_cidr_updater();
        ret
    }

    fn run_cidr_updater(&mut self) {
        let global_ctx = self.global_ctx.clone();
        let cidr_set = self.cidr_set.clone();
        let mapped_to_real = self.mapped_to_real.clone();
        self.tasks.spawn(async move {
            let mut last_cidrs = vec![];
            loop {
                let cidrs = global_ctx.config.get_proxy_cidrs();
                if cidrs != last_cidrs {
                    last_cidrs = cidrs.clone();
                    mapped_to_real.clear();
                    cidr_set.lock().unwrap().clear();
                    for cidr in cidrs.iter() {
                        let real_cidr = cidr.cidr;
                        let mapped = cidr.mapped_cidr.unwrap_or(real_cidr);
                        cidr_set.lock().unwrap().push(mapped);

                        if mapped != real_cidr {
                            mapped_to_real.insert(mapped, real_cidr);
                        }
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
    }

    pub fn contains_v4(&self, ipv4: std::net::Ipv4Addr, real_ip: &mut std::net::Ipv4Addr) -> bool {
        let ip = ipv4;
        let s = self.cidr_set.lock().unwrap();
        for cidr in s.iter() {
            if cidr.contains(&ip) {
                if let Some(real_cidr) = self.mapped_to_real.get(cidr).map(|v| *v.value()) {
                    let origin_network_bits = real_cidr.first().address().to_bits();
                    let network_mask = cidr.mask().to_bits();

                    let mut converted_ip = ipv4.to_bits();
                    converted_ip &= !network_mask;
                    converted_ip |= origin_network_bits;

                    *real_ip = std::net::Ipv4Addr::from(converted_ip);
                } else {
                    *real_ip = ipv4;
                }
                return true;
            }
        }
        false
    }

    pub fn is_empty(&self) -> bool {
        self.cidr_set.lock().unwrap().is_empty()
    }
}
