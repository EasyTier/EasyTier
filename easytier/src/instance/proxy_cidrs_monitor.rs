use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::{Arc, Weak};
use std::time::Instant;

use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::common::ifcfg::{IfConfiger, IfConfiguerTrait};
use crate::common::scoped_task::ScopedTask;
use crate::peers::peer_manager::PeerManager;

#[cfg(feature = "tun")]
use crate::instance::instance::ArcNicCtx;
use crate::instance::virtual_nic::NicCtx;

/// ProxyCidrsMonitor monitors changes in proxy CIDRs from peer routes,
/// directly applies route changes to the TUN device (if present), and emits
/// `GlobalCtxEvent::ProxyCidrsUpdated` for logging / GUI notification.
///
/// The monitor holds an `ArcNicCtx` and on each tick attempts to extract the
/// TUN interface name from it. If the NicCtx has been cleared (DHCP transition)
/// or was never set (mobile / no-tun), route operations are simply skipped.
/// No shared slots, no traits, no `Lagged` handling.
pub struct ProxyCidrsMonitor {
    peer_mgr: Weak<PeerManager>,
    global_ctx: ArcGlobalCtx,
    #[cfg(feature = "tun")]
    nic_ctx: ArcNicCtx,
}

impl ProxyCidrsMonitor {
    pub fn new(
        peer_mgr: Arc<PeerManager>,
        global_ctx: ArcGlobalCtx,
        #[cfg(feature = "tun")] nic_ctx: ArcNicCtx,
    ) -> Self {
        Self {
            peer_mgr: Arc::downgrade(&peer_mgr),
            global_ctx,
            #[cfg(feature = "tun")]
            nic_ctx,
        }
    }

    /// Collects current proxy_cidrs from peer routes, VPN portal config, manual routes, and DNS.
    pub async fn collect_proxy_cidrs(
        peer_mgr: &PeerManager,
        global_ctx: &ArcGlobalCtx,
    ) -> BTreeSet<cidr::Ipv4Cidr> {
        let mut proxy_cidrs = BTreeSet::new();
        let routes = peer_mgr.list_routes().await;
        for r in routes {
            for cidr in r.proxy_cidrs {
                let Ok(cidr) = cidr.parse::<cidr::Ipv4Cidr>() else {
                    continue;
                };
                proxy_cidrs.insert(cidr);
            }
        }

        // Add VPN portal cidr to proxy_cidrs
        if let Some(vpn_cfg) = global_ctx.config.get_vpn_portal_config() {
            proxy_cidrs.insert(vpn_cfg.client_cidr);
        }

        // If has manual routes, override entire proxy_cidrs
        if let Some(routes) = global_ctx.config.get_routes() {
            proxy_cidrs = routes.into_iter().collect();
        }

        if let Some(dns) = global_ctx.get_dns() {
            proxy_cidrs.extend(dns.addresses().into_iter().filter_map(|a| match a.ip() {
                IpAddr::V4(ip) => Some(cidr::Ipv4Cidr::new_host(ip)),
                _ => None,
            }))
        }

        proxy_cidrs
    }

    /// Try to get the TUN interface name from the NicCtx.
    /// Returns `None` if there is no TUN device (cleared, mobile, no-tun).
    #[cfg(feature = "tun")]
    async fn ifname(&self) -> Option<String> {
        let guard = self.nic_ctx.lock().await;
        let container = guard.as_ref()?;
        let nic = container.nic_ctx.as_ref()?;
        let nic = nic.downcast_ref::<NicCtx>()?;
        nic.ifname().await
    }

    /// Apply route changes to the TUN device.
    #[cfg(feature = "tun")]
    async fn apply_routes(
        &self,
        added: &[cidr::Ipv4Cidr],
        removed: &[cidr::Ipv4Cidr],
    ) {
        let Some(ifname) = self.ifname().await else {
            return;
        };
        let ifcfg = IfConfiger {};
        let _g = self.global_ctx.net_ns.guard();

        for cidr in removed {
            let ret = ifcfg
                .remove_ipv4_route(&ifname, cidr.first_address(), cidr.network_length())
                .await;
            if let Err(e) = ret {
                tracing::trace!(?cidr, err = ?e, "remove route failed.");
            }
        }
        for cidr in added {
            let ret = ifcfg
                .add_ipv4_route(&ifname, cidr.first_address(), cidr.network_length(), None)
                .await;
            if let Err(e) = ret {
                tracing::trace!(?cidr, err = ?e, "add route failed.");
            }
        }
    }

    /// Starts the monitoring loop.
    pub fn start(self) -> ScopedTask<()> {
        ScopedTask::from(tokio::spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::new();
            let mut last_update = None::<Instant>;
            // Track TUN ifname to detect NicCtx recreation (DHCP).
            #[cfg(feature = "tun")]
            let mut last_ifname: Option<String> = None;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;

                let Some(peer_mgr) = self.peer_mgr.upgrade() else {
                    tracing::warn!("peer manager dropped, stopping ProxyCidrsMonitor");
                    break;
                };

                let last_update_time = peer_mgr.get_route_peer_info_last_update_time().await;

                // Detect NicCtx recreation by checking if ifname changed.
                #[cfg(feature = "tun")]
                {
                    let cur_ifname = self.ifname().await;
                    if cur_ifname != last_ifname {
                        if cur_ifname.is_some() {
                            tracing::debug!("TUN interface changed, forcing full proxy_cidrs resync");
                            cur_proxy_cidrs.clear();
                        }
                        last_ifname = cur_ifname;
                    } else if last_update == Some(last_update_time) {
                        continue;
                    }
                }
                #[cfg(not(feature = "tun"))]
                if last_update == Some(last_update_time) {
                    continue;
                }
                last_update = Some(last_update_time);

                let new_proxy_cidrs =
                    Self::collect_proxy_cidrs(peer_mgr.as_ref(), &self.global_ctx).await;

                if cur_proxy_cidrs == new_proxy_cidrs {
                    continue;
                }

                let added: Vec<_> = new_proxy_cidrs
                    .difference(&cur_proxy_cidrs)
                    .cloned()
                    .collect();
                let removed: Vec<_> = cur_proxy_cidrs
                    .difference(&new_proxy_cidrs)
                    .cloned()
                    .collect();

                #[cfg(feature = "tun")]
                self.apply_routes(&added, &removed).await;

                cur_proxy_cidrs = new_proxy_cidrs;

                if !added.is_empty() || !removed.is_empty() {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::ProxyCidrsUpdated(added, removed));
                }
            }
        }))
    }
}
