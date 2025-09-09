use std::sync::Arc;

use cidr::Ipv6Inet;
use std::hash::Hash;
use tokio::task::JoinSet;

use crate::common::config::Ipv6OnlinkConfig;
use crate::common::global_ctx::{ArcGlobalCtx, GlobalCtxEvent};
use crate::common::ifcfg::IfConfiguerTrait;
use crate::common::PeerId;
use crate::instance::virtual_nic::NicCtx;
use crate::peers::peer_manager::PeerManager;
use crate::proto::rpc_types::controller::BaseController;
use crate::proto::{
    peer_rpc::{AddrAssignRpcClientFactory, AssignVirtualIpv6Request},
    rpc_impl::RpcController,
};

pub struct Ipv6OnlinkAllocator {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Arc<PeerManager>,
    nic_ctx: Arc<tokio::sync::Mutex<Option<super::instance::NicCtxContainer>>>,
    cfg: Ipv6OnlinkConfig,
}

impl Ipv6OnlinkAllocator {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_mgr: Arc<PeerManager>,
        nic_ctx: Arc<tokio::sync::Mutex<Option<super::instance::NicCtxContainer>>>,
        cfg: Ipv6OnlinkConfig,
    ) -> Self {
        Self {
            global_ctx,
            peer_mgr,
            nic_ctx,
            cfg,
        }
    }

    fn derive_addr(prefix: Ipv6Inet, peer_id: PeerId) -> std::net::Ipv6Addr {
        // stable host part from peer_id
        let host_bits = 128 - prefix.network_length() as u32;
        let mask: u128 = if host_bits == 128 { u128::MAX } else { (1u128 << host_bits) - 1 };
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        peer_id.hash(&mut hasher);
        let h = hasher.finish() as u128;
        let host = h & mask;
        let base: u128 = u128::from_be_bytes(prefix.address().octets());
        let addr = (base & !mask) | host;
        std::net::Ipv6Addr::from(addr.to_be_bytes())
    }

    pub async fn start(mut self) {
        let Some(prefix) = self.cfg.prefix else { return; };
        let Some(uplink) = self.cfg.uplink_iface.clone() else { return; };

        let mut tasks = JoinSet::new();
        let mut sub = self.global_ctx.subscribe();
        let peer_mgr = self.peer_mgr.clone();
        let nic_ctx = self.nic_ctx.clone();
        let install_src_default = self.cfg.install_source_default_on_receiver;
        let gc = self.global_ctx.clone();

        tasks.spawn(async move {
            while let Ok(ev) = sub.recv().await {
                if let GlobalCtxEvent::PeerAdded(pid) = ev {
                    if pid == peer_mgr.my_peer_id() {
                        continue;
                    }
                    // compute addr
                    let addr = Ipv6OnlinkAllocator::derive_addr(prefix, pid);

                    // Add route to local EasyTier interface
                    if let Some(holder) = nic_ctx.lock().await.as_ref() {
                        if let Some(nic) = holder
                            .nic_ctx
                            .as_ref()
                            .and_then(|b| b.downcast_ref::<NicCtx>())
                        {
                            let _ = nic.add_host_ipv6_route(addr).await;
                        }
                    }

                    // Add NDP proxy on uplink
                    if let Some(holder) = nic_ctx.lock().await.as_ref() {
                        if let Some(nic) = holder
                            .nic_ctx
                            .as_ref()
                            .and_then(|b| b.downcast_ref::<NicCtx>())
                        {
                            let _ = nic.add_ndp_proxy_on(uplink.as_str(), addr).await;
                        }
                    }

                    // Tell remote peer to configure address
                    let client = peer_mgr
                        .get_peer_rpc_mgr()
                        .rpc_client()
                        .scoped_client::<AddrAssignRpcClientFactory<BaseController>>(pid, 1, "".to_string());
                    let _ = client
                        .assign_virtual_ipv6(
                            BaseController::default(),
                            AssignVirtualIpv6Request {
                                ipv6: Some(addr.into()),
                                install_source_default: install_src_default,
                            },
                        )
                        .await;
                }
            }
        });
    }
}
