use std::sync::Arc;

use cidr::Ipv6Inet;
use tokio::sync::Mutex;

use crate::common::global_ctx::ArcGlobalCtx;
use crate::common::ifcfg::IfConfiguerTrait;
use crate::instance::virtual_nic::NicCtx;
use crate::proto::common::Void;
use crate::proto::peer_rpc::{AddrAssignRpc, AssignVirtualIpv6Request};
use crate::proto::rpc_types::{self, controller::BaseController};

use super::instance::ArcNicCtx;

#[derive(Clone)]
pub struct AddrAssignRpcService {
    global_ctx: ArcGlobalCtx,
    nic_ctx: ArcNicCtx,
}

impl AddrAssignRpcService {
    pub fn new(global_ctx: ArcGlobalCtx, nic_ctx: ArcNicCtx) -> Self {
        Self { global_ctx, nic_ctx }
    }
}

#[async_trait::async_trait]
impl AddrAssignRpc for AddrAssignRpcService {
    type Controller = BaseController;

    async fn assign_virtual_ipv6(
        &self,
        _: BaseController,
        req: AssignVirtualIpv6Request,
    ) -> rpc_types::error::Result<Void> {
        let Some(ipv6) = req.ipv6 else { return Err(anyhow::anyhow!("ipv6 required").into()); };
        let ipv6_inet = Ipv6Inet::from(ipv6);

        // update config
        self.global_ctx.set_ipv6(Some(ipv6_inet));

        // best-effort: configure on TUN if available
        if let Some(mut holder) = self.nic_ctx.lock().await.as_mut() {
            if let Some(nic) = holder
                .nic_ctx
                .as_mut()
                .and_then(|b| b.downcast_mut::<NicCtx>())
            {
                let _ = nic.assign_ipv6_to_tun_device(ipv6_inet).await;

                if req.install_source_default {
                    if let Some(ifname) = nic.ifname().await {
                        // linux best-effort policy routing: ip -6 rule + table route
                        #[cfg(target_os = "linux")]
                        {
                            use std::process::Stdio;
                            let tbl_id = 10000 + (u16::from_be_bytes(ipv6_inet.address().octets()[14..16].try_into().unwrap()) as u32);
                            let rule_cmd = format!(
                                "ip -6 rule add from {}/128 table {} prio 1000 || true",
                                ipv6_inet.address(), tbl_id
                            );
                            let route_cmd = format!(
                                "ip -6 route add default dev {} table {} || true",
                                ifname, tbl_id
                            );
                            let _ = tokio::process::Command::new("sh")
                                .arg("-c")
                                .arg(rule_cmd)
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status()
                                .await;
                            let _ = tokio::process::Command::new("sh")
                                .arg("-c")
                                .arg(route_cmd)
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status()
                                .await;
                        }
                    }
                }
            }
        }

        Ok(Void::default())
    }
}

