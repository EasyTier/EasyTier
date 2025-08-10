use std::{sync::Arc, time::Duration};

use tokio::task::JoinSet;

use crate::{
    peers::peer_manager::PeerManager,
    proto::{
        cli::Route,
        common::Void,
        magic_dns::{
            HandshakeRequest, MagicDnsServerRpc, MagicDnsServerRpcClientFactory,
            UpdateDnsRecordRequest,
        },
        rpc_impl::standalone::StandAloneClient,
        rpc_types::controller::BaseController,
    },
    tunnel::tcp::TcpTunnelConnector,
};

use super::{DEFAULT_ET_DNS_ZONE, MAGIC_DNS_INSTANCE_ADDR};

pub struct MagicDnsClientInstance {
    rpc_client: StandAloneClient<TcpTunnelConnector>,
    rpc_stub: Option<Box<dyn MagicDnsServerRpc<Controller = BaseController> + Send>>,
    peer_mgr: Arc<PeerManager>,
    tasks: JoinSet<()>,
}

impl MagicDnsClientInstance {
    pub async fn new(peer_mgr: Arc<PeerManager>) -> Result<Self, anyhow::Error> {
        let tcp_connector = TcpTunnelConnector::new(MAGIC_DNS_INSTANCE_ADDR.parse().unwrap());
        let mut rpc_client = StandAloneClient::new(tcp_connector);
        let rpc_stub = rpc_client
            .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>("".to_string())
            .await?;
        Ok(MagicDnsClientInstance {
            rpc_client,
            rpc_stub: Some(rpc_stub),
            peer_mgr,
            tasks: JoinSet::new(),
        })
    }

    async fn update_dns_task(
        peer_mgr: Arc<PeerManager>,
        rpc_stub: Box<dyn MagicDnsServerRpc<Controller = BaseController> + Send>,
    ) -> Result<(), anyhow::Error> {
        let mut prev_last_update = None;
        rpc_stub
            .handshake(BaseController::default(), HandshakeRequest::default())
            .await?;
        loop {
            rpc_stub
                .heartbeat(BaseController::default(), Void::default())
                .await?;

            let last_update = peer_mgr.get_route_peer_info_last_update_time().await;
            if Some(last_update) == prev_last_update {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            }

            let mut routes = peer_mgr.list_routes().await;
            // add self as a route
            let ctx = peer_mgr.get_global_ctx();
            routes.push(Route {
                hostname: ctx.get_hostname(),
                ipv4_addr: ctx.get_ipv4().map(Into::into),
                ..Default::default()
            });
            let req = UpdateDnsRecordRequest {
                routes,
                zone: DEFAULT_ET_DNS_ZONE.to_string(),
            };
            tracing::debug!(
                "MagicDnsClientInstance::update_dns_task: update dns records: {:?}",
                req
            );
            rpc_stub
                .update_dns_record(BaseController::default(), req)
                .await?;

            let last_update_after_rpc = peer_mgr.get_route_peer_info_last_update_time().await;
            if last_update_after_rpc == last_update {
                prev_last_update = Some(last_update);
            }
        }
    }

    pub async fn run_and_wait(&mut self) {
        let rpc_stub = self.rpc_stub.take().unwrap();
        let peer_mgr = self.peer_mgr.clone();
        self.tasks.spawn(async move {
            let ret = Self::update_dns_task(peer_mgr, rpc_stub).await;
            if let Err(e) = ret {
                tracing::error!("MagicDnsServerInstanceData::run_and_wait: {:?}", e);
            }
        });

        tokio::select! {
            _ = self.tasks.join_next() => {
                tracing::warn!("MagicDnsServerInstanceData::run_and_wait: dns record update task exited");
            }
            _ = self.rpc_client.wait() => {
                tracing::warn!("MagicDnsServerInstanceData::run_and_wait: rpc client exited");
            }
        }
    }
}
