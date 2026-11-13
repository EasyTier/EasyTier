use std::{sync::Arc, time::Duration};

use easytier_core::gateway::magic_dns::{
    MagicDnsRoutePublisher, MagicDnsRouteSnapshot, normalized_dns, run_magic_dns_route_publisher,
};
use easytier_core::instance::CorePacketPlane;
use tokio::task::JoinSet;

use crate::{
    common::global_ctx::ArcGlobalCtx,
    proto::{
        api::instance::Route,
        common::Void,
        magic_dns::{
            HandshakeRequest, MagicDnsServerRpc, MagicDnsServerRpcClientFactory,
            UpdateDnsRecordRequest,
        },
        rpc::standalone::{RuntimeRpcClient, runtime_rpc_client},
        rpc_types::{controller::BaseController, error::Error as RpcError},
    },
};

use super::MAGIC_DNS_INSTANCE_ADDR;

pub struct MagicDnsClientInstance {
    rpc_client: RuntimeRpcClient,
    rpc_stub: Option<Box<dyn MagicDnsServerRpc<Controller = BaseController> + Send>>,
    route_source: Arc<CorePacketPlane>,
    global_ctx: ArcGlobalCtx,
    tasks: JoinSet<()>,
}

struct RpcMagicDnsRoutePublisher {
    rpc_stub: Box<dyn MagicDnsServerRpc<Controller = BaseController> + Send>,
    global_ctx: ArcGlobalCtx,
}

#[async_trait::async_trait]
impl MagicDnsRoutePublisher for RpcMagicDnsRoutePublisher {
    async fn handshake(&mut self) -> anyhow::Result<()> {
        self.rpc_stub
            .handshake(BaseController::default(), HandshakeRequest::default())
            .await?;
        Ok(())
    }

    async fn heartbeat(&mut self) -> anyhow::Result<()> {
        self.rpc_stub
            .heartbeat(BaseController::default(), Void::default())
            .await?;
        Ok(())
    }

    async fn publish(&mut self, snapshot: &MagicDnsRouteSnapshot) -> anyhow::Result<()> {
        let dns = normalized_dns(&self.global_ctx.config)?;
        let request = UpdateDnsRecordRequest {
            routes: snapshot
                .routes
                .iter()
                .map(|route| Route {
                    hostname: route.hostname.clone(),
                    ipv4_addr: route.ipv4_addr,
                    ..Default::default()
                })
                .collect(),
            zone: dns.domain.clone().unwrap(),
            instance_id: self.global_ctx.get_id().to_string(),
            dns: Some(dns),
        };
        match self
            .rpc_stub
            .update_dns_record(BaseController::default(), request)
            .await
        {
            Ok(_) => Ok(()),
            Err(RpcError::ExecutionError(error)) => {
                // Keep accepted records and this connection until a later snapshot succeeds.
                tracing::warn!(?error, "DNS contribution rejected");
                Ok(())
            }
            Err(error) => Err(error.into()),
        }
    }
}

impl MagicDnsClientInstance {
    pub(crate) async fn new(
        route_source: Arc<CorePacketPlane>,
        global_ctx: ArcGlobalCtx,
    ) -> Result<Self, anyhow::Error> {
        let mut rpc_client = runtime_rpc_client(MAGIC_DNS_INSTANCE_ADDR.parse().unwrap());
        let rpc_stub = rpc_client
            .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>("".to_string())
            .await?;
        Ok(MagicDnsClientInstance {
            rpc_client,
            rpc_stub: Some(rpc_stub),
            route_source,
            global_ctx,
            tasks: JoinSet::new(),
        })
    }

    pub async fn run_and_wait(&mut self) {
        let route_source = self.route_source.clone();
        let mut publisher = RpcMagicDnsRoutePublisher {
            rpc_stub: self.rpc_stub.take().unwrap(),
            global_ctx: self.global_ctx.clone(),
        };
        self.tasks.spawn(async move {
            if let Err(error) = run_magic_dns_route_publisher(
                route_source.as_ref(),
                &mut publisher,
                Duration::from_millis(500),
            )
            .await
            {
                tracing::error!(?error, "DNS publishing task exited");
            }
        });

        tokio::select! {
            _ = self.tasks.join_next() => {
                tracing::warn!("DNS record update task exited");
            }
            _ = self.rpc_client.wait() => {
                tracing::warn!("DNS RPC client exited");
            }
        }
    }
}
