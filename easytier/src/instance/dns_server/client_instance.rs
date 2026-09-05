use std::{sync::Arc, time::Duration};

use anyhow::Context;
use easytier_core::gateway::magic_dns::{
    MagicDnsRoutePublisher, MagicDnsRouteSnapshot, run_magic_dns_route_publisher,
};
use easytier_core::instance::CorePacketPlane;
use tokio::task::JoinSet;

use crate::proto::{
    api::instance::Route,
    common::Void,
    magic_dns::{
        HandshakeRequest, MagicDnsServerRpc, MagicDnsServerRpcClientFactory, UpdateDnsRecordRequest,
    },
    rpc::standalone::{RuntimeRpcClient, runtime_rpc_client},
    rpc_types::controller::BaseController,
};

use super::endpoint::discover_magic_dns_endpoint;

pub struct MagicDnsClientInstance {
    rpc_client: RuntimeRpcClient,
    rpc_stub: Option<Box<dyn MagicDnsServerRpc<Controller = BaseController> + Send>>,
    route_source: Arc<CorePacketPlane>,
    tasks: JoinSet<anyhow::Result<()>>,
    endpoint: url::Url,
}

struct RpcMagicDnsRoutePublisher {
    rpc_stub: Box<dyn MagicDnsServerRpc<Controller = BaseController> + Send>,
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
            zone: snapshot.zone.clone(),
        };
        tracing::debug!(
            "MagicDnsClientInstance::update_dns_task: update dns records: {:?}",
            request
        );
        self.rpc_stub
            .update_dns_record(BaseController::default(), request)
            .await?;
        Ok(())
    }
}

impl MagicDnsClientInstance {
    pub(crate) async fn new(route_source: Arc<CorePacketPlane>) -> Result<Self, anyhow::Error> {
        let endpoint = discover_magic_dns_endpoint()?;
        let mut rpc_client = runtime_rpc_client(endpoint.clone());
        let rpc_stub = rpc_client
            .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>("".to_string())
            .await?;
        Ok(MagicDnsClientInstance {
            rpc_client,
            rpc_stub: Some(rpc_stub),
            route_source,
            tasks: JoinSet::new(),
            endpoint,
        })
    }

    pub(crate) fn endpoint(&self) -> &url::Url {
        &self.endpoint
    }

    async fn update_dns_task(
        route_source: Arc<CorePacketPlane>,
        rpc_stub: Box<dyn MagicDnsServerRpc<Controller = BaseController> + Send>,
    ) -> Result<(), anyhow::Error> {
        let mut publisher = RpcMagicDnsRoutePublisher { rpc_stub };
        run_magic_dns_route_publisher(
            route_source.as_ref(),
            &mut publisher,
            Duration::from_millis(500),
        )
        .await
    }

    pub async fn run_and_wait(&mut self) -> anyhow::Result<()> {
        let rpc_stub = self.rpc_stub.take().unwrap();
        let route_source = self.route_source.clone();
        self.tasks
            .spawn(Self::update_dns_task(route_source, rpc_stub));

        tokio::select! {
            result = self.tasks.join_next() => {
                match result {
                    Some(Ok(result)) => result.context("Magic DNS route publisher exited"),
                    Some(Err(error)) => Err(error).context("Magic DNS route publisher task failed"),
                    None => anyhow::bail!("Magic DNS route publisher task was not running"),
                }
            }
            _ = self.rpc_client.wait() => {
                anyhow::bail!("Magic DNS RPC client exited")
            }
        }
    }
}
