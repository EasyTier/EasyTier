use std::{sync::Arc, time::Duration};

use easytier_core::instance::CorePacketPlane;
use easytier_core::magic_dns::{
    MagicDnsRoutePublisher, MagicDnsRouteSnapshot, run_magic_dns_route_publisher,
};
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

use super::MAGIC_DNS_INSTANCE_ADDR;

pub struct MagicDnsClientInstance {
    rpc_client: RuntimeRpcClient,
    rpc_stub: Option<Box<dyn MagicDnsServerRpc<Controller = BaseController> + Send>>,
    route_source: Arc<CorePacketPlane>,
    tasks: JoinSet<()>,
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
                    ipv4_addr: route.ipv4_addr.clone(),
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
        let mut rpc_client = runtime_rpc_client(MAGIC_DNS_INSTANCE_ADDR.parse().unwrap());
        let rpc_stub = rpc_client
            .scoped_client::<MagicDnsServerRpcClientFactory<BaseController>>("".to_string())
            .await?;
        Ok(MagicDnsClientInstance {
            rpc_client,
            rpc_stub: Some(rpc_stub),
            route_source,
            tasks: JoinSet::new(),
        })
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

    pub async fn run_and_wait(&mut self) {
        let rpc_stub = self.rpc_stub.take().unwrap();
        let route_source = self.route_source.clone();
        self.tasks.spawn(async move {
            let ret = Self::update_dns_task(route_source, rpc_stub).await;
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
