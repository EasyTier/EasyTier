//! Native instance ownership. I/O tasks receive context, never close authority.

use easytier_core::{
    config::runtime::CoreRuntimeConfigStore,
    host::route::{DeviceEpoch, InstanceRouteStatus, InstanceRoutes, RouteHandle},
};
use parking_lot::Mutex;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

use super::{RouteController, device::DeviceState};
use crate::{
    common::{global_ctx::ArcGlobalCtx, netns::NetNS},
    instance::{shared_virtual_nic::SharedVirtualNicMember, virtual_nic::VirtualNicConfig},
};

pub(crate) struct NativeRouteContext {
    namespace: Arc<NetNS>,
    run: Uuid,
    name: String,
    device: Arc<DeviceState>,
    pub(crate) handle: RouteHandle,
}

impl NativeRouteContext {
    fn controller(&self) -> anyhow::Result<&RouteController> {
        self.namespace
            .existing_route_controller()
            .ok_or_else(|| anyhow::anyhow!("native route controller is unavailable"))
    }
    pub(crate) fn ensure_open(&self) -> anyhow::Result<()> {
        self.namespace.ensure_open()?;
        self.controller()?.ensure_instance_open(self.run)
    }
    pub(crate) fn config(&self, mtu: u32) -> VirtualNicConfig {
        VirtualNicConfig::new(self.name.clone(), mtu, self.namespace.clone())
            .with_route_device(self.device.clone())
    }
    pub(crate) fn bind_member(&self, member: &SharedVirtualNicMember) -> anyhow::Result<()> {
        self.ensure_open()?;
        self.controller()?.bind_member(self.run, member)
    }
    pub(crate) fn ready(
        &self,
        member: &SharedVirtualNicMember,
        epoch: DeviceEpoch,
    ) -> anyhow::Result<DeviceEpoch> {
        self.ensure_open()?;
        self.controller()?
            .set_member_ready(self.run, member.registration_id(), epoch)
    }
    pub(crate) fn unready(&self, member: &SharedVirtualNicMember) {
        if let Ok(controller) = self.controller() {
            controller.set_member_unready(self.run, member.registration_id());
        }
    }
    pub(crate) fn abandon(&self, reason: Arc<str>) {
        if let Ok(controller) = self.controller() {
            controller.abandon_instance(self.run, reason);
        }
    }
}

pub(crate) struct NativeRouteRuntime {
    owner: Mutex<Option<InstanceRoutes>>,
    pub(crate) context: Arc<NativeRouteContext>,
}

impl NativeRouteRuntime {
    pub(crate) fn new(global_ctx: &ArcGlobalCtx) -> anyhow::Result<Self> {
        let namespace = global_ctx.net_ns.clone();
        let run = global_ctx.run_key();
        let name = global_ctx.get_flags().dev_name.clone();
        let controller = namespace.route_controller()?;
        let owner = controller.open_instance(run, name.clone())?;
        let (_, device) = controller.device(run)?;
        let handle = owner.handle();
        Ok(Self {
            owner: Mutex::new(Some(owner)),
            context: Arc::new(NativeRouteContext {
                namespace,
                run,
                name,
                device,
                handle,
            }),
        })
    }
    pub(crate) fn bind_config(&self, config: CoreRuntimeConfigStore) -> anyhow::Result<()> {
        let owner = self.owner.lock();
        owner
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("native routes are closing"))?
            .bind_config(config)?;
        Ok(())
    }
    pub(crate) fn request_close(&self) {
        if let Some(owner) = self.owner.lock().as_ref() {
            owner.request_close();
        }
    }
    pub(crate) async fn drain(&self) -> anyhow::Result<()> {
        self.request_close();
        let Some(owner) = self.owner.lock().take() else {
            return Ok(());
        };
        close_owner(owner, self.context.clone()).await
    }
    pub(crate) fn abandon(&self, reason: Arc<str>) {
        let owner = self.owner.lock().take();
        if let Some(owner) = owner.as_ref() {
            owner.request_close();
        }
        self.context.abandon(reason);
        drop(owner);
    }
}
impl Drop for NativeRouteRuntime {
    fn drop(&mut self) {
        let Some(owner) = self.owner.get_mut().take() else {
            return;
        };
        owner.request_close();
        let context = self.context.clone();
        match crate::host_runtime::native_host_runtime().shared_executor() {
            Ok(shared) => {
                // Make the cancellation guard before spawn: the cleanup future
                // may be destroyed without its first poll.
                let lost = guarden::guard!([context = context.clone()] {
                    context.abandon("native route cleanup executor disappeared".into());
                });
                shared.spawn(async move {
                    if let Err(error) = close_owner(owner, context).await {
                        tracing::warn!(?error, "native route cleanup incomplete");
                    }
                    lost.defuse();
                });
            }
            Err(error) => context.abandon(error.to_string().into()),
        }
    }
}

async fn close_owner(
    mut owner: InstanceRoutes,
    context: Arc<NativeRouteContext>,
) -> anyhow::Result<()> {
    owner.request_close();
    let abandoned = guarden::guard!([context = context.clone()] {
        context.abandon("native route cleanup was interrupted".into());
    });
    let result = wait_for_cleanup(&mut owner, Duration::from_secs(30)).await;
    if let Err(error) = &result {
        context.abandon(error.to_string().into());
    }
    abandoned.defuse();
    result
}

async fn wait_for_cleanup(owner: &mut InstanceRoutes, stall: Duration) -> anyhow::Result<()> {
    let mut deadline = tokio::time::Instant::now() + stall;
    let mut least_remaining = None;
    loop {
        match owner.status() {
            InstanceRouteStatus::Drained => return Ok(()),
            InstanceRouteStatus::Failed(error) => anyhow::bail!("{error}"),
            InstanceRouteStatus::Draining {
                remaining: Some(remaining),
            } => {
                if least_remaining.is_none_or(|least| remaining < least) {
                    least_remaining = Some(remaining);
                    deadline = tokio::time::Instant::now() + stall;
                }
            }
            _ => {}
        }
        match tokio::time::timeout_at(deadline, owner.status_changed()).await {
            Ok(changed) => {
                changed?;
            }
            Err(_) => {
                if matches!(owner.status(), InstanceRouteStatus::Drained) {
                    return Ok(());
                }
                anyhow::bail!("host route cleanup made no progress for {stall:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_core::{
        config::{peers::PeerRuntimeSnapshot, runtime::CoreRuntimeConfig},
        host::route::{RouteDemand, RouteSet},
    };
    use futures::FutureExt;
    use std::collections::BTreeMap;

    #[tokio::test(start_paused = true)]
    async fn watchdog_does_not_treat_repeated_unknown_presence_as_progress() {
        let mut owner = InstanceRoutes::new(Arc::new(|| {}));
        owner.request_close();
        let inputs = owner.inputs();
        let snapshot = inputs.snapshot();
        inputs.publish_feedback(
            &snapshot,
            InstanceRouteStatus::Draining { remaining: Some(1) },
            BTreeMap::new(),
        );
        let cleanup = wait_for_cleanup(&mut owner, Duration::from_secs(1));
        tokio::pin!(cleanup);
        assert!(cleanup.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(500)).await;
        inputs.publish_feedback(
            &snapshot,
            InstanceRouteStatus::Draining { remaining: Some(1) },
            BTreeMap::new(),
        );
        assert!(cleanup.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(501)).await;
        assert!(cleanup.now_or_never().unwrap().is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn real_retirement_extends_the_stall_deadline_without_a_total_time_limit() {
        let mut owner = InstanceRoutes::new(Arc::new(|| {}));
        owner.request_close();
        let inputs = owner.inputs();
        let snapshot = inputs.snapshot();
        inputs.publish_feedback(
            &snapshot,
            InstanceRouteStatus::Draining { remaining: Some(2) },
            BTreeMap::new(),
        );
        let cleanup = wait_for_cleanup(&mut owner, Duration::from_secs(1));
        tokio::pin!(cleanup);
        assert!(cleanup.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(750)).await;
        inputs.publish_feedback(
            &snapshot,
            InstanceRouteStatus::Draining { remaining: Some(1) },
            BTreeMap::new(),
        );
        assert!(cleanup.as_mut().now_or_never().is_none());
        tokio::time::advance(Duration::from_millis(750)).await;
        assert!(cleanup.as_mut().now_or_never().is_none());
        inputs.publish_feedback(&snapshot, InstanceRouteStatus::Drained, BTreeMap::new());
        cleanup.await.unwrap();
    }

    #[tokio::test]
    async fn native_owner_binds_config_then_closes_without_context_keeping_authority_alive() {
        let global = Arc::new(crate::common::global_ctx::GlobalCtx::new(
            crate::common::config::TomlConfig::default(),
        ));
        let runtime = NativeRouteRuntime::new(&global).unwrap();
        let context = runtime.context.clone();
        runtime
            .bind_config(CoreRuntimeConfigStore::new(
                CoreRuntimeConfig::default(),
                Arc::new(PeerRuntimeSnapshot::default()),
            ))
            .unwrap();
        runtime.request_close();
        tokio::time::timeout(Duration::from_secs(3), runtime.drain())
            .await
            .unwrap()
            .unwrap();
        assert!(context.ensure_open().is_err());
        assert!(
            context
                .handle
                .publish(RouteDemand::Additional(RouteSet::new()))
                .is_err()
        );
    }
    #[tokio::test]
    async fn dropping_the_native_owner_uses_shared_cleanup_without_a_caller_waiter() {
        let global = Arc::new(crate::common::global_ctx::GlobalCtx::new(
            crate::common::config::TomlConfig::default(),
        ));
        let runtime = NativeRouteRuntime::new(&global).unwrap();
        let weak = Arc::downgrade(&runtime.owner.lock().as_ref().unwrap().inputs());
        let context = runtime.context.clone();
        drop(runtime);
        assert!(
            context
                .handle
                .publish(RouteDemand::Additional(RouteSet::new()))
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(3), async {
            while weak.upgrade().is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
