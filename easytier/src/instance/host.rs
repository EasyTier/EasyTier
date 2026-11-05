use std::{net::IpAddr, sync::Arc};

use crate::{common::global_ctx::ArcGlobalCtx, host_runtime::NativeHostRuntime};
use easytier_core::connectivity::composite::{ConnectorEnvironment, ConnectorHostAdapter};
use easytier_core::socket::SocketContext;

pub type NativeInstanceHost = ConnectorHostAdapter<NativeHostRuntime, NativeInstanceEnvironment>;

/// Instance facts queried by portable connector policy.
///
/// This Adapter never creates or operates sockets. Mechanical network I/O is
/// owned by the instance's [`NativeHostRuntime`] composed beside it.
pub struct NativeInstanceEnvironment {
    global_ctx: ArcGlobalCtx,
    runtime: Arc<NativeHostRuntime>,
    socket_context: SocketContext,
}

impl NativeInstanceEnvironment {
    fn new(global_ctx: ArcGlobalCtx, runtime: Arc<NativeHostRuntime>) -> Self {
        let socket_context = SocketContext {
            socket_mark: global_ctx.get_flags().socket_mark,
            ..SocketContext::default()
        };
        Self {
            global_ctx,
            runtime,
            socket_context,
        }
    }
}

pub(crate) fn native_instance_host(
    global_ctx: ArcGlobalCtx,
    runtime: Arc<NativeHostRuntime>,
) -> Arc<NativeInstanceHost> {
    Arc::new(ConnectorHostAdapter::new(
        runtime.clone(),
        Arc::new(NativeInstanceEnvironment::new(global_ctx, runtime)),
    ))
}

impl ConnectorEnvironment for NativeInstanceEnvironment {
    fn socket_context(&self) -> SocketContext {
        self.socket_context.clone()
    }

    fn mapped_listeners(&self) -> Vec<url::Url> {
        self.global_ctx.runtime_mapped_listeners()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_ip_local_virtual_ip(ip)
            || self.runtime.is_local_ip(ip, &self.socket_context)
    }
}
