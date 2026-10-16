use std::{net::IpAddr, sync::Arc};

use easytier_core::{
    connectivity::composite::{ConnectorEnvironment, ConnectorHostAdapter},
    socket::SocketContext,
};

use crate::{common::global_ctx::ArcGlobalCtx, common::netns::NetNS};

pub type NativeInstanceHost = ConnectorHostAdapter<NetNS, NativeInstanceEnvironment>;

/// Instance facts queried by portable connector policy.
///
/// This Adapter never creates or operates sockets. Mechanical network I/O is
/// owned by the canonical [`NetNS`] selected during composition.
pub struct NativeInstanceEnvironment {
    global_ctx: ArcGlobalCtx,
    runtime: Arc<NetNS>,
    socket_context: SocketContext,
}

impl NativeInstanceEnvironment {
    fn new(global_ctx: ArcGlobalCtx, runtime: Arc<NetNS>) -> Self {
        let socket_context = SocketContext::default()
            .with_socket_mark(global_ctx.get_flags().socket_mark)
            .with_netns(Some(global_ctx.net_ns.token()));
        Self {
            global_ctx,
            runtime,
            socket_context,
        }
    }
}

pub(crate) fn native_instance_host(global_ctx: ArcGlobalCtx) -> Arc<NativeInstanceHost> {
    let runtime = global_ctx.net_ns.clone();
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
