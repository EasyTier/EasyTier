use std::{
    net::{IpAddr, Ipv6Addr},
    sync::Arc,
};

use easytier_core::{
    connectivity::composite::{ConnectorEnvironment, ConnectorHostAdapter},
    socket::{NetNamespace, SocketContext},
};

use crate::{
    common::global_ctx::ArcGlobalCtx,
    host_runtime::{NativeHostRuntime, native_host_runtime},
};

pub(crate) type NativeInstanceHost =
    ConnectorHostAdapter<NativeHostRuntime, NativeInstanceEnvironment>;

/// Instance facts queried by portable connector policy.
///
/// This Adapter never creates or operates sockets. Mechanical network I/O is
/// owned by the process-wide [`NativeHostRuntime`] composed beside it.
pub(crate) struct NativeInstanceEnvironment {
    global_ctx: ArcGlobalCtx,
    socket_context: SocketContext,
}

impl NativeInstanceEnvironment {
    fn new(global_ctx: ArcGlobalCtx) -> Self {
        let socket_context = SocketContext::default()
            .with_socket_mark(global_ctx.config.get_flags().socket_mark)
            .with_netns(global_ctx.net_ns.name().map(NetNamespace::new));
        Self {
            global_ctx,
            socket_context,
        }
    }
}

pub(crate) fn native_instance_host(global_ctx: ArcGlobalCtx) -> Arc<NativeInstanceHost> {
    let runtime = native_host_runtime();
    Arc::new(ConnectorHostAdapter::new(
        runtime,
        Arc::new(NativeInstanceEnvironment::new(global_ctx)),
    ))
}

impl ConnectorEnvironment for NativeInstanceEnvironment {
    fn socket_context(&self) -> SocketContext {
        self.socket_context.clone()
    }

    fn mapped_listeners(&self) -> Vec<url::Url> {
        self.global_ctx.config.get_mapped_listeners()
    }

    fn is_local_ip(&self, ip: &IpAddr) -> bool {
        self.global_ctx.is_local_ip(ip)
    }

    fn is_protected_tcp_port(&self, port: u16) -> bool {
        self.global_ctx.is_protected_tcp_port(port)
    }

    fn is_easytier_managed_ipv6(&self, ip: &Ipv6Addr) -> bool {
        self.global_ctx.is_ip_easytier_managed_ipv6(ip)
    }
}
