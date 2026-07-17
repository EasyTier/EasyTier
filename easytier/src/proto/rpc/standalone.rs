use easytier_core::{
    connectivity::protocol::raw::{
        TcpTunnelDialer, TcpTunnelListener, TunnelDialer, UdpTunnelDialer, UdpTunnelListener,
    },
    listener::SocketListener,
    rpc::standalone::StandAloneClient,
    socket::udp::{UdpBindOptions, UdpSessionListenRequest},
    tunnel::Tunnel,
};

use crate::{
    host_runtime::{NativeHostRuntime, native_host_runtime},
    tunnel::TunnelUrl,
};

pub use easytier_core::rpc::standalone::{RpcServerHook, StandAloneServer};

pub type RuntimeRpcDialer = TcpTunnelDialer<NativeHostRuntime>;
pub type RuntimeRpcListener = TcpTunnelListener<NativeHostRuntime>;
pub type RuntimeRpcClient = StandAloneClient<RuntimeRpcDialer>;

pub fn runtime_rpc_dialer(remote_url: url::Url) -> RuntimeRpcDialer {
    TcpTunnelDialer::new(remote_url, native_host_runtime(), native_host_runtime())
}

pub fn runtime_rpc_client(remote_url: url::Url) -> RuntimeRpcClient {
    StandAloneClient::new(runtime_rpc_dialer(remote_url))
}

pub fn runtime_rpc_listener(local_addr: std::net::SocketAddr) -> RuntimeRpcListener {
    TcpTunnelListener::new(local_addr, native_host_runtime())
}

pub fn runtime_udp_tunnel_dialer(remote_url: url::Url) -> impl TunnelDialer {
    UdpTunnelDialer::new(remote_url, native_host_runtime(), native_host_runtime())
}

pub fn runtime_udp_tunnel_listener(
    local_url: url::Url,
    local_addr: std::net::SocketAddr,
) -> impl SocketListener<Accepted = Box<dyn Tunnel>> {
    let bind = UdpBindOptions::port_bound_listener(local_addr)
        .with_bind_device(TunnelUrl::from(local_url.clone()).bind_dev())
        .with_only_v6(true);
    UdpTunnelListener::new_with_request(
        local_url,
        UdpSessionListenRequest::new(bind),
        native_host_runtime(),
    )
}

#[cfg(test)]
mod tests {
    use easytier_core::{
        connectivity::protocol::raw::TunnelDialer as _, listener::SocketListener as _,
    };

    use crate::proto::rpc::standalone::{
        StandAloneServer, runtime_rpc_dialer, runtime_rpc_listener, runtime_udp_tunnel_dialer,
        runtime_udp_tunnel_listener,
    };

    #[tokio::test]
    async fn standalone_exit_on_drop() {
        let addr = "0.0.0.0:53884".parse().unwrap();
        let tunnel = runtime_rpc_listener(addr);
        let mut server = StandAloneServer::new(tunnel);
        server.serve().await.unwrap();
        drop(server);

        // tcp should closed
        let connector = runtime_rpc_dialer("tcp://0.0.0.0:53884".parse().unwrap());
        connector.connect().await.unwrap_err();
    }

    #[tokio::test]
    async fn standalone_ipv4_and_ipv6_listeners_share_port() {
        let mut ipv6 = runtime_rpc_listener("[::]:0".parse().unwrap());
        ipv6.listen().await.unwrap();
        let port = ipv6.local_url().port().unwrap();

        let mut ipv4 = runtime_rpc_listener(format!("0.0.0.0:{port}").parse().unwrap());
        ipv4.listen().await.unwrap();
    }

    #[tokio::test]
    async fn runtime_udp_tunnel_endpoints_connect() {
        let local_url = "udp://127.0.0.1:0".parse().unwrap();
        let mut listener = runtime_udp_tunnel_listener(local_url, "127.0.0.1:0".parse().unwrap());
        listener.listen().await.unwrap();
        let listener_url = listener.local_url();
        let dialer = runtime_udp_tunnel_dialer(listener_url.clone());

        let (accepted, connected) =
            tokio::time::timeout(std::time::Duration::from_secs(5), async {
                tokio::try_join!(listener.accept(), dialer.connect())
            })
            .await
            .unwrap()
            .unwrap();

        assert_eq!(
            accepted.info().unwrap().local_addr.unwrap().url,
            listener_url.as_str()
        );
        assert_eq!(
            connected.info().unwrap().remote_addr.unwrap().url,
            listener_url.as_str()
        );
    }
}
