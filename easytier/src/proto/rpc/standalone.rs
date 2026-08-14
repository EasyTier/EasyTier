use std::fmt;

use async_trait::async_trait;
use easytier_core::{
    connectivity::{
        composite::ConnectorRuntime,
        protocol::raw::{
            TcpTunnelDialer, TcpTunnelListener, TunnelDialer, UdpTunnelDialer, UdpTunnelListener,
            upgrade_accepted_byte_stream, upgrade_connected_byte_stream,
        },
    },
    rpc::standalone::StandAloneClient,
    socket::SocketListener,
    socket::udp::{UdpBindOptions, UdpSessionListenRequest},
    tunnel::Tunnel,
};

use crate::{
    host_runtime::{NativeHostRuntime, native_host_runtime},
    socket::tcp::RuntimeTcpSocket,
    tunnel::TunnelUrl,
};

pub use easytier_core::rpc::standalone::{RpcServerHook, StandAloneServer};

pub type RuntimeRpcDialer = TcpTunnelDialer<NativeHostRuntime>;
pub type RuntimeRpcListener = TcpTunnelListener<NativeHostRuntime>;
pub type RuntimeRpcClient = StandAloneClient<RuntimeRpcDialer>;
pub type RuntimeUnixRpcClient = StandAloneClient<RuntimeUnixRpcDialer>;

pub fn runtime_rpc_dialer(remote_url: url::Url) -> RuntimeRpcDialer {
    TcpTunnelDialer::new(remote_url, native_host_runtime(), native_host_runtime())
}

pub fn runtime_rpc_client(remote_url: url::Url) -> RuntimeRpcClient {
    StandAloneClient::new(runtime_rpc_dialer(remote_url))
}

pub fn runtime_unix_rpc_client(remote_url: url::Url) -> RuntimeUnixRpcClient {
    StandAloneClient::new(RuntimeUnixRpcDialer::new(remote_url))
}

pub fn runtime_rpc_listener(local_addr: std::net::SocketAddr) -> RuntimeRpcListener {
    TcpTunnelListener::new(local_addr, native_host_runtime())
}

pub struct RuntimeUnixRpcDialer {
    remote_url: url::Url,
}

impl RuntimeUnixRpcDialer {
    pub fn new(remote_url: url::Url) -> Self {
        Self { remote_url }
    }
}

#[async_trait]
impl TunnelDialer for RuntimeUnixRpcDialer {
    async fn connect(&self) -> anyhow::Result<Box<dyn Tunnel>> {
        if self.remote_url.scheme() != "unix" {
            anyhow::bail!("Unix RPC dialer requires unix:// URL")
        }
        let stream = native_host_runtime()
            .connect_byte_stream(&self.remote_url)
            .await?;
        Ok(upgrade_connected_byte_stream(stream)?)
    }

    fn remote_url(&self) -> url::Url {
        self.remote_url.clone()
    }
}

pub struct RuntimeUnixRpcListener {
    local_url: url::Url,
    #[cfg(unix)]
    inner: Option<tokio::net::UnixListener>,
    bound: bool,
    #[cfg(unix)]
    bound_identity: Option<(u64, u64)>,
}

impl RuntimeUnixRpcListener {
    pub fn new(local_url: url::Url) -> anyhow::Result<Self> {
        anyhow::ensure!(local_url.scheme() == "unix", "RPC portal must use unix://");
        anyhow::ensure!(
            !local_url.path().is_empty(),
            "Unix RPC portal path is required"
        );
        Ok(Self {
            local_url,
            #[cfg(unix)]
            inner: None,
            bound: false,
            #[cfg(unix)]
            bound_identity: None,
        })
    }
}

impl fmt::Debug for RuntimeUnixRpcListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeUnixRpcListener")
            .field("local_url", &self.local_url)
            .field("bound", &self.bound)
            .finish()
    }
}

#[async_trait]
impl SocketListener for RuntimeUnixRpcListener {
    type Accepted = Box<dyn Tunnel>;

    async fn listen(&mut self) -> anyhow::Result<()> {
        #[cfg(not(unix))]
        anyhow::bail!("Unix RPC portals are unsupported on this platform");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};

            if self.inner.is_some() {
                return Ok(());
            }
            let path = std::path::Path::new(self.local_url.path());
            match std::fs::symlink_metadata(path) {
                Ok(metadata) => {
                    anyhow::ensure!(
                        metadata.file_type().is_socket(),
                        "refusing to replace non-socket Unix RPC path {}",
                        path.display()
                    );
                    match tokio::net::UnixStream::connect(path).await {
                        Ok(_) => {
                            anyhow::bail!("Unix RPC portal {} is already in use", path.display())
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionRefused
                                    | std::io::ErrorKind::NotFound
                            ) =>
                        {
                            if let Err(error) = std::fs::remove_file(path)
                                && error.kind() != std::io::ErrorKind::NotFound
                            {
                                return Err(error.into());
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }

            let listener = tokio::net::UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            let metadata = std::fs::symlink_metadata(path)?;
            self.bound_identity = Some((metadata.dev(), metadata.ino()));
            self.inner = Some(listener);
            self.bound = true;
            Ok(())
        }
    }

    async fn accept(&mut self) -> anyhow::Result<Self::Accepted> {
        #[cfg(not(unix))]
        anyhow::bail!("Unix RPC portals are unsupported on this platform");

        #[cfg(unix)]
        {
            let (stream, remote_addr) = self
                .inner
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Unix RPC listener is not started"))?
                .accept()
                .await?;
            let remote_url = crate::socket::tcp::url_from_unix_socket_addr(remote_addr);
            Ok(upgrade_accepted_byte_stream(
                RuntimeTcpSocket::from_unix(stream),
                self.local_url.clone(),
                remote_url,
            )?)
        }
    }

    fn local_url(&self) -> url::Url {
        self.local_url.clone()
    }
}

impl Drop for RuntimeUnixRpcListener {
    fn drop(&mut self) {
        #[cfg(unix)]
        if self.bound {
            use std::os::unix::fs::MetadataExt;

            let path = self.local_url.path();
            if std::fs::symlink_metadata(path)
                .map(|metadata| (metadata.dev(), metadata.ino()))
                .ok()
                == self.bound_identity
            {
                let _ = std::fs::remove_file(path);
            }
        }
    }
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
        connectivity::protocol::raw::TunnelDialer as _, socket::SocketListener as _,
    };

    use crate::proto::rpc::standalone::{
        RuntimeUnixRpcDialer, RuntimeUnixRpcListener, StandAloneServer, runtime_rpc_dialer,
        runtime_rpc_listener, runtime_udp_tunnel_dialer, runtime_udp_tunnel_listener,
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

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_unix_rpc_endpoints_connect_with_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rpc.sock");
        let url: url::Url = format!("unix://{}", path.display()).parse().unwrap();
        let mut listener = RuntimeUnixRpcListener::new(url.clone()).unwrap();
        listener.listen().await.unwrap();

        let dialer = RuntimeUnixRpcDialer::new(url.clone());
        let (accepted, connected) = tokio::try_join!(listener.accept(), dialer.connect()).unwrap();
        assert_eq!(
            accepted.info().unwrap().local_addr.unwrap().url,
            url.as_str()
        );
        assert_eq!(
            connected.info().unwrap().remote_addr.unwrap().url,
            url.as_str()
        );
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        drop(listener);
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_unix_rpc_listener_refuses_non_socket_path() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rpc.sock");
        std::fs::write(&path, b"not a socket").unwrap();
        let url: url::Url = format!("unix://{}", path.display()).parse().unwrap();
        let mut listener = RuntimeUnixRpcListener::new(url).unwrap();

        let error = listener.listen().await.unwrap_err();
        assert!(error.to_string().contains("refusing to replace non-socket"));
        assert_eq!(std::fs::read(path).unwrap(), b"not a socket");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn runtime_unix_rpc_listener_does_not_remove_replacement_socket() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("rpc.sock");
        let url: url::Url = format!("unix://{}", path.display()).parse().unwrap();
        let mut listener = RuntimeUnixRpcListener::new(url).unwrap();
        listener.listen().await.unwrap();

        std::fs::remove_file(&path).unwrap();
        let replacement = tokio::net::UnixListener::bind(&path).unwrap();
        drop(listener);

        assert!(path.exists());
        drop(replacement);
    }
}
