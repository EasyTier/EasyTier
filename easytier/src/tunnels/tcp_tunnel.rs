use std::net::SocketAddr;

use async_trait::async_trait;
use futures::{stream::FuturesUnordered, StreamExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream};
use tokio_util::codec::{FramedRead, FramedWrite, LengthDelimitedCodec};

use crate::tunnels::common::setup_sokcet2;

use super::{
    check_scheme_and_get_socket_addr, common::FramedTunnel, Tunnel, TunnelInfo, TunnelListener,
};

#[derive(Debug)]
pub struct TcpTunnelListener {
    addr: url::Url,
    listener: Option<TcpListener>,
}

impl TcpTunnelListener {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelListener {
            addr,
            listener: None,
        }
    }
}

#[async_trait]
impl TunnelListener for TcpTunnelListener {
    async fn listen(&mut self) -> Result<(), super::TunnelError> {
        let addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "tcp")?;

        let socket = if addr.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };

        socket.set_reuseaddr(true)?;
        // #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
        // socket.set_reuseport(true)?;
        socket.bind(addr)?;

        self.listener = Some(socket.listen(1024)?);
        Ok(())
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let listener = self.listener.as_ref().unwrap();
        let (stream, _) = listener.accept().await?;
        stream.set_nodelay(true).unwrap();
        let info = TunnelInfo {
            tunnel_type: "tcp".to_owned(),
            local_addr: self.local_url().into(),
            remote_addr: super::build_url_from_socket_addr(&stream.peer_addr()?.to_string(), "tcp")
                .into(),
        };

        let (r, w) = tokio::io::split(stream);
        Ok(FramedTunnel::new_tunnel_with_info(
            FramedRead::new(r, LengthDelimitedCodec::new()),
            FramedWrite::new(w, LengthDelimitedCodec::new()),
            info,
        ))
    }

    fn local_url(&self) -> url::Url {
        self.addr.clone()
    }
}

fn get_tunnel_with_tcp_stream(
    stream: TcpStream,
    remote_url: url::Url,
) -> Result<Box<dyn Tunnel>, super::TunnelError> {
    stream.set_nodelay(true).unwrap();

    let info = TunnelInfo {
        tunnel_type: "tcp".to_owned(),
        local_addr: super::build_url_from_socket_addr(&stream.local_addr()?.to_string(), "tcp")
            .into(),
        remote_addr: remote_url.into(),
    };

    let (r, w) = tokio::io::split(stream);
    Ok(Box::new(FramedTunnel::new_tunnel_with_info(
        FramedRead::new(r, LengthDelimitedCodec::new()),
        FramedWrite::new(w, LengthDelimitedCodec::new()),
        info,
    )))
}

#[derive(Debug)]
pub struct TcpTunnelConnector {
    addr: url::Url,

    bind_addrs: Vec<SocketAddr>,
}

impl TcpTunnelConnector {
    pub fn new(addr: url::Url) -> Self {
        TcpTunnelConnector {
            addr,
            bind_addrs: vec![],
        }
    }

    async fn connect_with_default_bind(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        tracing::info!(addr = ?self.addr, "connect tcp start");
        let addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "tcp")?;
        let stream = TcpStream::connect(addr).await?;
        tracing::info!(addr = ?self.addr, "connect tcp succ");
        return get_tunnel_with_tcp_stream(stream, self.addr.clone().into());
    }

    async fn connect_with_custom_bind(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        let mut futures = FuturesUnordered::new();
        let dst_addr = check_scheme_and_get_socket_addr::<SocketAddr>(&self.addr, "tcp")?;

        for bind_addr in self.bind_addrs.iter() {
            tracing::info!(bind_addr = ?bind_addr, ?dst_addr, "bind addr");

            let socket2_socket = socket2::Socket::new(
                socket2::Domain::for_address(dst_addr),
                socket2::Type::STREAM,
                Some(socket2::Protocol::TCP),
            )?;
            setup_sokcet2(&socket2_socket, bind_addr)?;

            let socket = TcpSocket::from_std_stream(socket2_socket.into());
            futures.push(socket.connect(dst_addr.clone()));
        }

        let Some(ret) = futures.next().await else {
            return Err(super::TunnelError::CommonError(
                "join connect futures failed".to_owned(),
            ));
        };

        return get_tunnel_with_tcp_stream(ret?, self.addr.clone().into());
    }
}

#[async_trait]
impl super::TunnelConnector for TcpTunnelConnector {
    async fn connect(&mut self) -> Result<Box<dyn Tunnel>, super::TunnelError> {
        if self.bind_addrs.is_empty() {
            self.connect_with_default_bind().await
        } else {
            self.connect_with_custom_bind().await
        }
    }

    fn remote_url(&self) -> url::Url {
        self.addr.clone()
    }
    fn set_bind_addrs(&mut self, addrs: Vec<SocketAddr>) {
        self.bind_addrs = addrs;
    }
}

#[cfg(test)]
mod tests {
    use futures::SinkExt;

    use crate::tunnels::{
        common::tests::{_tunnel_bench, _tunnel_pingpong},
        TunnelConnector,
    };

    use super::*;

    #[tokio::test]
    async fn tcp_pingpong() {
        let listener = TcpTunnelListener::new("tcp://0.0.0.0:11011".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://127.0.0.1:11011".parse().unwrap());
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    async fn tcp_bench() {
        let listener = TcpTunnelListener::new("tcp://0.0.0.0:11012".parse().unwrap());
        let connector = TcpTunnelConnector::new("tcp://127.0.0.1:11012".parse().unwrap());
        _tunnel_bench(listener, connector).await
    }

    #[tokio::test]
    async fn tcp_bench_with_bind() {
        let listener = TcpTunnelListener::new("tcp://127.0.0.1:11013".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11013".parse().unwrap());
        connector.set_bind_addrs(vec!["127.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    #[tokio::test]
    #[should_panic]
    async fn tcp_bench_with_bind_fail() {
        let listener = TcpTunnelListener::new("tcp://127.0.0.1:11014".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11014".parse().unwrap());
        connector.set_bind_addrs(vec!["10.0.0.1:0".parse().unwrap()]);
        _tunnel_pingpong(listener, connector).await
    }

    // test slow send lock in framed tunnel
    #[tokio::test]
    async fn tcp_multiple_sender_and_slow_receiver() {
        // console_subscriber::init();
        let mut listener = TcpTunnelListener::new("tcp://127.0.0.1:11014".parse().unwrap());
        let mut connector = TcpTunnelConnector::new("tcp://127.0.0.1:11014".parse().unwrap());

        listener.listen().await.unwrap();
        let t1 = tokio::spawn(async move {
            let t = listener.accept().await.unwrap();
            let mut stream = t.pin_stream();

            let now = tokio::time::Instant::now();

            while let Some(Ok(_)) = stream.next().await {
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                if now.elapsed().as_secs() > 5 {
                    break;
                }
            }

            tracing::info!("t1 exit");
        });

        let tunnel = connector.connect().await.unwrap();
        let mut sink1 = tunnel.pin_sink();
        let t2 = tokio::spawn(async move {
            for i in 0..1000000 {
                let a = sink1.send(b"hello".to_vec().into()).await;
                if a.is_err() {
                    tracing::info!(?a, "t2 exit with err");
                    break;
                }

                if i % 5000 == 0 {
                    tracing::info!(i, "send2 1000");
                }
            }

            tracing::info!("t2 exit");
        });

        let mut sink2 = tunnel.pin_sink();
        let t3 = tokio::spawn(async move {
            for i in 0..1000000 {
                let a = sink2.send(b"hello".to_vec().into()).await;
                if a.is_err() {
                    tracing::info!(?a, "t3 exit with err");
                    break;
                }

                if i % 5000 == 0 {
                    tracing::info!(i, "send2 1000");
                }
            }

            tracing::info!("t3 exit");
        });

        let t4 = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            tracing::info!("closing");
            let close_ret = tunnel.pin_sink().close().await;
            tracing::info!("closed {:?}", close_ret);
        });

        let _ = tokio::join!(t1, t2, t3, t4);
    }
}
