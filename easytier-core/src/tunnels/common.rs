use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    task::{ready, Context, Poll},
};

use async_stream::stream;
use futures::{Future, FutureExt, Sink, SinkExt, Stream, StreamExt};
use tokio::{sync::Mutex, time::error::Elapsed};

use std::pin::Pin;

use crate::tunnels::{SinkError, TunnelError};

use super::{DatagramSink, DatagramStream, SinkItem, StreamT, Tunnel, TunnelInfo};

pub struct FramedTunnel<R, W> {
    read: Arc<Mutex<R>>,
    write: Arc<Mutex<W>>,

    info: Option<TunnelInfo>,
}

impl<R, RE, W, WE> FramedTunnel<R, W>
where
    R: Stream<Item = Result<StreamT, RE>> + Send + Sync + Unpin + 'static,
    W: Sink<SinkItem, Error = WE> + Send + Sync + Unpin + 'static,
    RE: std::error::Error + std::fmt::Debug + Send + Sync + 'static,
    WE: std::error::Error + std::fmt::Debug + Send + Sync + 'static + From<Elapsed>,
{
    pub fn new(read: R, write: W, info: Option<TunnelInfo>) -> Self {
        FramedTunnel {
            read: Arc::new(Mutex::new(read)),
            write: Arc::new(Mutex::new(write)),
            info,
        }
    }

    pub fn new_tunnel_with_info(read: R, write: W, info: TunnelInfo) -> Box<dyn Tunnel> {
        Box::new(FramedTunnel::new(read, write, Some(info)))
    }

    pub fn recv_stream(&self) -> impl DatagramStream {
        let read = self.read.clone();
        let info = self.info.clone();
        stream! {
            loop {
                let read_ret = read.lock().await.next().await;
                if read_ret.is_none() {
                    tracing::info!(?info, "read_ret is none");
                    yield Err(TunnelError::CommonError("recv stream closed".to_string()));
                } else {
                    let read_ret = read_ret.unwrap();
                    if read_ret.is_err() {
                        let err = read_ret.err().unwrap();
                        tracing::info!(?info, "recv stream read error");
                        yield Err(TunnelError::CommonError(err.to_string()));
                    } else {
                        yield Ok(read_ret.unwrap());
                    }
                }
            }
        }
    }

    pub fn send_sink(&self) -> impl DatagramSink {
        struct SendSink<W, WE> {
            write: Arc<Mutex<W>>,
            max_buffer_size: usize,
            sending_buffers: Option<VecDeque<SinkItem>>,
            send_task:
                Option<Pin<Box<dyn Future<Output = Result<(), WE>> + Send + Sync + 'static>>>,
            close_task:
                Option<Pin<Box<dyn Future<Output = Result<(), WE>> + Send + Sync + 'static>>>,
        }

        impl<W, WE> SendSink<W, WE>
        where
            W: Sink<SinkItem, Error = WE> + Send + Sync + Unpin + 'static,
            WE: std::error::Error + std::fmt::Debug + Send + Sync + From<Elapsed>,
        {
            fn try_send_buffser(
                &mut self,
                cx: &mut Context<'_>,
            ) -> Poll<std::result::Result<(), WE>> {
                if self.send_task.is_none() {
                    let mut buffers = self.sending_buffers.take().unwrap();
                    let tun = self.write.clone();
                    let send_task = async move {
                        if buffers.is_empty() {
                            return Ok(());
                        }

                        let mut locked_tun = tun.lock_owned().await;
                        while let Some(buf) = buffers.front() {
                            log::trace!(
                                "try_send buffer, len: {:?}, buf: {:?}",
                                buffers.len(),
                                &buf
                            );
                            let timeout_task = tokio::time::timeout(
                                std::time::Duration::from_secs(1),
                                locked_tun.send(buf.clone()),
                            );
                            let send_res = timeout_task.await;
                            let Ok(send_res) = send_res else {
                                // panic!("send timeout");
                                let err = send_res.err().unwrap();
                                return Err(err.into());
                            };
                            let Ok(_) = send_res else {
                                let err = send_res.err().unwrap();
                                println!("send error: {:?}", err);
                                return Err(err);
                            };
                            buffers.pop_front();
                        }
                        return Ok(());
                    };
                    self.send_task = Some(Box::pin(send_task));
                }

                let ret = ready!(self.send_task.as_mut().unwrap().poll_unpin(cx));
                self.send_task = None;
                self.sending_buffers = Some(VecDeque::new());
                return Poll::Ready(ret);
            }
        }

        impl<W, WE> Sink<SinkItem> for SendSink<W, WE>
        where
            W: Sink<SinkItem, Error = WE> + Send + Sync + Unpin + 'static,
            WE: std::error::Error + std::fmt::Debug + Send + Sync + From<Elapsed>,
        {
            type Error = SinkError;

            fn poll_ready(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                let self_mut = self.get_mut();
                let sending_buf = self_mut.sending_buffers.as_ref();
                // if sending_buffers is None, must already be doing flush
                if sending_buf.is_none() || sending_buf.unwrap().len() > self_mut.max_buffer_size {
                    return self_mut.poll_flush_unpin(cx);
                } else {
                    return Poll::Ready(Ok(()));
                }
            }

            fn start_send(self: Pin<&mut Self>, item: SinkItem) -> Result<(), Self::Error> {
                assert!(self.send_task.is_none());
                let self_mut = self.get_mut();
                self_mut.sending_buffers.as_mut().unwrap().push_back(item);
                Ok(())
            }

            fn poll_flush(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                let self_mut = self.get_mut();
                let ret = self_mut.try_send_buffser(cx);
                match ret {
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(SinkError::CommonError(e.to_string()))),
                    Poll::Pending => {
                        return Poll::Pending;
                    }
                }
            }

            fn poll_close(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<Result<(), Self::Error>> {
                let self_mut = self.get_mut();
                if self_mut.close_task.is_none() {
                    let tun = self_mut.write.clone();
                    let close_task = async move {
                        let mut locked_tun = tun.lock_owned().await;
                        return locked_tun.close().await;
                    };
                    self_mut.close_task = Some(Box::pin(close_task));
                }

                let ret = ready!(self_mut.close_task.as_mut().unwrap().poll_unpin(cx));
                self_mut.close_task = None;

                if ret.is_err() {
                    return Poll::Ready(Err(SinkError::CommonError(
                        ret.err().unwrap().to_string(),
                    )));
                } else {
                    return Poll::Ready(Ok(()));
                }
            }
        }

        SendSink {
            write: self.write.clone(),
            max_buffer_size: 1000,
            sending_buffers: Some(VecDeque::new()),
            send_task: None,
            close_task: None,
        }
    }
}

impl<R, RE, W, WE> Tunnel for FramedTunnel<R, W>
where
    R: Stream<Item = Result<StreamT, RE>> + Send + Sync + Unpin + 'static,
    W: Sink<SinkItem, Error = WE> + Send + Sync + Unpin + 'static,
    RE: std::error::Error + std::fmt::Debug + Send + Sync + 'static,
    WE: std::error::Error + std::fmt::Debug + Send + Sync + 'static + From<Elapsed>,
{
    fn stream(&self) -> Box<dyn DatagramStream> {
        Box::new(self.recv_stream())
    }

    fn sink(&self) -> Box<dyn DatagramSink> {
        Box::new(self.send_sink())
    }

    fn info(&self) -> Option<TunnelInfo> {
        if self.info.is_none() {
            None
        } else {
            Some(self.info.clone().unwrap())
        }
    }
}

pub struct TunnelWithCustomInfo {
    tunnel: Box<dyn Tunnel>,
    info: TunnelInfo,
}

impl TunnelWithCustomInfo {
    pub fn new(tunnel: Box<dyn Tunnel>, info: TunnelInfo) -> Self {
        TunnelWithCustomInfo { tunnel, info }
    }
}

impl Tunnel for TunnelWithCustomInfo {
    fn stream(&self) -> Box<dyn DatagramStream> {
        self.tunnel.stream()
    }

    fn sink(&self) -> Box<dyn DatagramSink> {
        self.tunnel.sink()
    }

    fn info(&self) -> Option<TunnelInfo> {
        Some(self.info.clone())
    }
}

pub(crate) fn get_interface_name_by_ip(local_ip: &IpAddr) -> Option<String> {
    let ifaces = pnet::datalink::interfaces();
    for iface in ifaces {
        for ip in iface.ips {
            if ip.ip() == *local_ip {
                return Some(iface.name);
            }
        }
    }
    None
}

pub(crate) fn setup_sokcet2(
    socket2_socket: &socket2::Socket,
    bind_addr: &SocketAddr,
) -> Result<(), TunnelError> {
    socket2_socket.set_nonblocking(true)?;
    socket2_socket.set_reuse_address(true)?;
    socket2_socket.bind(&socket2::SockAddr::from(*bind_addr))?;

    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    socket2_socket.set_reuse_port(true)?;

    // linux/mac does not use interface of bind_addr to send packet, so we need to bind device
    // win can handle this with bind correctly
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    if let Some(dev_name) = super::common::get_interface_name_by_ip(&bind_addr.ip()) {
        // use IP_BOUND_IF to bind device
        unsafe {
            let dev_idx = nix::libc::if_nametoindex(dev_name.as_str().as_ptr() as *const i8);
            tracing::warn!(?dev_idx, ?dev_name, "bind device");
            socket2_socket.bind_device_by_index_v4(std::num::NonZeroU32::new(dev_idx))?;
            tracing::warn!(?dev_idx, ?dev_name, "bind device doen");
        }
    }

    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    if let Some(dev_name) = super::common::get_interface_name_by_ip(&bind_addr.ip()) {
        tracing::trace!(dev_name = ?dev_name, "bind device");
        socket2_socket.bind_device(Some(dev_name.as_bytes()))?;
    }

    Ok(())
}

pub mod tests {
    use std::time::Instant;

    use futures::SinkExt;
    use tokio_stream::StreamExt;
    use tokio_util::bytes::{BufMut, Bytes, BytesMut};

    use crate::{
        common::netns::NetNS,
        tunnels::{close_tunnel, TunnelConnector, TunnelListener},
    };

    pub async fn _tunnel_echo_server(tunnel: Box<dyn super::Tunnel>, once: bool) {
        let mut recv = Box::into_pin(tunnel.stream());
        let mut send = Box::into_pin(tunnel.sink());

        while let Some(ret) = recv.next().await {
            if ret.is_err() {
                log::trace!("recv error: {:?}", ret.err().unwrap());
                break;
            }
            let res = ret.unwrap();
            log::trace!("recv a msg, try echo back: {:?}", res);
            send.send(Bytes::from(res)).await.unwrap();
            if once {
                break;
            }
        }
        log::warn!("echo server exit...");
    }

    pub(crate) async fn _tunnel_pingpong<L, C>(listener: L, connector: C)
    where
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
    {
        _tunnel_pingpong_netns(listener, connector, NetNS::new(None), NetNS::new(None)).await
    }

    pub(crate) async fn _tunnel_pingpong_netns<L, C>(
        mut listener: L,
        mut connector: C,
        l_netns: NetNS,
        c_netns: NetNS,
    ) where
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
    {
        l_netns
            .run_async(|| async {
                listener.listen().await.unwrap();
            })
            .await;

        let lis = tokio::spawn(async move {
            let ret = listener.accept().await.unwrap();
            assert_eq!(
                ret.info().unwrap().local_addr,
                listener.local_url().to_string()
            );
            _tunnel_echo_server(ret, false).await
        });

        let tunnel = c_netns.run_async(|| connector.connect()).await.unwrap();

        assert_eq!(
            tunnel.info().unwrap().remote_addr,
            connector.remote_url().to_string()
        );

        let mut send = tunnel.pin_sink();
        let mut recv = tunnel.pin_stream();
        let send_data = Bytes::from("abc");
        send.send(send_data).await.unwrap();
        let ret = tokio::time::timeout(tokio::time::Duration::from_secs(1), recv.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        println!("echo back: {:?}", ret);
        assert_eq!(ret, Bytes::from("abc"));

        close_tunnel(&tunnel).await.unwrap();

        if connector.remote_url().scheme() == "udp" {
            lis.abort();
        } else {
            // lis should finish in 1 second
            let ret = tokio::time::timeout(tokio::time::Duration::from_secs(1), lis).await;
            assert!(ret.is_ok());
        }
    }

    pub(crate) async fn _tunnel_bench<L, C>(mut listener: L, mut connector: C)
    where
        L: TunnelListener + Send + Sync + 'static,
        C: TunnelConnector + Send + Sync + 'static,
    {
        listener.listen().await.unwrap();

        let lis = tokio::spawn(async move {
            let ret = listener.accept().await.unwrap();
            _tunnel_echo_server(ret, false).await
        });

        let tunnel = connector.connect().await.unwrap();

        let mut send = tunnel.pin_sink();
        let mut recv = tunnel.pin_stream();

        // prepare a 4k buffer with random data
        let mut send_buf = BytesMut::new();
        for _ in 0..64 {
            send_buf.put_i128(rand::random::<i128>());
        }

        let now = Instant::now();
        let mut count = 0;
        while now.elapsed().as_secs() < 3 {
            send.send(send_buf.clone().freeze()).await.unwrap();
            let _ = recv.next().await.unwrap().unwrap();
            count += 1;
        }
        println!("bps: {}", (count / 1024) * 4 / now.elapsed().as_secs());

        lis.abort();
    }
}
