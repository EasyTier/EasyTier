use std::{net::Ipv4Addr, pin::Pin};

use crate::{
    common::{
        error::Result,
        global_ctx::ArcGlobalCtx,
        ifcfg::{IfConfiger, IfConfiguerTrait},
    },
    tunnels::{
        codec::BytesCodec, common::FramedTunnel, DatagramSink, DatagramStream, Tunnel, TunnelError,
    },
};

use futures::{SinkExt, StreamExt};
use tokio_util::{bytes::Bytes, codec::Framed};
use tun::Device;

use super::tun_codec::{TunPacket, TunPacketCodec};

pub struct VirtualNic {
    dev_name: String,
    queue_num: usize,

    global_ctx: ArcGlobalCtx,

    ifname: Option<String>,
    tun: Option<Box<dyn Tunnel>>,
    ifcfg: Box<dyn IfConfiguerTrait + Send + Sync + 'static>,
}

impl VirtualNic {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            dev_name: "".to_owned(),
            queue_num: 1,
            global_ctx,
            ifname: None,
            tun: None,
            ifcfg: Box::new(IfConfiger {}),
        }
    }

    pub fn set_dev_name(mut self, dev_name: &str) -> Result<Self> {
        self.dev_name = dev_name.to_owned();
        Ok(self)
    }

    pub fn set_queue_num(mut self, queue_num: usize) -> Result<Self> {
        self.queue_num = queue_num;
        Ok(self)
    }

    async fn create_dev_ret_err(&mut self) -> Result<()> {
        let mut config = tun::Configuration::default();
        let has_packet_info = cfg!(target_os = "macos");
        config.layer(tun::Layer::L3);

        #[cfg(target_os = "linux")]
        {
            config.platform(|config| {
                // detect protocol by ourselves for cross platform
                config.packet_information(false);
            });
        }

        if self.queue_num != 1 {
            todo!("queue_num != 1")
        }
        config.queues(self.queue_num);
        config.up();

        let dev = {
            let _g = self.global_ctx.net_ns.guard();
            tun::create_as_async(&config)?
        };
        let ifname = dev.get_ref().name()?;
        self.ifcfg.wait_interface_show(ifname.as_str()).await?;

        let ft: Box<dyn Tunnel> = if has_packet_info {
            let framed = Framed::new(dev, TunPacketCodec::new(true, 2500));
            let (sink, stream) = framed.split();

            let new_stream = stream.map(|item| match item {
                Ok(item) => Ok(item.into_bytes_mut()),
                Err(err) => {
                    println!("tun stream error: {:?}", err);
                    Err(TunnelError::TunError(err.to_string()))
                }
            });

            let new_sink = Box::pin(sink.with(|item: Bytes| async move {
                if false {
                    return Err(TunnelError::TunError("tun sink error".to_owned()));
                }
                Ok(TunPacket::new(super::tun_codec::TunPacketBuffer::Bytes(
                    item,
                )))
            }));

            Box::new(FramedTunnel::new(new_stream, new_sink, None))
        } else {
            let framed = Framed::new(dev, BytesCodec::new(2500));
            let (sink, stream) = framed.split();
            Box::new(FramedTunnel::new(stream, sink, None))
        };

        self.ifname = Some(ifname.to_owned());
        self.tun = Some(ft);

        Ok(())
    }

    pub async fn create_dev(mut self) -> Result<Self> {
        self.create_dev_ret_err().await?;
        Ok(self)
    }

    pub fn ifname(&self) -> &str {
        self.ifname.as_ref().unwrap().as_str()
    }

    pub async fn link_up(&self) -> Result<()> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.set_link_status(self.ifname(), true).await?;
        Ok(())
    }

    pub async fn add_route(&self, address: Ipv4Addr, cidr: u8) -> Result<()> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_route(self.ifname(), address, cidr)
            .await?;
        Ok(())
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Addr>) -> Result<()> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ip(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn add_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<()> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub fn pin_recv_stream(&self) -> Pin<Box<dyn DatagramStream>> {
        self.tun.as_ref().unwrap().pin_stream()
    }

    pub fn pin_send_stream(&self) -> Pin<Box<dyn DatagramSink>> {
        self.tun.as_ref().unwrap().pin_sink()
    }

    pub fn get_ifcfg(&self) -> &dyn IfConfiguerTrait {
        self.ifcfg.as_ref()
    }
}
#[cfg(test)]
mod tests {
    use crate::common::{error::Error, global_ctx::tests::get_mock_global_ctx};

    use super::VirtualNic;

    async fn run_test_helper() -> Result<VirtualNic, Error> {
        let dev = VirtualNic::new(get_mock_global_ctx()).create_dev().await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        dev.link_up().await?;
        dev.remove_ip(None).await?;
        dev.add_ip("10.144.111.1".parse().unwrap(), 24).await?;
        Ok(dev)
    }

    #[tokio::test]
    async fn tun_test() {
        let _dev = run_test_helper().await.unwrap();

        // let mut stream = nic.pin_recv_stream();
        // while let Some(item) = stream.next().await {
        //     println!("item: {:?}", item);
        // }

        // let framed = dev.into_framed();
        // let (mut s, mut b) = framed.split();
        // loop {
        //     let tmp = b.next().await.unwrap().unwrap();
        //     let tmp = EthernetPacket::new(tmp.get_bytes());
        //     println!("ret: {:?}", tmp.unwrap());
        // }
    }
}
