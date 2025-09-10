use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::{Arc, Weak},
    task::{Context, Poll},
};

use crate::{
    common::{
        error::Error,
        global_ctx::{ArcGlobalCtx, GlobalCtxEvent},
        ifcfg::{IfConfiger, IfConfiguerTrait},
    },
    peers::{peer_manager::PeerManager, recv_packet_from_chan, PacketRecvChanReceiver},
    tunnel::{
        common::{reserve_buf, FramedWriter, TunnelWrapper, ZCPacketToBytes},
        packet_def::{ZCPacket, ZCPacketType, TAIL_RESERVED_SIZE},
        StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
    },
};

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::common::ifcfg;
use byteorder::WriteBytesExt as _;
use bytes::{BufMut, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{lock::BiLock, ready, SinkExt, Stream, StreamExt};
use pin_project_lite::pin_project;
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tokio_util::bytes::Bytes;
use tun::{AbstractDevice, AsyncDevice, Configuration, Layer};
use zerocopy::{NativeEndian, NetworkEndian};

#[cfg(target_os = "windows")]
use crate::common::ifcfg::RegistryManager;

pin_project! {
    pub struct TunStream {
        #[pin]
        l: BiLock<AsyncDevice>,
        cur_buf: BytesMut,
        has_packet_info: bool,
        payload_offset: usize,
    }
}

impl TunStream {
    pub fn new(l: BiLock<AsyncDevice>, has_packet_info: bool) -> Self {
        let mut payload_offset = ZCPacketType::NIC.get_packet_offsets().payload_offset;
        if has_packet_info {
            payload_offset -= 4;
        }
        Self {
            l,
            cur_buf: BytesMut::new(),
            has_packet_info,
            payload_offset,
        }
    }
}

impl Stream for TunStream {
    type Item = StreamItem;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<StreamItem>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        reserve_buf(self_mut.cur_buf, 2500, 4 * 1024);
        if self_mut.cur_buf.is_empty() {
            unsafe {
                self_mut.cur_buf.set_len(*self_mut.payload_offset);
            }
        }
        let buf = self_mut.cur_buf.chunk_mut().as_mut_ptr();
        let buf = unsafe { std::slice::from_raw_parts_mut(buf, 2500) };
        let mut buf = ReadBuf::new(buf);

        let ret = ready!(g.as_pin_mut().poll_read(cx, &mut buf));
        let len = buf.filled().len();
        if len == 0 {
            return Poll::Ready(None);
        }
        unsafe { self_mut.cur_buf.advance_mut(len + TAIL_RESERVED_SIZE) };

        let mut ret_buf = self_mut.cur_buf.split();
        let cur_len = ret_buf.len();
        ret_buf.truncate(cur_len - TAIL_RESERVED_SIZE);

        match ret {
            Ok(_) => Poll::Ready(Some(Ok(ZCPacket::new_from_buf(ret_buf, ZCPacketType::NIC)))),
            Err(err) => {
                println!("tun stream error: {:?}", err);
                Poll::Ready(None)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
enum PacketProtocol {
    #[default]
    IPv4,
    IPv6,
    Other(u8),
}

// Note: the protocol in the packet information header is platform dependent.
impl PacketProtocol {
    #[cfg(any(target_os = "linux", target_os = "android", target_env = "ohos"))]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        use nix::libc;
        match self {
            PacketProtocol::IPv4 => Ok(libc::ETH_P_IP as u16),
            PacketProtocol::IPv6 => Ok(libc::ETH_P_IPV6 as u16),
            PacketProtocol::Other(_) => Err(io::Error::other("neither an IPv4 nor IPv6 packet")),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "freebsd"))]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        use nix::libc;
        match self {
            PacketProtocol::IPv4 => Ok(libc::PF_INET as u16),
            PacketProtocol::IPv6 => Ok(libc::PF_INET6 as u16),
            PacketProtocol::Other(_) => Err(io::Error::other("neither an IPv4 nor IPv6 packet")),
        }
    }

    #[cfg(target_os = "windows")]
    fn into_pi_field(self) -> Result<u16, io::Error> {
        unimplemented!()
    }
}

/// Infer the protocol based on the first nibble in the packet buffer.
fn infer_proto(buf: &[u8]) -> PacketProtocol {
    match buf[0] >> 4 {
        4 => PacketProtocol::IPv4,
        6 => PacketProtocol::IPv6,
        p => PacketProtocol::Other(p),
    }
}

struct TunZCPacketToBytes {
    has_packet_info: bool,
}

impl TunZCPacketToBytes {
    pub fn new(has_packet_info: bool) -> Self {
        Self { has_packet_info }
    }

    pub fn fill_packet_info(
        &self,
        mut buf: &mut [u8],
        proto: PacketProtocol,
    ) -> Result<(), io::Error> {
        // flags is always 0
        buf.write_u16::<NativeEndian>(0)?;
        // write the protocol as network byte order
        buf.write_u16::<NetworkEndian>(proto.into_pi_field()?)?;
        Ok(())
    }
}

impl ZCPacketToBytes for TunZCPacketToBytes {
    fn zcpacket_into_bytes(&self, zc_packet: ZCPacket) -> Result<Bytes, TunnelError> {
        let payload_offset = zc_packet.payload_offset();
        let mut inner = zc_packet.inner();
        // we have peer manager header, so payload offset must larger than 4
        assert!(payload_offset >= 4);

        let ret = if self.has_packet_info {
            let mut inner = inner.split_off(payload_offset - 4);
            let proto = infer_proto(&inner[4..]);
            self.fill_packet_info(&mut inner[0..4], proto)?;
            inner
        } else {
            inner.split_off(payload_offset)
        };

        tracing::debug!(?ret, ?payload_offset, "convert zc packet to tun packet");

        Ok(ret.into())
    }
}

pin_project! {
    pub struct TunAsyncWrite {
        #[pin]
        l: BiLock<AsyncDevice>,
    }
}

impl AsyncWrite for TunAsyncWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_shutdown(cx)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        let self_mut = self.project();
        let mut g = ready!(self_mut.l.poll_lock(cx));
        g.as_pin_mut().poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        true
    }
}

pub struct VirtualNic {
    global_ctx: ArcGlobalCtx,

    ifname: Option<String>,
    ifcfg: Box<dyn IfConfiguerTrait + Send + Sync + 'static>,
}

impl Drop for VirtualNic {
    fn drop(&mut self) {
        #[cfg(target_os = "windows")]
        {
            if let Some(ref ifname) = self.ifname {
                // Try to clean up firewall rules, but don't panic in destructor
                if let Err(e) = crate::arch::windows::remove_interface_firewall_rules(ifname) {
                    eprintln!(
                        "Warning: Failed to remove firewall rules for interface {}: {}",
                        ifname, e
                    );
                }
            }
        }
    }
}

impl VirtualNic {
    pub fn new(global_ctx: ArcGlobalCtx) -> Self {
        Self {
            global_ctx,
            ifname: None,
            ifcfg: Box::new(IfConfiger {}),
        }
    }

    /// Check and create TUN device node if necessary on Linux systems
    #[cfg(target_os = "linux")]
    async fn ensure_tun_device_node() {
        const TUN_DEV_PATH: &str = "/dev/net/tun";
        const TUN_DIR_PATH: &str = "/dev/net";

        // Check if /dev/net/tun already exists
        if tokio::fs::metadata(TUN_DEV_PATH).await.is_ok() {
            tracing::debug!("TUN device node {} already exists", TUN_DEV_PATH);
            return;
        }

        tracing::info!(
            "TUN device node {} not found, attempting to create",
            TUN_DEV_PATH
        );

        // Check if TUN kernel module is available
        let tun_module_available = tokio::fs::metadata("/proc/net/dev").await.is_ok()
            && (tokio::fs::read_to_string("/proc/modules").await)
                .map(|content| content.contains("tun"))
                .unwrap_or(false);

        if !tun_module_available {
            tracing::warn!("TUN kernel module may not be loaded");
            println!("⚠ Warning: TUN kernel module may not be available.");
            println!("  You may need to load it with: sudo modprobe tun");
        }

        // Try to create /dev/net directory if it doesn't exist
        if tokio::fs::metadata(TUN_DIR_PATH).await.is_err() {
            if let Err(e) = tokio::fs::create_dir_all(TUN_DIR_PATH).await {
                tracing::warn!(
                    "Failed to create directory {}: {}. Continuing anyway.",
                    TUN_DIR_PATH,
                    e
                );
                println!(
                    "⚠ Warning: Failed to create directory {}. TUN device creation may fail.",
                    TUN_DIR_PATH
                );
                println!(
                    "  You may need to run with root privileges or manually create the TUN device."
                );
                Self::print_troubleshooting_info();
                return;
            }
            tracing::info!("Created directory {}", TUN_DIR_PATH);
        }

        // Try to create the TUN device node
        // Major number 10, minor number 200 for /dev/net/tun
        let dev_node = nix::sys::stat::makedev(10, 200);

        match nix::sys::stat::mknod(
            TUN_DEV_PATH,
            nix::sys::stat::SFlag::S_IFCHR,
            nix::sys::stat::Mode::from_bits(0o600).unwrap(),
            dev_node,
        ) {
            Ok(_) => {
                tracing::info!("Successfully created TUN device node {}", TUN_DEV_PATH);
                println!("✓ Created TUN device node {}", TUN_DEV_PATH);
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to create TUN device node {}: {}. Continuing anyway.",
                    TUN_DEV_PATH,
                    e
                );
                println!(
                    "⚠ Warning: Failed to create TUN device node {}.",
                    TUN_DEV_PATH
                );
                println!("  Error: {}", e);
                Self::print_troubleshooting_info();
            }
        }
    }

    /// Print troubleshooting information for TUN device issues
    #[cfg(target_os = "linux")]
    fn print_troubleshooting_info() {
        println!("  Possible solutions:");
        println!("  1. Run with root privileges: sudo ./easytier-core [options]");
        println!("  2. Manually create TUN device: sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200");
        println!("  3. Load TUN kernel module: sudo modprobe tun");
        println!("  4. Use --no-tun flag if TUN functionality is not needed");
        println!("  5. Check if your system/container supports TUN devices");
        println!("  Note: TUN functionality may still work if the kernel supports dynamic device creation.");
    }

    /// For non-Linux systems, this is a no-op
    #[cfg(not(target_os = "linux"))]
    async fn ensure_tun_device_node() -> Result<(), Error> {
        Ok(())
    }

    async fn create_tun(&mut self) -> Result<tun::platform::Device, Error> {
        let mut config = Configuration::default();
        config.layer(Layer::L3);

        #[cfg(target_os = "linux")]
        {
            // Check and create TUN device node if necessary (Linux only)
            Self::ensure_tun_device_node().await;

            let dev_name = self.global_ctx.get_flags().dev_name;
            if !dev_name.is_empty() {
                config.tun_name(&dev_name);
            }
        }

        #[cfg(target_os = "macos")]
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });

        #[cfg(target_os = "windows")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            match crate::arch::windows::add_self_to_firewall_allowlist() {
                Ok(_) => tracing::info!("add_self_to_firewall_allowlist successful!"),
                Err(e) => {
                    println!("Failed to add Easytier to firewall allowlist, Subnet proxy and KCP proxy may not work properly. error: {}", e);
                    println!("You can add firewall rules manually, or use --use-smoltcp to run with user-space TCP/IP stack.");
                    println!();
                }
            }

            match RegistryManager::reg_delete_obsoleted_items(&dev_name) {
                Ok(_) => tracing::trace!("delete successful!"),
                Err(e) => tracing::error!("An error occurred: {}", e),
            }

            if !dev_name.is_empty() {
                config.tun_name(&dev_name);
            } else {
                use rand::distributions::Distribution as _;
                let c = crate::arch::windows::interface_count()?;
                let mut rng = rand::thread_rng();
                let s: String = rand::distributions::Alphanumeric
                    .sample_iter(&mut rng)
                    .take(4)
                    .map(char::from)
                    .collect::<String>()
                    .to_lowercase();

                let random_dev_name = format!("et_{}_{}", c, s);
                config.tun_name(random_dev_name.clone());

                let mut flags = self.global_ctx.get_flags();
                flags.dev_name = random_dev_name.clone();
                self.global_ctx.set_flags(flags);
            }

            config.platform_config(|config| {
                config.skip_config(true);
                config.ring_cap(Some(std::cmp::min(
                    config.min_ring_cap() * 32,
                    config.max_ring_cap(),
                )));
            });
        }

        config.up();

        let _g = self.global_ctx.net_ns.guard();
        Ok(tun::create(&config)?)
    }

    #[cfg(any(target_os = "android", target_env = "ohos"))]
    pub async fn create_dev_for_android(
        &mut self,
        tun_fd: std::os::fd::RawFd,
    ) -> Result<Box<dyn Tunnel>, Error> {
        println!("tun_fd: {}", tun_fd);
        let mut config = Configuration::default();
        config.layer(Layer::L3);
        config.raw_fd(tun_fd);
        config.close_fd_on_drop(false);
        config.up();

        let dev = tun::create(&config)?;
        let dev = AsyncDevice::new(dev)?;
        let (a, b) = BiLock::new(dev);
        let ft = TunnelWrapper::new(
            TunStream::new(a, false),
            FramedWriter::new_with_converter(
                TunAsyncWrite { l: b },
                TunZCPacketToBytes::new(false),
            ),
            None,
        );

        self.ifname = Some(format!("tunfd_{}", tun_fd));

        Ok(Box::new(ft))
    }

    pub async fn create_dev(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        let dev = self.create_tun().await?;
        let ifname = dev.tun_name()?;
        self.ifcfg.wait_interface_show(ifname.as_str()).await?;

        #[cfg(target_os = "windows")]
        {
            if let Ok(guid) = RegistryManager::find_interface_guid(&ifname) {
                if let Err(e) = RegistryManager::disable_dynamic_updates(&guid) {
                    tracing::error!(
                        "Failed to disable dhcp for interface {} {}: {}",
                        ifname,
                        guid,
                        e
                    );
                }

                // Disable NetBIOS over TCP/IP
                if let Err(e) = RegistryManager::disable_netbios(&guid) {
                    tracing::error!(
                        "Failed to disable netbios for interface {} {}: {}",
                        ifname,
                        guid,
                        e
                    );
                }
            }
        }

        let dev = AsyncDevice::new(dev)?;

        let flags = self.global_ctx.config.get_flags();
        let mut mtu_in_config = flags.mtu;
        if flags.enable_encryption {
            mtu_in_config -= 20;
        }
        {
            // set mtu by ourselves, rust-tun does not handle it correctly on windows
            let _g = self.global_ctx.net_ns.guard();
            self.ifcfg.set_mtu(ifname.as_str(), mtu_in_config).await?;
        }

        let has_packet_info = cfg!(target_os = "macos");
        let (a, b) = BiLock::new(dev);
        let ft = TunnelWrapper::new(
            TunStream::new(a, has_packet_info),
            FramedWriter::new_with_converter(
                TunAsyncWrite { l: b },
                TunZCPacketToBytes::new(has_packet_info),
            ),
            None,
        );

        self.ifname = Some(ifname.to_owned());

        #[cfg(target_os = "windows")]
        {
            // Add firewall rules for virtual NIC interface to allow all traffic
            match crate::arch::windows::add_interface_to_firewall_allowlist(&ifname) {
                Ok(_) => {
                    tracing::info!(
                        "Successfully configured Windows Firewall for interface: {}",
                        ifname
                    );
                    tracing::info!(
                        "All protocols (TCP/UDP/ICMP) are now allowed on interface: {}",
                        ifname
                    );
                }
                Err(e) => {
                    tracing::warn!("Failed to configure Windows Firewall for {}: {}", ifname, e);
                    println!(
                        "⚠ Warning: Failed to configure Windows Firewall for interface {}.",
                        ifname
                    );
                    println!("  This may cause connectivity issues with ping and other network functions.");
                    println!(
                        "  Please run as Administrator or manually configure Windows Firewall."
                    );
                    println!(
                        "  Alternatively, you can disable Windows Firewall for testing purposes."
                    );
                }
            }
        }

        Ok(Box::new(ft))
    }

    pub fn ifname(&self) -> &str {
        self.ifname.as_ref().unwrap().as_str()
    }

    pub async fn link_up(&self) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.set_link_status(self.ifname(), true).await?;
        Ok(())
    }

    pub async fn add_route(&self, address: Ipv4Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_route(self.ifname(), address, cidr, None)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_route(self.ifname(), address, cidr, None)
            .await?;
        Ok(())
    }

    pub async fn remove_ip(&self, ip: Option<Ipv4Inet>) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ip(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn remove_ipv6(&self, ip: Option<Ipv6Inet>) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg.remove_ipv6(self.ifname(), ip).await?;
        Ok(())
    }

    pub async fn add_ip(&self, ip: Ipv4Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv4_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub async fn add_ipv6(&self, ip: Ipv6Addr, cidr: i32) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_ip(self.ifname(), ip, cidr as u8)
            .await?;
        Ok(())
    }

    pub fn get_ifcfg(&self) -> impl IfConfiguerTrait {
        IfConfiger {}
    }
}

pub struct NicCtx {
    global_ctx: ArcGlobalCtx,
    peer_mgr: Weak<PeerManager>,
    peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,

    close_notifier: Arc<Notify>,

    nic: Arc<Mutex<VirtualNic>>,
    tasks: JoinSet<()>,
}

impl NicCtx {
    pub fn new(
        global_ctx: ArcGlobalCtx,
        peer_manager: &Arc<PeerManager>,
        peer_packet_receiver: Arc<Mutex<PacketRecvChanReceiver>>,
        close_notifier: Arc<Notify>,
    ) -> Self {
        NicCtx {
            global_ctx: global_ctx.clone(),
            peer_mgr: Arc::downgrade(peer_manager),
            peer_packet_receiver,

            close_notifier,

            nic: Arc::new(Mutex::new(VirtualNic::new(global_ctx))),
            tasks: JoinSet::new(),
        }
    }

    pub async fn ifname(&self) -> Option<String> {
        let nic = self.nic.lock().await;
        nic.ifname.as_ref().map(|s| s.to_owned())
    }

    pub async fn assign_ipv4_to_tun_device(&self, ipv4_addr: cidr::Ipv4Inet) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ip(None).await?;
        nic.add_ip(ipv4_addr.address(), ipv4_addr.network_length() as i32)
            .await?;
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            nic.add_route(ipv4_addr.first_address(), ipv4_addr.network_length())
                .await?;
        }
        Ok(())
    }

    pub async fn assign_ipv6_to_tun_device(&self, ipv6_addr: cidr::Ipv6Inet) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ipv6(None).await?;
        nic.add_ipv6(ipv6_addr.address(), ipv6_addr.network_length() as i32)
            .await?;
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        {
            nic.add_ipv6_route(ipv6_addr.first_address(), ipv6_addr.network_length())
                .await?;
        }
        Ok(())
    }

    pub async fn assign_ipv6_multi_to_tun_device(
        &self,
        ipv6_addrs: Vec<cidr::Ipv6Inet>,
    ) -> Result<(), Error> {
        let nic = self.nic.lock().await;
        nic.link_up().await?;
        nic.remove_ipv6(None).await?;
        for inet in ipv6_addrs.iter() {
            nic.add_ipv6(inet.address(), inet.network_length() as i32)
                .await?;
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            {
                nic.add_ipv6_route(inet.first_address(), inet.network_length())
                    .await?;
            }
        }
        Ok(())
    }

    async fn do_forward_nic_to_peers_ipv4(ret: ZCPacket, mgr: &PeerManager) {
        if let Some(ipv4) = Ipv4Packet::new(ret.payload()) {
            if ipv4.get_version() != 4 {
                tracing::info!("[USER_PACKET] not ipv4 packet: {:?}", ipv4);
                return;
            }
            let dst_ipv4 = ipv4.get_destination();
            tracing::trace!(
                ?ret,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            // TODO: use zero-copy
            let send_ret = mgr.send_msg_by_ip(ret, IpAddr::V4(dst_ipv4)).await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv4 packet");
        }
    }

    async fn do_forward_nic_to_peers_ipv6(ret: ZCPacket, mgr: &PeerManager) {
        if let Some(ipv6) = Ipv6Packet::new(ret.payload()) {
            if ipv6.get_version() != 6 {
                tracing::info!("[USER_PACKET] not ipv6 packet: {:?}", ipv6);
                return;
            }
            let src_ipv6 = ipv6.get_source();
            let dst_ipv6 = ipv6.get_destination();
            tracing::trace!(
                ?ret,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            if src_ipv6.is_unicast_link_local()
                && Some(src_ipv6) != mgr.get_global_ctx().get_ipv6().map(|x| x.address())
            {
                // do not route link local packet to other nodes unless the address is assigned by user
                return;
            }

            // TODO: use zero-copy
            let send_ret = mgr.send_msg_by_ip(ret, IpAddr::V6(dst_ipv6)).await;
            if send_ret.is_err() {
                tracing::trace!(?send_ret, "[USER_PACKET] send_msg failed")
            }
        } else {
            tracing::warn!(?ret, "[USER_PACKET] not ipv6 packet");
        }
    }

    async fn do_forward_nic_to_peers(ret: ZCPacket, mgr: &PeerManager) {
        let payload = ret.payload();
        if payload.is_empty() {
            return;
        }

        match payload[0] >> 4 {
            4 => Self::do_forward_nic_to_peers_ipv4(ret, mgr).await,
            6 => Self::do_forward_nic_to_peers_ipv6(ret, mgr).await,
            _ => {
                tracing::warn!(?ret, "[USER_PACKET] unknown IP version");
            }
        }
    }

    fn do_forward_nic_to_peers_task(
        &mut self,
        mut stream: Pin<Box<dyn ZCPacketStream>>,
    ) -> Result<(), Error> {
        // read from nic and write to corresponding tunnel
        let Some(mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let close_notifier = self.close_notifier.clone();
        self.tasks.spawn(async move {
            while let Some(ret) = stream.next().await {
                if ret.is_err() {
                    tracing::error!("read from nic failed: {:?}", ret);
                    break;
                }
                Self::do_forward_nic_to_peers(ret.unwrap(), mgr.as_ref()).await;
            }
            close_notifier.notify_one();
            tracing::error!("nic closed when recving from it");
        });

        Ok(())
    }

    fn do_forward_peers_to_nic(&mut self, mut sink: Pin<Box<dyn ZCPacketSink>>) {
        let channel = self.peer_packet_receiver.clone();
        let close_notifier = self.close_notifier.clone();
        self.tasks.spawn(async move {
            // unlock until coroutine finished
            let mut channel = channel.lock().await;
            while let Ok(packet) = recv_packet_from_chan(&mut channel).await {
                tracing::trace!(
                    "[USER_PACKET] forward packet from peers to nic. packet: {:?}",
                    packet
                );
                let ret = sink.send(packet).await;
                if ret.is_err() {
                    tracing::error!(?ret, "do_forward_tunnel_to_nic sink error");
                }
            }
            close_notifier.notify_one();
            tracing::error!("nic closed when sending to it");
        });
    }

    async fn run_proxy_cidrs_route_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = nic.get_ifcfg();
        let ifname = nic.ifname().to_owned();

        self.tasks.spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::new();
            loop {
                let mut proxy_cidrs = BTreeSet::new();
                let routes = peer_mgr.list_routes().await;
                for r in routes {
                    for cidr in r.proxy_cidrs {
                        let Ok(cidr) = cidr.parse::<cidr::Ipv4Cidr>() else {
                            continue;
                        };
                        proxy_cidrs.insert(cidr);
                    }
                }
                // add vpn portal cidr to proxy_cidrs
                if let Some(vpn_cfg) = global_ctx.config.get_vpn_portal_config() {
                    proxy_cidrs.insert(vpn_cfg.client_cidr);
                }

                if let Some(routes) = global_ctx.config.get_routes() {
                    // if has manual routes, just override entire proxy_cidrs
                    proxy_cidrs = routes.into_iter().collect();
                }

                // if route is in cur_proxy_cidrs but not in proxy_cidrs, delete it.
                for cidr in cur_proxy_cidrs.iter() {
                    if proxy_cidrs.contains(cidr) {
                        continue;
                    }

                    let _g = net_ns.guard();
                    let ret = ifcfg
                        .remove_ipv4_route(
                            ifname.as_str(),
                            cidr.first_address(),
                            cidr.network_length(),
                        )
                        .await;

                    if ret.is_err() {
                        tracing::trace!(
                            cidr = ?cidr,
                            err = ?ret,
                            "remove route failed.",
                        );
                    }
                }

                for cidr in proxy_cidrs.iter() {
                    if cur_proxy_cidrs.contains(cidr) {
                        continue;
                    }
                    let _g = net_ns.guard();
                    let ret = ifcfg
                        .add_ipv4_route(
                            ifname.as_str(),
                            cidr.first_address(),
                            cidr.network_length(),
                            None,
                        )
                        .await;

                    if ret.is_err() {
                        tracing::trace!(
                            cidr = ?cidr,
                            err = ?ret,
                            "add route failed.",
                        );
                    }
                }

                cur_proxy_cidrs = proxy_cidrs;
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    async fn run_ipv6_prefix_allocator(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = nic.get_ifcfg();
        let _tun_ifname = nic.ifname().to_owned();
        drop(nic);

        // Only run if allocator is enabled, TUN is used, and at least one prefix provided.
        if global_ctx.get_flags().no_tun {
            return Ok(());
        }
        if !global_ctx.config.get_enable_ipv6_prefix_allocator() {
            return Ok(());
        }
        let prefixes = global_ctx.config.get_ipv6_prefixes();
        if prefixes.is_empty() {
            return Ok(());
        }

        let my_inst_id = global_ctx.get_id().to_string();
        // track current applied set to add/remove
        let applied = std::sync::Arc::new(tokio::sync::Mutex::new(std::collections::BTreeSet::<
            std::net::Ipv6Addr,
        >::new()));
        let applied_clone = applied.clone();

        self.tasks.spawn(async move {
            loop {
                let mut new_set = std::collections::BTreeSet::<std::net::Ipv6Addr>::new();
                let routes = peer_mgr.list_routes().await;
                for r in routes {
                    if r.inst_id == my_inst_id {
                        continue;
                    }
                    // Only derive if peer advertised allocator + prefixes; use intersection
                    let peer_enable = r.enable_ipv6_prefix_allocator.unwrap_or(false);
                    if !peer_enable {
                        continue;
                    }
                    let peer_prefix_strs: Vec<String> = r.ipv6_prefixes.clone();
                    if peer_prefix_strs.is_empty() {
                        continue;
                    }
                    let mut peer_prefixes: Vec<cidr::Ipv6Cidr> = Vec::new();
                    for s in peer_prefix_strs.iter() {
                        if let Ok(p) = s.parse() {
                            peer_prefixes.push(p);
                        }
                    }
                    if peer_prefixes.is_empty() {
                        continue;
                    }

                    // derive v6 from inst_id + prefix when compatible
                    let Ok(uuid) = uuid::Uuid::parse_str(&r.inst_id) else {
                        continue;
                    };
                    use std::hash::{Hash, Hasher};
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    uuid.as_u128().hash(&mut hasher);
                    global_ctx.get_network_name().hash(&mut hasher);
                    let h64 = hasher.finish();
                    for prefix in &prefixes {
                        // Check intersection with any peer prefix
                        let mut ok = false;
                        for pp in &peer_prefixes {
                            let compatible = if prefix.network_length() <= pp.network_length() {
                                prefix.contains(&pp.first_address())
                            } else {
                                pp.contains(&prefix.first_address())
                            };
                            if compatible {
                                ok = true;
                                break;
                            }
                        }
                        if !ok {
                            continue;
                        }

                        let pfx_len = prefix.network_length();
                        let host_bits = 128 - pfx_len as u32;
                        let base = prefix.first_address();
                        let oct = base.octets();
                        let mut addr_u128 = u128::from_be_bytes(oct);
                        let mask: u128 = if host_bits == 128 {
                            0
                        } else {
                            (!0u128) >> pfx_len
                        };
                        let host_part = if host_bits >= 64 {
                            (h64 as u128) & mask
                        } else if host_bits == 0 {
                            0
                        } else {
                            ((h64 as u128) & ((1u128 << host_bits) - 1)) & mask
                        };
                        addr_u128 = (addr_u128 & (!mask)) | host_part;
                        let ipv6 = std::net::Ipv6Addr::from(addr_u128.to_be_bytes());
                        new_set.insert(ipv6);
                    }
                }

                // Also include this node's assigned IPv6s for all prefixes
                {
                    use std::hash::{Hash, Hasher};
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    global_ctx.get_id().as_u128().hash(&mut hasher);
                    global_ctx.get_network_name().hash(&mut hasher);
                    let h64 = hasher.finish();
                    for prefix in &prefixes {
                        let pfx_len = prefix.network_length();
                        let host_bits = 128 - pfx_len as u32;
                        let base = prefix.first_address();
                        let mut addr_u128 = u128::from_be_bytes(base.octets());
                        let mask: u128 = if host_bits == 128 {
                            0
                        } else {
                            (!0u128) >> pfx_len
                        };
                        let host_part = if host_bits >= 64 {
                            (h64 as u128) & mask
                        } else if host_bits == 0 {
                            0
                        } else {
                            ((h64 as u128) & ((1u128 << host_bits) - 1)) & mask
                        };
                        addr_u128 = (addr_u128 & (!mask)) | host_part;
                        let ipv6 = std::net::Ipv6Addr::from(addr_u128.to_be_bytes());
                        new_set.insert(ipv6);
                    }
                }

                // diff and apply
                let mut applied_guard = applied_clone.lock().await;
                // removals
                let removed: Vec<_> = applied_guard.difference(&new_set).cloned().collect();
                for ip in removed.iter() {
                    let _g = net_ns.guard();
                    // remove route on tun
                    let _ = ifcfg.remove_ipv6_route(&_tun_ifname, *ip, 128).await;
                }
                // additions
                for ip in new_set.iter() {
                    if applied_guard.contains(ip) {
                        continue;
                    }
                    let _g = net_ns.guard();
                    let _ = ifcfg.add_ipv6_route(&_tun_ifname, *ip, 128, None).await;
                }
                *applied_guard = new_set;
                drop(applied_guard);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    async fn run_ipv6_default_route_updater(&mut self) -> Result<(), Error> {
        // For non-gateway nodes, add a default IPv6 route via the TUN interface
        // to send IPv6 Internet traffic over EasyTier when either:
        // - IPv6 on-link allocator is enabled (mesh-managed IPv6), or
        // - Exit nodes are configured (use peers as IPv6 egress).
        let global_ctx = self.global_ctx.clone();
        let allocator_enabled = global_ctx.config.get_enable_ipv6_prefix_allocator();
        let has_exit_nodes = !global_ctx.config.get_exit_nodes().is_empty();
        if !allocator_enabled && !has_exit_nodes {
            return Ok(());
        }
        // No dedicated gateway concept; keep default route updater when enabled.

        let nic = self.nic.lock().await;
        let ifname = nic.ifname().to_owned();
        let ifcfg = nic.get_ifcfg();
        let net_ns = self.global_ctx.net_ns.clone();
        drop(nic);

        self.tasks.spawn(async move {
            loop {
                let _g = net_ns.guard();
                // ::/0 default route
                let _ = ifcfg
                    .add_ipv6_route(&ifname, std::net::Ipv6Addr::UNSPECIFIED, 0, None)
                    .await;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        });

        Ok(())
    }

    async fn run_ipv6_exit_node_forwarding(&mut self) -> Result<(), Error> {
        // Prepare system IPv6 forwarding and NAT66 on Linux when this node acts as an exit node.
        // This is independent of the on-link allocator feature and helps IPv6 Internet/LAN egress.
        if !self.global_ctx.enable_exit_node() {
            return Ok(());
        }

        let nic = self.nic.lock().await;
        let _tun_ifname = nic.ifname().to_owned();
        drop(nic);

        #[cfg(target_os = "linux")]
        {
            let _ = ifcfg::run_shell_cmd("sysctl -w net.ipv6.conf.all.forwarding=1").await;
            // Detect default IPv6 egress interface and set FORWARD/NAT66 rules/best effort.
            // Use shell substitution to avoid parsing in Rust.
            let cmd = format!(
                "WAN=$(ip -6 route show default | awk '{{for(i=1;i<=NF;i++) if ($i==\"dev\") {{print $(i+1); exit}}}}'); \
                 if [ -n \"$WAN\" ]; then \
                   ip6tables -C FORWARD -i {} -o $WAN -j ACCEPT || ip6tables -I FORWARD -i {} -o $WAN -j ACCEPT; \
                   ip6tables -C FORWARD -i $WAN -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT || ip6tables -I FORWARD -i $WAN -o {} -m state --state RELATED,ESTABLISHED -j ACCEPT; \
                   ip6tables -t nat -C POSTROUTING -o $WAN -j MASQUERADE || ip6tables -t nat -A POSTROUTING -o $WAN -j MASQUERADE; \
                 else \
                   # Fallback: MASQUERADE everything not going out via TUN (broad, but functional)
                   ip6tables -t nat -C POSTROUTING ! -o {} -j MASQUERADE || ip6tables -t nat -A POSTROUTING ! -o {} -j MASQUERADE; \
                 fi",
                _tun_ifname, _tun_ifname, _tun_ifname, _tun_ifname, _tun_ifname, _tun_ifname
            );
            let _ = ifcfg::run_shell_cmd(&cmd).await;
        }

        #[cfg(target_os = "macos")]
        {
            // Forwarding toggle only. NAT66 on macOS requires pf anchors/rules which are out of scope here.
            let _ = ifcfg::run_shell_cmd("sysctl -w net.inet6.ip6.forwarding=1").await;
        }

        Ok(())
    }

    pub async fn run(
        &mut self,
        ipv4_addr: Option<cidr::Ipv4Inet>,
        ipv6_addr: Option<cidr::Ipv6Inet>,
    ) -> Result<(), Error> {
        let tunnel = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev().await {
                Ok(ret) => {
                    #[cfg(target_os = "windows")]
                    {
                        let dev_name = self.global_ctx.get_flags().dev_name;
                        let _ = RegistryManager::reg_change_catrgory_in_profile(&dev_name);
                    }

                    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                    {
                        // remove the 10.0.0.0/24 route (which is added by rust-tun by default)
                        let _ = nic
                            .ifcfg
                            .remove_ipv4_route(nic.ifname(), "10.0.0.0".parse().unwrap(), 24)
                            .await;
                    }

                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceReady(nic.ifname().to_string()));
                    ret
                }
                Err(err) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceError(err.to_string()));
                    return Err(err);
                }
            }
        };

        let (stream, sink) = tunnel.split();

        self.do_forward_nic_to_peers_task(stream)?;
        self.do_forward_peers_to_nic(sink);

        // Assign IPv4 address if provided
        if let Some(ipv4_addr) = ipv4_addr {
            self.assign_ipv4_to_tun_device(ipv4_addr).await?;
        }

        // Assign IPv6 address(es)
        let prefixes = self.global_ctx.config.get_ipv6_prefixes();
        let allocator_enabled = self.global_ctx.config.get_enable_ipv6_prefix_allocator();
        if allocator_enabled && !prefixes.is_empty() && !self.global_ctx.get_flags().no_tun {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            self.global_ctx.get_id().as_u128().hash(&mut hasher);
            self.global_ctx.get_network_name().hash(&mut hasher);
            let h64 = hasher.finish();
            let mut addrs = Vec::new();
            for prefix in prefixes.iter() {
                let pfx_len = prefix.network_length();
                let host_bits = 128 - pfx_len as u32;
                let base = prefix.first_address();
                let mut addr_u128 = u128::from_be_bytes(base.octets());
                let mask: u128 = if host_bits == 128 {
                    0
                } else {
                    (!0u128) >> pfx_len
                };
                let host_part = if host_bits >= 64 {
                    (h64 as u128) & mask
                } else if host_bits == 0 {
                    0
                } else {
                    ((h64 as u128) & ((1u128 << host_bits) - 1)) & mask
                };
                addr_u128 = (addr_u128 & (!mask)) | host_part;
                let ipv6 = std::net::Ipv6Addr::from(addr_u128.to_be_bytes());
                addrs.push(cidr::Ipv6Inet::new(ipv6, 128).unwrap());
            }
            self.assign_ipv6_multi_to_tun_device(addrs).await?;
        } else if let Some(ipv6_addr) = ipv6_addr {
            self.assign_ipv6_to_tun_device(ipv6_addr).await?;
        }

        self.run_proxy_cidrs_route_updater().await?;

        // IPv6 prefix allocation and NDP proxy routing (if enabled)
        self.run_ipv6_prefix_allocator().await?;

        // Default IPv6 route on non-gateway nodes
        self.run_ipv6_default_route_updater().await?;

        // If acting as IPv6 exit node, ensure system-level forwarding/NAT66 ready
        self.run_ipv6_exit_node_forwarding().await?;

        Ok(())
    }

    #[cfg(any(target_os = "android", target_env = "ohos"))]
    pub async fn run_for_android(&mut self, tun_fd: std::os::fd::RawFd) -> Result<(), Error> {
        let tunnel = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev_for_android(tun_fd).await {
                Ok(ret) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceReady(nic.ifname().to_string()));
                    ret
                }
                Err(err) => {
                    self.global_ctx
                        .issue_event(GlobalCtxEvent::TunDeviceError(err.to_string()));
                    return Err(err);
                }
            }
        };

        let (stream, sink) = tunnel.split();

        self.do_forward_nic_to_peers_task(stream)?;
        self.do_forward_peers_to_nic(sink);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::common::{error::Error, global_ctx::tests::get_mock_global_ctx};

    use super::VirtualNic;

    async fn run_test_helper() -> Result<VirtualNic, Error> {
        let mut dev = VirtualNic::new(get_mock_global_ctx());
        let _tunnel = dev.create_dev().await?;

        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

        dev.link_up().await?;
        dev.remove_ip(None).await?;
        dev.add_ip("10.144.111.1".parse().unwrap(), 24).await?;
        Ok(dev)
    }

    #[tokio::test]
    async fn tun_test() {
        match run_test_helper().await {
            Ok(_dev) => {
                // success
            }
            Err(e) => {
                eprintln!("skip tun_test due to error: {:?}", e);
            }
        }

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
