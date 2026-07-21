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
        log,
    },
    instance::proxy_cidrs_monitor::ProxyCidrsMonitor,
    peers::{PacketRecvChanReceiver, peer_manager::PeerManager, recv_packet_from_chan},
    tunnel::{
        StreamItem, Tunnel, TunnelError, ZCPacketSink, ZCPacketStream,
        common::{FramedWriter, TunnelWrapper, ZCPacketToBytes, reserve_buf},
        packet_def::{TAIL_RESERVED_SIZE, ZCPacket, ZCPacketType},
    },
};

use byteorder::WriteBytesExt as _;
use bytes::{Buf, BufMut, BytesMut};
use cidr::{Ipv4Inet, Ipv6Inet};
use futures::{SinkExt, Stream, StreamExt, lock::BiLock, ready};
use pin_project_lite::pin_project;
use pnet::packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{Mutex, Notify},
    task::JoinSet,
};
use tokio_util::bytes::Bytes;
#[cfg(target_os = "windows")]
use tokio_util::task::AbortOnDropHandle;
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
                log::error!("tun stream error: {:?}", err);
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
            inner.advance(payload_offset - 4);
            let proto = infer_proto(&inner[4..]);
            self.fill_packet_info(&mut inner[0..4], proto)?;
            inner
        } else {
            inner.advance(payload_offset);
            inner
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
                if let Err(error) = crate::arch::windows::remove_interface_firewall_rules(ifname) {
                    log::warn!(
                        %error,
                        "failed to remove firewall rules for interface {}",
                        ifname
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
            log::warn!("TUN kernel module may not be available.");
            log::warn!("\tYou may need to load it with: sudo modprobe tun.");
        }

        // Try to create /dev/net directory if it doesn't exist
        if tokio::fs::metadata(TUN_DIR_PATH).await.is_err() {
            if let Err(error) = tokio::fs::create_dir_all(TUN_DIR_PATH).await {
                log::warn!(
                    ?error,
                    "Failed to create directory {}. TUN device creation may fail. Continuing anyway.",
                    TUN_DIR_PATH
                );
                log::warn!(
                    "\tYou may need to run with root privileges or manually create the TUN device."
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
                log::info!("Successfully created TUN device node {}", TUN_DEV_PATH);
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "Failed to create TUN device node {}. Continuing anyway.",
                    TUN_DEV_PATH,
                );
                Self::print_troubleshooting_info();
            }
        }
    }

    /// Print troubleshooting information for TUN device issues
    #[cfg(target_os = "linux")]
    fn print_troubleshooting_info() {
        log::info!(
            "Possible solutions:\
            \n\t1. Run with root privileges: sudo ./easytier-core [options]\
            \n\t2. Manually create TUN device: sudo mkdir -p /dev/net && sudo mknod /dev/net/tun c 10 200\
            \n\t3. Load TUN kernel module: sudo modprobe tun\
            \n\t4. Use --no-tun flag if TUN functionality is not needed\
            \n\t5. Check if your system/container supports TUN devices\
            \nNote: TUN functionality may still work if the kernel supports dynamic device creation."
        );
    }

    /// For non-Linux systems, this is a no-op
    #[cfg(not(target_os = "linux"))]
    async fn ensure_tun_device_node() -> Result<(), Error> {
        Ok(())
    }

    /// FreeBSD specific: Rename a TUN interface
    #[cfg(target_os = "freebsd")]
    async fn rename_tun_interface(old_name: &str, new_name: &str) -> Result<(), Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg(old_name)
            .arg("name")
            .arg(new_name)
            .output()
            .await?;

        if output.status.success() {
            tracing::info!(
                "Successfully renamed interface {} to {}",
                old_name,
                new_name
            );
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!(
                "Failed to rename interface {} to {}: {}",
                old_name,
                new_name,
                stderr
            );
            // Return Ok even if rename fails, as it's not critical
            Ok(())
        }
    }

    /// FreeBSD specific: List all TUN interface names
    #[cfg(target_os = "freebsd")]
    async fn list_tun_names() -> Result<Vec<String>, Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg("-g")
            .arg("tun")
            .output()
            .await?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let tun_names: Vec<String> = stdout
                .trim()
                .split_whitespace()
                .map(|s| s.to_string())
                .collect();
            tracing::debug!("Found TUN interfaces: {:?}", tun_names);
            Ok(tun_names)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::warn!("Failed to list TUN interfaces: {}", stderr);
            Ok(Vec::new())
        }
    }

    /// FreeBSD specific: Get interface information
    #[cfg(target_os = "freebsd")]
    async fn get_interface_info(ifname: &str) -> Result<String, Error> {
        let output = tokio::process::Command::new("ifconfig")
            .arg("-v")
            .arg(ifname)
            .output()
            .await?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(
                anyhow::anyhow!("Failed to get interface details for {}: {}", ifname, stderr)
                    .into(),
            )
        }
    }

    /// FreeBSD specific: Extract original name from interface information
    #[cfg(target_os = "freebsd")]
    fn extract_original_name(ifinfo: &str) -> Option<String> {
        ifinfo
            .lines()
            .find(|line| line.trim().starts_with("drivername:"))
            .and_then(|line| line.trim().split_whitespace().nth(1))
            .map(|name| name.to_string())
    }

    /// FreeBSD specific: Check if interface is used by any process
    #[cfg(target_os = "freebsd")]
    fn is_interface_used(ifinfo: &str) -> bool {
        ifinfo.contains("Opened by PID")
    }

    /// FreeBSD specific: Restore TUN interface name to its original value
    #[cfg(target_os = "freebsd")]
    async fn restore_tun_name(dev_name: &str) -> Result<(), Error> {
        let tun_names = Self::list_tun_names().await?;

        // Check if desired dev_name is in use
        if tun_names.iter().any(|name| name == dev_name) {
            tracing::debug!(
                "Desired dev_name {} is in TUN interfaces list, checking if it can be renamed",
                dev_name
            );

            let ifinfo = Self::get_interface_info(dev_name).await?;

            // Check if interface is not occupied
            if !Self::is_interface_used(&ifinfo) {
                // Extract original name
                if let Some(orig_name) = Self::extract_original_name(&ifinfo) {
                    if orig_name != dev_name {
                        tracing::info!(
                            "Restoring dev_name {} to original name {}",
                            dev_name,
                            orig_name
                        );
                        // Rename interface
                        Self::rename_tun_interface(dev_name, &orig_name).await?;
                    }
                }
            } else {
                tracing::debug!(
                    "Interface {} is opened by a process, skipping rename",
                    dev_name
                );
            }
        }

        Ok(())
    }

    async fn create_tun(&self) -> Result<tun::platform::Device, Error> {
        let mut config = Configuration::default();
        config.layer(Layer::L3);

        // FreeBSD specific: Check and restore TUN interfaces before creating new one
        #[cfg(target_os = "freebsd")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            if !dev_name.is_empty() {
                // Restore TUN interface name if needed, ignoring errors as it's not critical
                let _ = Self::restore_tun_name(&dev_name).await;
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Check and create TUN device node if necessary (Linux only)
            Self::ensure_tun_device_node().await;

            let dev_name = self.global_ctx.get_flags().dev_name;
            if !dev_name.is_empty() {
                config.tun_name(&dev_name);
            }
        }

        #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });

        #[cfg(target_os = "windows")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            match crate::arch::windows::add_self_to_firewall_allowlist() {
                Ok(_) => tracing::info!("add_self_to_firewall_allowlist successful!"),
                Err(error) => {
                    log::warn!(%error, "Failed to add Easytier to firewall allowlist, Subnet proxy and KCP proxy may not work properly.");
                    log::warn!(
                        "You can add firewall rules manually, or use --use-smoltcp to run with user-space TCP/IP stack."
                    );
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

    #[cfg(mobile)]
    pub async fn create_dev_for_mobile(
        &mut self,
        tun_fd: std::os::fd::RawFd,
    ) -> Result<Box<dyn Tunnel>, Error> {
        log::debug!(%tun_fd);
        let mut config = Configuration::default();
        config.layer(Layer::L3);

        #[cfg(any(target_os = "ios", all(target_os = "macos", feature = "macos-ne")))]
        config.platform_config(|config| {
            // disable packet information so we can process the header by ourselves, see tun2 impl for more details
            config.packet_information(false);
        });

        config.raw_fd(tun_fd);
        config.close_fd_on_drop(false);
        config.up();

        let has_packet_info = cfg!(any(
            target_os = "ios",
            all(target_os = "macos", feature = "macos-ne")
        ));
        let dev = tun::create(&config)?;
        let dev = AsyncDevice::new(dev)?;
        let (a, b) = BiLock::new(dev);
        let ft = TunnelWrapper::new(
            TunStream::new(a, has_packet_info),
            FramedWriter::new_with_converter(
                TunAsyncWrite { l: b },
                TunZCPacketToBytes::new(has_packet_info),
            ),
            None,
        );

        self.ifname = Some(format!("tunfd_{}", tun_fd));

        Ok(Box::new(ft))
    }

    pub async fn create_dev(&mut self) -> Result<Box<dyn Tunnel>, Error> {
        let dev = self.create_tun().await?;

        #[cfg(not(target_os = "freebsd"))]
        let ifname = dev.tun_name()?;

        #[cfg(target_os = "freebsd")]
        let mut ifname = dev.tun_name()?;
        self.ifcfg.wait_interface_show(ifname.as_str()).await?;

        // FreeBSD TUN interface rename functionality
        #[cfg(target_os = "freebsd")]
        {
            let dev_name = self.global_ctx.get_flags().dev_name;

            if !dev_name.is_empty() && dev_name != ifname {
                // Use ifconfig to rename the TUN interface
                if Self::rename_tun_interface(&ifname, &dev_name).await.is_ok() {
                    ifname = dev_name;
                }
            }
        }

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

        let has_packet_info = cfg!(all(target_os = "macos", not(feature = "macos-ne")));
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
                Err(error) => {
                    log::warn!(%error, "Failed to configure Windows Firewall for interface {}\
                    \n\tThis may cause connectivity issues with ping and other network functions.\
                    \n\tPlease run as Administrator or manually configure Windows Firewall.\
                    \n\tAlternatively, you can disable Windows Firewall for testing purposes.", ifname);
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
        self.add_ipv6_route_with_cost(address, cidr, None).await
    }

    pub async fn add_ipv6_route_with_cost(
        &self,
        address: Ipv6Addr,
        cidr: u8,
        cost: Option<i32>,
    ) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .add_ipv6_route(self.ifname(), address, cidr, cost)
            .await?;
        Ok(())
    }

    pub async fn remove_ipv6_route(&self, address: Ipv6Addr, cidr: u8) -> Result<(), Error> {
        let _g = self.global_ctx.net_ns.guard();
        self.ifcfg
            .remove_ipv6_route(self.ifname(), address, cidr)
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

    pub fn get_ifcfg(&self) -> impl IfConfiguerTrait + use<> {
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

    #[cfg(target_os = "windows")]
    windows_udp_broadcast_relay: Option<AbortOnDropHandle<()>>,
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

            #[cfg(target_os = "windows")]
            windows_udp_broadcast_relay: None,
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
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
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
        #[cfg(any(
            all(target_os = "macos", not(feature = "macos-ne")),
            target_os = "freebsd"
        ))]
        {
            nic.add_ipv6_route(ipv6_addr.first_address(), ipv6_addr.network_length())
                .await?;
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
            let src_ipv4 = ipv4.get_source();
            let my_ipv4 = mgr.get_global_ctx().get_ipv4().map(|x| x.address());
            tracing::trace!(
                ?ret,
                ?src_ipv4,
                ?dst_ipv4,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            // Subnet A is proxied as 10.0.0.0/24, and Subnet B is also proxied as 10.0.0.0/24.
            //
            // Subnet A has received a route advertised by Subnet B. As a result, A can reach
            // the physical subnet 10.0.0.0/24 directly and has also added a virtual route for
            // the same subnet 10.0.0.0/24. However, the physical route has a higher priority
            // (lower metric) than the virtual one.
            //
            // When A sends a UDP packet to a non-existent IP within this subnet, the packet
            // cannot be delivered on the physical network and is instead routed to the virtual
            // network interface.
            //
            // The virtual interface receives the packet and forwards it to itself, which triggers
            // the subnet proxy logic. The subnet proxy then attempts to send another packet to
            // the same destination address, causing the same process to repeat and creating an
            // infinite loop. Therefore, we must avoid re-sending packets back to ourselves
            // when the subnet proxy itself is the originator of the packet.
            //
            // However, there is a special scenario to consider: when A acts as a gateway,
            // packets from devices behind A may be forwarded by the OS to the ET (e.g., an
            // eBPF or tunneling component), which happens to proxy the subnet. In this case,
            // the packet’s source IP is not A’s own IP, and we must allow such packets to be
            // sent to the virtual interface (i.e., "sent to ourselves") to maintain correct
            // forwarding behavior. Thus, loop prevention should only apply when the source IP
            // belongs to the local host.
            let send_ret = mgr
                .send_msg_by_ip(ret, IpAddr::V4(dst_ipv4), Some(src_ipv4) == my_ipv4)
                .await;
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
            let is_local_src = mgr.get_global_ctx().is_ip_local_ipv6(&src_ipv6);
            tracing::trace!(
                ?ret,
                ?src_ipv6,
                ?dst_ipv6,
                "[USER_PACKET] recv new packet from tun device and forward to peers."
            );

            if src_ipv6.is_unicast_link_local() && !is_local_src {
                // do not route link local packet to other nodes unless the address is assigned by user
                return;
            }

            // TODO: use zero-copy
            let send_ret = mgr
                .send_msg_by_ip(ret, IpAddr::V6(dst_ipv6), is_local_src)
                .await;
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

    #[cfg(target_os = "windows")]
    fn start_windows_udp_broadcast_relay(&mut self, virtual_ipv4: Ipv4Inet) {
        if !self.global_ctx.get_flags().enable_udp_broadcast_relay {
            return;
        }

        let Some(peer_manager) = self.peer_mgr.upgrade() else {
            tracing::warn!("peer manager is dropped, skip Windows UDP broadcast relay");
            return;
        };

        match super::windows_udp_broadcast::start(peer_manager, virtual_ipv4) {
            Ok(handle) => {
                self.windows_udp_broadcast_relay = Some(handle);
                tracing::info!("Windows UDP broadcast relay started");
            }
            Err(err) => {
                tracing::warn!(
                    ?err,
                    "failed to start Windows UDP broadcast relay; administrator privileges are required"
                );
            }
        }
    }

    async fn apply_route_changes(
        ifcfg: &impl IfConfiguerTrait,
        ifname: &str,
        net_ns: &crate::common::netns::NetNS,
        cur_proxy_cidrs: &mut BTreeSet<cidr::Ipv4Cidr>,
        added: Vec<cidr::Ipv4Cidr>,
        removed: Vec<cidr::Ipv4Cidr>,
        #[allow(unused_variables)] tun_ipv4: Option<std::net::Ipv4Addr>,
    ) {
        tracing::debug!(?added, ?removed, "applying proxy_cidrs route changes");

        // Remove routes
        for cidr in removed {
            if !cur_proxy_cidrs.contains(&cidr) {
                continue;
            }

            // macOS: 0.0.0.0/0 was installed as split routes, remove those
            #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
            if cidr.network_length() == 0 && cidr.first_address() == std::net::Ipv4Addr::UNSPECIFIED {
                tracing::info!("macOS: removing split default routes from TUN");
                for (octet, prefix) in MACOS_SPLIT_DEFAULT_ROUTES {
                    remove_macos_route_if_on_iface(
                        std::net::Ipv4Addr::new(octet, 0, 0, 0),
                        prefix,
                        ifname,
                    )
                    .await;
                }
                // also clean the old-style /1 split left by earlier builds
                remove_macos_route_if_on_iface(std::net::Ipv4Addr::new(0, 0, 0, 0), 1, ifname)
                    .await;
                cur_proxy_cidrs.remove(&cidr);
                continue;
            }

            let _g = net_ns.guard();
            let ret = ifcfg
                .remove_ipv4_route(ifname, cidr.first_address(), cidr.network_length())
                .await;

            if ret.is_err() {
                tracing::trace!(
                    cidr = ?cidr,
                    err = ?ret,
                    "remove route failed.",
                );
            }
            cur_proxy_cidrs.remove(&cidr);
        }

        // Add routes
        for cidr in added {
            if cur_proxy_cidrs.contains(&cidr) {
                continue;
            }

            // macOS: adding 0.0.0.0/0 conflicts with the existing system default
            // route, so install the clash/mihomo-style split instead. Two
            // hard-won constraints from live debugging:
            //  - any route whose destination is 0.0.0.0 (e.g. 0.0.0.0/1) is
            //    marked RTF_GLOBAL by the kernel and breaks sends from
            //    IP_BOUND_IF-scoped underlay sockets (EHOSTUNREACH), killing
            //    STUN and hole punching — hence the split starts at 1.0.0.0/8
            //    and skips the reserved 0.0.0.0/8;
            //  - gateway-form routes (via the TUN's own address) are used to
            //    match the empirically verified working configuration.
            #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
            if cidr.network_length() == 0 && cidr.first_address() == std::net::Ipv4Addr::UNSPECIFIED {
                if let Some(tun_ip) = tun_ipv4 {
                    let mac_ifcfg = crate::common::ifcfg::IfConfiger {};
                    let mut installed = vec![];
                    let mut first_err = None;
                    for (octet, prefix) in MACOS_SPLIT_DEFAULT_ROUTES {
                        let dst = std::net::Ipv4Addr::new(octet, 0, 0, 0);
                        match mac_ifcfg.add_ipv4_route_via_gateway(dst, prefix, tun_ip).await {
                            Ok(()) => installed.push((dst, prefix)),
                            Err(e) => {
                                first_err = Some((dst, prefix, e));
                                break;
                            }
                        }
                    }
                    if let Some((dst, prefix, e)) = first_err {
                        // all-or-nothing: half a split default route silently
                        // un-tunnels part of the address space, which is worse
                        // than a fully absent one. Roll back (ownership-checked)
                        // and leave 0/0 out of cur_proxy_cidrs so the periodic
                        // reconcile retries the whole set.
                        tracing::warn!(
                            ?dst,
                            prefix,
                            ?e,
                            "macOS: split default route add failed, rolling back the set"
                        );
                        for (dst, prefix) in installed {
                            remove_macos_route_if_on_iface(dst, prefix, ifname).await;
                        }
                        continue;
                    }
                    tracing::info!(?tun_ip, "macOS: installed split default routes for TUN routing");
                } else {
                    for (octet, prefix) in MACOS_SPLIT_DEFAULT_ROUTES {
                        let dst = std::net::Ipv4Addr::new(octet, 0, 0, 0);
                        let _ = ifcfg.add_ipv4_route(ifname, dst, prefix, None).await;
                    }
                    tracing::warn!("macOS: tun has no ipv4, split default routes use interface form");
                }
                cur_proxy_cidrs.insert(cidr);
                continue;
            }

            let _g = net_ns.guard();
            let ret = ifcfg
                .add_ipv4_route(ifname, cidr.first_address(), cidr.network_length(), None)
                .await;

            if ret.is_err() {
                tracing::trace!(
                    cidr = ?cidr,
                    err = ?ret,
                    "add route failed.",
                );
            }
            cur_proxy_cidrs.insert(cidr);
        }
    }

    async fn apply_public_ipv6_route_changes(
        ifcfg: &impl IfConfiguerTrait,
        ifname: &str,
        net_ns: &crate::common::netns::NetNS,
        cur_routes: &mut BTreeSet<cidr::Ipv6Inet>,
        added: Vec<cidr::Ipv6Inet>,
        removed: Vec<cidr::Ipv6Inet>,
    ) {
        for route in removed {
            if !cur_routes.contains(&route) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .remove_ipv6_route(ifname, route.address(), route.network_length())
                .await;
            if ret.is_err() {
                tracing::trace!(route = ?route, err = ?ret, "remove public ipv6 route failed");
            }
            cur_routes.remove(&route);
        }

        for route in added {
            if cur_routes.contains(&route) {
                continue;
            }
            let _g = net_ns.guard();
            let ret = ifcfg
                .add_ipv6_route(ifname, route.address(), route.network_length(), None)
                .await;
            if ret.is_err() {
                tracing::trace!(route = ?route, err = ?ret, "add public ipv6 route failed");
            } else {
                cur_routes.insert(route);
            }
        }
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
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut cur_proxy_cidrs = BTreeSet::<cidr::Ipv4Cidr>::new();

            // macOS: host routes protecting underlay endpoints from the broad
            // full-tunnel TUN routes; reconciled periodically so endpoints of
            // closed conns get pruned and gateway changes are followed
            #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
            let mut bypass = macos_bypass::BypassRouteManager::new(macos_bypass::SysRouteOps);
            #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
            let mut bypass_reconcile = tokio::time::interval_at(
                tokio::time::Instant::now() + BYPASS_RECONCILE_INTERVAL,
                BYPASS_RECONCILE_INTERVAL,
            );

            // Initial sync: get current proxy_cidrs state and apply routes
            let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                peer_mgr.as_ref(),
                &global_ctx,
                &cur_proxy_cidrs,
            )
            .await;

            // macOS: install bypass routes before the TUN routes start capturing traffic
            #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
            sync_macos_bypass_routes(&mut bypass, &cur_proxy_cidrs, &added, &global_ctx, &peer_mgr)
                .await;

            Self::apply_route_changes(
                &ifcfg,
                &ifname,
                &net_ns,
                &mut cur_proxy_cidrs,
                added,
                removed,
                global_ctx.get_ipv4().map(|ip| ip.address()),
            )
            .await;

            loop {
                #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
                let received = tokio::select! {
                    r = event_receiver.recv() => r,
                    _ = bypass_reconcile.tick() => {
                        // the periodic reconcile also retries route changes
                        // that previously failed (e.g. a rolled-back split
                        // default route set)
                        let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                            peer_mgr.as_ref(),
                            &global_ctx,
                            &cur_proxy_cidrs,
                        )
                        .await;
                        sync_macos_bypass_routes(
                            &mut bypass,
                            &cur_proxy_cidrs,
                            &added,
                            &global_ctx,
                            &peer_mgr,
                        )
                        .await;
                        if !added.is_empty() || !removed.is_empty() {
                            Self::apply_route_changes(
                                &ifcfg,
                                &ifname,
                                &net_ns,
                                &mut cur_proxy_cidrs,
                                added,
                                removed,
                                global_ctx.get_ipv4().map(|ip| ip.address()),
                            )
                            .await;
                        }
                        continue;
                    }
                };
                #[cfg(not(all(target_os = "macos", not(feature = "macos-ne"))))]
                let received = event_receiver.recv().await;

                let event = match received {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        tracing::debug!("event bus closed, stopping proxy_cidrs route updater");
                        break;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        tracing::warn!(
                            "event bus lagged in proxy_cidrs route updater, doing full sync"
                        );
                        event_receiver = event_receiver.resubscribe();
                        // Full sync after lagged to recover consistent state
                        let (_, added, removed) = ProxyCidrsMonitor::diff_proxy_cidrs(
                            peer_mgr.as_ref(),
                            &global_ctx,
                            &cur_proxy_cidrs,
                        )
                        .await;
                        GlobalCtxEvent::ProxyCidrsUpdated(added, removed)
                    }
                };

                let (added, removed) = match event {
                    GlobalCtxEvent::ProxyCidrsUpdated(added, removed) => (added, removed),
                    // a fresh underlay conn (e.g. a just-punched p2p endpoint)
                    // must be protected before its traffic loops into the TUN
                    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
                    GlobalCtxEvent::PeerConnAdded(conn) => {
                        if cur_proxy_cidrs.iter().any(|c| c.network_length() <= 1)
                            && let Some(ip) = conn_remote_ipv4(&conn)
                            && is_bypass_candidate_ipv4(ip, &physical_onlink_v4_subnets(), &global_ctx)
                            && let Some(route) = crate::arch::macos::get_default_route_v4()
                        {
                            bypass.add_one(ip, route.gateway).await;
                        }
                        continue;
                    }
                    _ => continue,
                };

                // macOS: refresh bypass routes before applying main route changes
                #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
                sync_macos_bypass_routes(
                    &mut bypass,
                    &cur_proxy_cidrs,
                    &added,
                    &global_ctx,
                    &peer_mgr,
                )
                .await;

                Self::apply_route_changes(
                    &ifcfg,
                    &ifname,
                    &net_ns,
                    &mut cur_proxy_cidrs,
                    added,
                    removed,
                    global_ctx.get_ipv4().map(|ip| ip.address()),
                )
                .await;
            }

            // remove bypass routes when the updater stops
            #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
            bypass.clear().await;
        });

        Ok(())
    }

    async fn run_public_ipv6_route_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let net_ns = self.global_ctx.net_ns.clone();
        let nic = self.nic.lock().await;
        let ifcfg = nic.get_ifcfg();
        let ifname = nic.ifname().to_owned();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut cur_routes = BTreeSet::<cidr::Ipv6Inet>::new();
            let initial_routes = peer_mgr.list_public_ipv6_routes().await;
            let initial_added = initial_routes.iter().copied().collect::<Vec<_>>();
            Self::apply_public_ipv6_route_changes(
                &ifcfg,
                &ifname,
                &net_ns,
                &mut cur_routes,
                initial_added,
                Vec::new(),
            )
            .await;

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                        let latest = peer_mgr.list_public_ipv6_routes().await;
                        let added = latest.difference(&cur_routes).copied().collect::<Vec<_>>();
                        let removed = cur_routes.difference(&latest).copied().collect::<Vec<_>>();
                        GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed)
                    }
                };

                let (added, removed) = match event {
                    GlobalCtxEvent::PublicIpv6RoutesUpdated(added, removed) => (added, removed),
                    _ => continue,
                };

                Self::apply_public_ipv6_route_changes(
                    &ifcfg,
                    &ifname,
                    &net_ns,
                    &mut cur_routes,
                    added,
                    removed,
                )
                .await;
            }
        });

        Ok(())
    }

    async fn run_public_ipv6_addr_updater(&mut self) -> Result<(), Error> {
        let Some(peer_mgr) = self.peer_mgr.upgrade() else {
            return Err(anyhow::anyhow!("peer manager not available").into());
        };
        let global_ctx = self.global_ctx.clone();
        let nic = self.nic.clone();
        let mut event_receiver = global_ctx.subscribe();

        self.tasks.spawn(async move {
            let mut current_addr = peer_mgr.get_my_public_ipv6_addr().await;
            if let Some(addr) = current_addr {
                let nic = nic.lock().await;
                if let Err(err) = nic.link_up().await {
                    tracing::warn!(?err, "failed to bring public ipv6 nic link up");
                }
                if let Err(err) = nic.add_ipv6(addr.address(), addr.network_length() as i32).await {
                    tracing::warn!(addr = ?addr, ?err, "failed to add public ipv6 address");
                }
                if let Err(err) = nic
                    .add_ipv6_route_with_cost(Ipv6Addr::UNSPECIFIED, 0, Some(5))
                    .await
                {
                    tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to add default public ipv6 route");
                }
            }

            loop {
                let event = match event_receiver.recv().await {
                    Ok(event) => event,
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        event_receiver = event_receiver.resubscribe();
                        let latest = peer_mgr.get_my_public_ipv6_addr().await;
                        GlobalCtxEvent::PublicIpv6Changed(current_addr, latest)
                    }
                };

                let (old, new) = match event {
                    GlobalCtxEvent::PublicIpv6Changed(old, new) => (old, new),
                    _ => continue,
                };

                current_addr = new;
                let nic = nic.lock().await;
                if let Err(err) = nic.link_up().await {
                    tracing::warn!(?err, "failed to bring public ipv6 nic link up");
                }
                if let Some(old) = old {
                    if let Err(err) = nic.remove_ipv6_route(Ipv6Addr::UNSPECIFIED, 0).await {
                        tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to remove default public ipv6 route");
                    }
                    if let Err(err) = nic.remove_ipv6(Some(old)).await {
                        tracing::warn!(addr = ?old, ?err, "failed to remove old public ipv6 address");
                    }
                }
                if let Some(new) = new {
                    if let Err(err) = nic.add_ipv6(new.address(), new.network_length() as i32).await
                    {
                        tracing::warn!(addr = ?new, ?err, "failed to add public ipv6 address");
                    }
                    if let Err(err) = nic
                        .add_ipv6_route_with_cost(Ipv6Addr::UNSPECIFIED, 0, Some(5))
                        .await
                    {
                        tracing::warn!(route = %Ipv6Addr::UNSPECIFIED, prefix = 0, ?err, "failed to add default public ipv6 route");
                    }
                }
            }
        });

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

                    #[cfg(any(
                        all(target_os = "macos", not(feature = "macos-ne")),
                        target_os = "freebsd"
                    ))]
                    {
                        // remove the 10.0.0.0/24 route (which is added by rust-tun by default)
                        let _ = nic
                            .ifcfg
                            .remove_ipv4_route(nic.ifname(), "10.0.0.0".parse().unwrap(), 24)
                            .await;
                    }

                    self.global_ctx
                        .set_tun_device_ready(nic.ifname().to_string());
                    ret
                }
                Err(err) => {
                    self.global_ctx.set_tun_device_error(err.to_string());
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
            #[cfg(target_os = "windows")]
            self.start_windows_udp_broadcast_relay(ipv4_addr);
        }

        // Assign IPv6 address if provided
        if let Some(ipv6_addr) = ipv6_addr {
            self.assign_ipv6_to_tun_device(ipv6_addr).await?;
        }

        self.run_proxy_cidrs_route_updater().await?;
        self.run_public_ipv6_route_updater().await?;
        // Keep the updater running so runtime config patches can enable auto mode
        // without recreating the NIC.
        self.run_public_ipv6_addr_updater().await?;

        Ok(())
    }

    #[cfg(mobile)]
    pub async fn run_for_mobile(&mut self, tun_fd: std::os::fd::RawFd) -> Result<(), Error> {
        let tunnel = {
            let mut nic = self.nic.lock().await;
            match nic.create_dev_for_mobile(tun_fd).await {
                Ok(ret) => {
                    self.global_ctx
                        .set_tun_device_ready(nic.ifname().to_string());
                    ret
                }
                Err(err) => {
                    self.global_ctx.set_tun_device_error(err.to_string());
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

/// Delete the exact route `dst/prefix` only if the routing table shows it on
/// our own TUN interface — true for both the gateway-form entries (the TUN's
/// own address resolves on the TUN) and the no-ipv4 interface-form fallback.
/// Never touches an identical route owned by someone else: another VPN's
/// clash-style split routes point at that VPN's own utun, and deleting them
/// would cut the machine off the network.
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
async fn remove_macos_route_if_on_iface(dst: std::net::Ipv4Addr, prefix: u8, ifname: &str) {
    let mac_ifcfg = crate::common::ifcfg::IfConfiger {};
    match mac_ifcfg.query_ipv4_route_exact(dst, prefix).await {
        // no exact entry (or unknown shape): nothing of ours to remove
        None => {}
        Some(entry) if entry.iface.as_deref() == Some(ifname) => {
            if let Err(e) = mac_ifcfg.remove_ipv4_route_any(dst, prefix).await {
                tracing::warn!(?dst, prefix, ?e, "failed to remove split route");
            }
        }
        Some(entry) => {
            tracing::warn!(
                ?dst,
                prefix,
                iface = ?entry.iface,
                "route exists but is not on our TUN, leaving it alone"
            );
        }
    }
}

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
const BYPASS_RECONCILE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(15);

/// The clash/mihomo-style default-route split: (first octet, prefix length).
/// Covers 1.0.0.0-255.255.255.255; 0.0.0.0/8 is reserved and deliberately
/// skipped so no route has destination 0.0.0.0 (see apply_route_changes).
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
const MACOS_SPLIT_DEFAULT_ROUTES: [(u8, u8); 8] = [
    (1, 8),
    (2, 7),
    (4, 6),
    (8, 5),
    (16, 4),
    (32, 3),
    (64, 2),
    (128, 1),
];

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
mod macos_bypass {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::Ipv4Addr;

    use crate::common::error::Error;

    /// Exact /32 lookup result used for ownership checks before deletion.
    pub(super) enum HostRouteQuery {
        /// No /32 entry exists for this destination.
        Missing,
        /// An entry exists; `gateway` is None for non-gateway (interface /
        /// on-link) forms, which are by definition not ours.
        Entry { gateway: Option<Ipv4Addr> },
    }

    /// Routing-table operations behind the bypass manager, abstracted so the
    /// ownership/retry state machine below is unit-testable without touching
    /// the real routing table.
    pub(super) trait RouteOps {
        async fn add_host_route_via_gateway(
            &self,
            ip: Ipv4Addr,
            gateway: Ipv4Addr,
        ) -> Result<(), Error>;
        async fn remove_host_route(&self, ip: Ipv4Addr) -> Result<(), Error>;
        async fn query_host_route(&self, ip: Ipv4Addr) -> HostRouteQuery;
    }

    pub(super) struct SysRouteOps;

    impl RouteOps for SysRouteOps {
        async fn add_host_route_via_gateway(
            &self,
            ip: Ipv4Addr,
            gateway: Ipv4Addr,
        ) -> Result<(), Error> {
            let ifcfg = crate::common::ifcfg::IfConfiger {};
            ifcfg.add_ipv4_route_via_gateway(ip, 32, gateway).await
        }
        async fn remove_host_route(&self, ip: Ipv4Addr) -> Result<(), Error> {
            let ifcfg = crate::common::ifcfg::IfConfiger {};
            ifcfg.remove_ipv4_route_any(ip, 32).await
        }
        async fn query_host_route(&self, ip: Ipv4Addr) -> HostRouteQuery {
            let ifcfg = crate::common::ifcfg::IfConfiger {};
            match ifcfg.query_ipv4_route_exact(ip, 32).await {
                None => HostRouteQuery::Missing,
                Some(entry) => HostRouteQuery::Entry {
                    gateway: entry.gateway,
                },
            }
        }
    }

    /// Host routes (/32 via the physical gateway) that let easytier's own
    /// underlay traffic escape the broad split default routes installed for
    /// full tunnel (MACOS_SPLIT_DEFAULT_ROUTES). Without them, packets to
    /// peer endpoints would be captured by the TUN and loop back into
    /// easytier.
    ///
    /// Ownership rules: only routes this instance successfully installed are
    /// deleted, and deletion re-checks that the table still shows the gateway
    /// we recorded. An identical /32 owned by someone else (another VPN
    /// protecting the same endpoint) is never torn down — deleting it would
    /// pull that software's underlay traffic into our tunnel.
    pub(super) struct BypassRouteManager<O: RouteOps> {
        ops: O,
        installed: BTreeMap<Ipv4Addr, Ipv4Addr>, // dst ip -> gateway we installed
    }

    impl<O: RouteOps> BypassRouteManager<O> {
        pub(super) fn new(ops: O) -> Self {
            Self {
                ops,
                installed: BTreeMap::new(),
            }
        }

        pub(super) async fn sync(&mut self, desired: &BTreeSet<Ipv4Addr>, gateway: Ipv4Addr) {
            let stale: Vec<(Ipv4Addr, Ipv4Addr)> = self
                .installed
                .iter()
                .filter(|(ip, gw)| !desired.contains(ip) || **gw != gateway)
                .map(|(ip, gw)| (*ip, *gw))
                .collect();
            for (ip, gw) in stale {
                self.remove_one(ip, gw).await;
            }
            for ip in desired {
                self.add_one(*ip, gateway).await;
            }
        }

        pub(super) async fn add_one(&mut self, ip: Ipv4Addr, gateway: Ipv4Addr) {
            if let Some(old_gw) = self.installed.get(&ip).copied() {
                if old_gw == gateway {
                    return;
                }
                if !self.remove_one(ip, old_gw).await {
                    // the old entry could not be removed; keep it on the books
                    // and let a later reconcile retry the gateway switch
                    return;
                }
            }
            match self.ops.add_host_route_via_gateway(ip, gateway).await {
                Ok(()) => {
                    tracing::info!(?ip, ?gateway, "added underlay bypass route");
                    self.installed.insert(ip, gateway);
                }
                Err(e) => {
                    // do NOT track failed adds: an EEXIST here may be another
                    // VPN's bypass for the same endpoint, which must never be
                    // deleted by us. The cost is that a /32 leaked by a
                    // crashed previous run is not adopted; that leftover is
                    // harmless (it points at the physical gateway) and clears
                    // on reboot.
                    tracing::warn!(
                        ?ip,
                        ?gateway,
                        ?e,
                        "failed to add bypass route, leaving any existing entry alone"
                    );
                }
            }
        }

        /// Remove `ip`'s /32 if the table still shows the gateway we
        /// installed. Returns true when the entry is off our books (deleted,
        /// already gone, or replaced by a foreign route), false when deletion
        /// failed and should be retried by a later reconcile.
        async fn remove_one(&mut self, ip: Ipv4Addr, expected_gw: Ipv4Addr) -> bool {
            match self.ops.query_host_route(ip).await {
                HostRouteQuery::Missing => {
                    self.installed.remove(&ip);
                    true
                }
                HostRouteQuery::Entry { gateway: Some(gw) } if gw == expected_gw => {
                    match self.ops.remove_host_route(ip).await {
                        Ok(()) => {
                            self.installed.remove(&ip);
                            true
                        }
                        Err(e) => {
                            tracing::warn!(
                                ?ip,
                                ?expected_gw,
                                ?e,
                                "failed to remove bypass route, will retry"
                            );
                            false
                        }
                    }
                }
                HostRouteQuery::Entry { gateway } => {
                    // not the entry we installed (replaced or foreign): drop
                    // it from our books without deleting
                    tracing::warn!(
                        ?ip,
                        ?expected_gw,
                        current_gateway = ?gateway,
                        "bypass route replaced by a foreign entry, leaving it alone"
                    );
                    self.installed.remove(&ip);
                    true
                }
            }
        }

        /// Best-effort removal of everything we installed. Entries whose
        /// deletion fails stay on the books, so a later reconcile (or the
        /// next `clear`) retries them.
        pub(super) async fn clear(&mut self) {
            let entries: Vec<(Ipv4Addr, Ipv4Addr)> =
                self.installed.iter().map(|(ip, gw)| (*ip, *gw)).collect();
            for (ip, gw) in entries {
                self.remove_one(ip, gw).await;
            }
            if !self.installed.is_empty() {
                tracing::warn!(remaining = ?self.installed, "some bypass routes could not be removed");
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Mutex;

        #[derive(Default)]
        struct FakeOps {
            // simulated routing table: ip -> gateway (None = non-gateway entry)
            table: Mutex<BTreeMap<Ipv4Addr, Option<Ipv4Addr>>>,
            fail_remove: Mutex<std::collections::BTreeSet<Ipv4Addr>>,
            removed: Mutex<Vec<Ipv4Addr>>,
        }

        impl RouteOps for FakeOps {
            async fn add_host_route_via_gateway(
                &self,
                ip: Ipv4Addr,
                gateway: Ipv4Addr,
            ) -> Result<(), Error> {
                let mut table = self.table.lock().unwrap();
                if table.contains_key(&ip) {
                    return Err(Error::ShellCommandError("File exists".into()));
                }
                table.insert(ip, Some(gateway));
                Ok(())
            }
            async fn remove_host_route(&self, ip: Ipv4Addr) -> Result<(), Error> {
                if self.fail_remove.lock().unwrap().contains(&ip) {
                    return Err(Error::ShellCommandError("simulated failure".into()));
                }
                self.table.lock().unwrap().remove(&ip);
                self.removed.lock().unwrap().push(ip);
                Ok(())
            }
            async fn query_host_route(&self, ip: Ipv4Addr) -> HostRouteQuery {
                match self.table.lock().unwrap().get(&ip) {
                    None => HostRouteQuery::Missing,
                    Some(gw) => HostRouteQuery::Entry { gateway: *gw },
                }
            }
        }

        fn ip(s: &str) -> Ipv4Addr {
            s.parse().unwrap()
        }

        #[tokio::test]
        async fn eexist_add_is_not_tracked_and_never_deleted() {
            let ops = FakeOps::default();
            // someone else's /32 for the same endpoint pre-exists
            ops.table
                .lock()
                .unwrap()
                .insert(ip("1.2.3.4"), Some(ip("10.0.0.1")));
            let mut mgr = BypassRouteManager::new(ops);
            mgr.add_one(ip("1.2.3.4"), ip("192.168.0.1")).await;
            assert!(mgr.installed.is_empty());
            mgr.clear().await;
            assert!(mgr.ops.removed.lock().unwrap().is_empty());
            assert!(mgr.ops.table.lock().unwrap().contains_key(&ip("1.2.3.4")));
        }

        #[tokio::test]
        async fn failed_removal_is_retained_and_retried() {
            let mut mgr = BypassRouteManager::new(FakeOps::default());
            mgr.add_one(ip("1.2.3.4"), ip("192.168.0.1")).await;
            mgr.ops.fail_remove.lock().unwrap().insert(ip("1.2.3.4"));
            mgr.sync(&BTreeSet::new(), ip("192.168.0.1")).await;
            assert_eq!(mgr.installed.len(), 1); // kept for retry
            mgr.ops.fail_remove.lock().unwrap().clear();
            mgr.sync(&BTreeSet::new(), ip("192.168.0.1")).await;
            assert!(mgr.installed.is_empty());
            assert!(!mgr.ops.table.lock().unwrap().contains_key(&ip("1.2.3.4")));
        }

        #[tokio::test]
        async fn foreign_replacement_is_not_deleted() {
            let mut mgr = BypassRouteManager::new(FakeOps::default());
            mgr.add_one(ip("1.2.3.4"), ip("192.168.0.1")).await;
            // someone replaced our route with theirs
            mgr.ops
                .table
                .lock()
                .unwrap()
                .insert(ip("1.2.3.4"), Some(ip("10.9.9.9")));
            mgr.clear().await;
            assert!(mgr.installed.is_empty()); // off the books...
            assert!(mgr.ops.table.lock().unwrap().contains_key(&ip("1.2.3.4"))); // ...but not deleted
        }

        #[tokio::test]
        async fn gateway_change_reinstalls_route() {
            let mut mgr = BypassRouteManager::new(FakeOps::default());
            let desired: BTreeSet<Ipv4Addr> = [ip("1.2.3.4")].into();
            mgr.sync(&desired, ip("192.168.0.1")).await;
            mgr.sync(&desired, ip("192.168.5.1")).await;
            assert_eq!(mgr.installed.get(&ip("1.2.3.4")), Some(&ip("192.168.5.1")));
            assert_eq!(
                mgr.ops.table.lock().unwrap().get(&ip("1.2.3.4")),
                Some(&Some(ip("192.168.5.1")))
            );
        }
    }
}

/// Resolve a URI to IPv4 addresses (supports IP literals and hostname DNS resolution)
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
async fn resolve_uri_to_ipv4s(uri: &url::Url) -> Vec<std::net::Ipv4Addr> {
    use std::net::Ipv4Addr;
    let mut ips = Vec::new();
    if let Some(host) = uri.host_str() {
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            ips.push(ip);
            return ips;
        }
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}:0", host)).await {
            for addr in addrs {
                if let std::net::SocketAddr::V4(v4) = addr {
                    ips.push(*v4.ip());
                }
            }
        }
    }
    ips
}

/// Extract the underlay remote IPv4 of a peer connection (the on-wire
/// endpoint, i.e. the hole-punched address for punched conns).
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
fn conn_remote_ipv4(
    conn: &crate::proto::api::instance::PeerConnInfo,
) -> Option<std::net::Ipv4Addr> {
    let url = conn.tunnel.as_ref()?.effective_remote_addr()?;
    let parsed = url::Url::parse(&url.url).ok()?;
    // note: for non-special schemes like udp:// the url crate reports the
    // host as an opaque domain even when it is an IP literal, so parse the
    // host string instead of matching url::Host::Ipv4
    parsed.host_str()?.parse().ok()
}

/// IPv4 subnets directly connected on physical (non-TUN) interfaces. IPs
/// inside them are reachable via connected routes that already beat the /1
/// TUN routes, so they need no bypass.
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
fn physical_onlink_v4_subnets() -> Vec<(std::net::Ipv4Addr, std::net::Ipv4Addr)> {
    use network_interface::NetworkInterfaceConfig;
    let mut subnets = vec![];
    let Ok(ifaces) = network_interface::NetworkInterface::show() else {
        return subnets;
    };
    for iface in ifaces {
        if iface.name.starts_with("utun") || iface.name.starts_with("lo") {
            continue;
        }
        for addr in iface.addr {
            if let network_interface::Addr::V4(v4) = addr
                && let Some(netmask) = v4.netmask
            {
                subnets.push((v4.ip, netmask));
            }
        }
    }
    subnets
}

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
fn is_in_any_v4_subnet(
    ip: std::net::Ipv4Addr,
    subnets: &[(std::net::Ipv4Addr, std::net::Ipv4Addr)],
) -> bool {
    subnets
        .iter()
        .any(|(addr, mask)| u32::from(ip) & u32::from(*mask) == u32::from(*addr) & u32::from(*mask))
}

#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
fn is_bypass_candidate_ipv4(
    ip: std::net::Ipv4Addr,
    onlink_subnets: &[(std::net::Ipv4Addr, std::net::Ipv4Addr)],
    global_ctx: &crate::common::global_ctx::ArcGlobalCtx,
) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && !is_in_any_v4_subnet(ip, onlink_subnets)
        && global_ctx
            .get_ipv4()
            .is_none_or(|net| !net.network().contains(&ip))
}

/// All remote IPv4 endpoints easytier's underlay may talk to: configured
/// peers and live peer connections (including hole-punched endpoints that
/// appear in no config). STUN probes need no bypass — their sockets are
/// interface-bound (see bind_underlay_udp_socket).
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
async fn collect_underlay_bypass_ips(
    global_ctx: &crate::common::global_ctx::ArcGlobalCtx,
    peer_mgr: &std::sync::Arc<crate::peers::peer_manager::PeerManager>,
) -> std::collections::BTreeSet<std::net::Ipv4Addr> {
    let mut ips = std::collections::BTreeSet::new();

    for peer in global_ctx.config.get_peers() {
        let resolved = resolve_uri_to_ipv4s(&peer.uri).await;
        if resolved.is_empty() {
            tracing::warn!(uri = %peer.uri, "failed to resolve peer URI for bypass route");
        }
        ips.extend(resolved);
    }

    let peer_map = peer_mgr.get_peer_map();
    for peer_id in peer_map.list_peers_with_conn().await {
        for conn in peer_map.list_peer_conns(peer_id).await.unwrap_or_default() {
            ips.extend(conn_remote_ipv4(&conn));
        }
    }

    let onlink_subnets = physical_onlink_v4_subnets();
    ips.retain(|ip| is_bypass_candidate_ipv4(*ip, &onlink_subnets, global_ctx));
    ips
}

/// Reconcile bypass host routes with the current desired endpoint set. Only
/// active while broad TUN routes (prefix <= 1) are installed or about to be.
#[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
async fn sync_macos_bypass_routes(
    bypass: &mut macos_bypass::BypassRouteManager<impl macos_bypass::RouteOps>,
    cur_proxy_cidrs: &BTreeSet<cidr::Ipv4Cidr>,
    pending_added: &[cidr::Ipv4Cidr],
    global_ctx: &crate::common::global_ctx::ArcGlobalCtx,
    peer_mgr: &std::sync::Arc<crate::peers::peer_manager::PeerManager>,
) {
    let full_tunnel = cur_proxy_cidrs
        .iter()
        .chain(pending_added.iter())
        .any(|c| c.network_length() <= 1);
    if !full_tunnel {
        bypass.clear().await;
        return;
    }

    let Some(route) = crate::arch::macos::get_default_route_v4() else {
        // transient loss of the default route (e.g. wifi roaming) should not
        // tear down routes that may come back into effect
        tracing::warn!("no physical default route, skip bypass route sync");
        return;
    };
    let ips = collect_underlay_bypass_ips(global_ctx, peer_mgr).await;
    tracing::debug!(?ips, gateway = ?route.gateway, "syncing underlay bypass routes");
    bypass.sync(&ips, route.gateway).await;
}

#[cfg(test)]
mod tests {
    use crate::common::{error::Error, global_ctx::tests::get_mock_global_ctx};

    use super::VirtualNic;

    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
    #[test]
    fn test_is_in_any_v4_subnet() {
        let subnets = vec![
            ("192.168.0.20".parse().unwrap(), "255.255.255.0".parse().unwrap()),
            ("10.0.0.1".parse().unwrap(), "255.0.0.0".parse().unwrap()),
        ];
        assert!(super::is_in_any_v4_subnet(
            "192.168.0.1".parse().unwrap(),
            &subnets
        ));
        assert!(super::is_in_any_v4_subnet(
            "10.200.1.1".parse().unwrap(),
            &subnets
        ));
        assert!(!super::is_in_any_v4_subnet(
            "192.168.2.1".parse().unwrap(),
            &subnets
        ));
        assert!(!super::is_in_any_v4_subnet(
            "220.203.172.102".parse().unwrap(),
            &subnets
        ));
    }

    #[cfg(all(target_os = "macos", not(feature = "macos-ne")))]
    #[test]
    fn test_conn_remote_ipv4() {
        use crate::proto::{
            api::instance::PeerConnInfo,
            common::{TunnelInfo, Url},
        };

        let mk = |remote: Option<&str>, resolved: Option<&str>| PeerConnInfo {
            tunnel: Some(TunnelInfo {
                tunnel_type: "udp".to_string(),
                local_addr: None,
                remote_addr: remote.map(|u| Url { url: u.to_string() }),
                resolved_remote_addr: resolved.map(|u| Url { url: u.to_string() }),
            }),
            ..Default::default()
        };

        // resolved addr (the on-wire endpoint) wins over the configured one
        assert_eq!(
            super::conn_remote_ipv4(&mk(
                Some("udp://example.com:11010"),
                Some("udp://220.203.172.102:23456")
            )),
            Some("220.203.172.102".parse().unwrap())
        );
        assert_eq!(
            super::conn_remote_ipv4(&mk(Some("tcp://8.219.8.190:11010"), None)),
            Some("8.219.8.190".parse().unwrap())
        );
        // hostname-only url has no ipv4 to bypass
        assert_eq!(
            super::conn_remote_ipv4(&mk(Some("tcp://example.com:11010"), None)),
            None
        );
        assert_eq!(super::conn_remote_ipv4(&PeerConnInfo::default()), None);
    }


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
