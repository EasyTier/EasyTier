use bytes::Bytes;
use bytes::BytesMut;
use nix::libc;
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::socket::fake_tcp::stack;

const ETH_HDR_LEN: usize = 14;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const IPPROTO_TCP_U32: u32 = 6;

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_JMP: u16 = 0x05;
const BPF_RET: u16 = 0x06;

const BPF_W: u16 = 0x00;
const BPF_H: u16 = 0x08;
const BPF_B: u16 = 0x10;

const BPF_ABS: u16 = 0x20;
const BPF_IND: u16 = 0x40;
const BPF_MSH: u16 = 0xa0;

const BPF_JA: u16 = 0x00;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;

const BPF_K: u16 = 0x00;

const SOL_PACKET: i32 = 263;
const PACKET_STATISTICS: i32 = 6;

const DEFAULT_RCVBUF_BYTES: i32 = 32 * 1024 * 1024;
const IPV4_FRAGMENT_OFFSET_MASK: u32 = 0x1fff;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jeq(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k,
    }
}

fn jset(k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP | BPF_JSET | BPF_K,
        jt,
        jf,
        k,
    }
}

fn ja(k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code: BPF_JMP | BPF_JA,
        jt: 0,
        jf: 0,
        k,
    }
}

#[derive(Clone, Copy)]
struct Label(usize);

struct ConditionalJumpPatch {
    idx: usize,
    t: Label,
    f: Label,
}

struct JaPatch {
    idx: usize,
    target: Label,
}

struct BpfBuilder {
    insns: Vec<libc::sock_filter>,
    labels: Vec<Option<usize>>,
    conditional_jump_patches: Vec<ConditionalJumpPatch>,
    ja_patches: Vec<JaPatch>,
}

impl BpfBuilder {
    fn new() -> Self {
        Self {
            insns: Vec::new(),
            labels: Vec::new(),
            conditional_jump_patches: Vec::new(),
            ja_patches: Vec::new(),
        }
    }

    fn new_label(&mut self) -> Label {
        let idx = self.labels.len();
        self.labels.push(None);
        Label(idx)
    }

    fn set_label(&mut self, label: Label) {
        self.labels[label.0] = Some(self.insns.len());
    }

    fn push(&mut self, insn: libc::sock_filter) {
        self.insns.push(insn);
    }

    fn push_jeq(&mut self, k: u32, t: Label, f: Label) {
        let idx = self.insns.len();
        self.insns.push(jeq(k, 0, 0));
        self.conditional_jump_patches
            .push(ConditionalJumpPatch { idx, t, f });
    }

    fn push_jset(&mut self, k: u32, t: Label, f: Label) {
        let idx = self.insns.len();
        self.insns.push(jset(k, 0, 0));
        self.conditional_jump_patches
            .push(ConditionalJumpPatch { idx, t, f });
    }

    fn push_ja(&mut self, target: Label) {
        let idx = self.insns.len();
        self.insns.push(ja(0));
        self.ja_patches.push(JaPatch { idx, target });
    }

    fn finish(mut self) -> io::Result<Vec<libc::sock_filter>> {
        for patch in self.conditional_jump_patches {
            let ConditionalJumpPatch { idx, t, f } = patch;
            let cur = idx + 1;
            let t_pos =
                self.labels.get(t.0).and_then(|v| *v).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "unresolved label")
                })?;
            let f_pos =
                self.labels.get(f.0).and_then(|v| *v).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "unresolved label")
                })?;

            if t_pos < cur || f_pos < cur {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "backward bpf jump",
                ));
            }

            let jt: u8 = (t_pos - cur)
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bpf jump too far"))?;
            let jf: u8 = (f_pos - cur)
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bpf jump too far"))?;

            self.insns[idx].jt = jt;
            self.insns[idx].jf = jf;
        }

        for patch in self.ja_patches {
            let JaPatch { idx, target } = patch;
            let cur = idx + 1;
            let t_pos =
                self.labels.get(target.0).and_then(|v| *v).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "unresolved label")
                })?;
            if t_pos < cur {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "backward bpf jump",
                ));
            }
            self.insns[idx].k = (t_pos - cur) as u32;
        }

        Ok(self.insns)
    }
}

fn build_tcp_filter(
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Vec<libc::sock_filter>> {
    if let Some(src) = src_addr
        && src.is_ipv4() != dst_addr.is_ipv4()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "src/dst addr family mismatch",
        ));
    }

    let mut b = BpfBuilder::new();
    let l_accept = b.new_label();
    let l_reject = b.new_label();

    if dst_addr.is_ipv4() {
        let l_v4_proto_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, 9));
        b.push_jeq(IPPROTO_TCP_U32, l_v4_proto_ok, l_reject);

        b.set_label(l_v4_proto_ok);
        let l_v4_fragment_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_H | BPF_ABS, 6));
        b.push_jset(
            IPV4_FRAGMENT_OFFSET_MASK,
            l_reject,
            l_v4_fragment_ok,
        );

        b.set_label(l_v4_fragment_ok);
        let dst_ip = match dst_addr.ip() {
            IpAddr::V4(ip) => u32::from(ip),
            _ => unreachable!(),
        };
        let l_v4_dstip_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_W | BPF_ABS, 16));
        b.push_jeq(dst_ip, l_v4_dstip_ok, l_reject);

        b.set_label(l_v4_dstip_ok);
        if let Some(src) = src_addr {
            let src_ip = match src.ip() {
                IpAddr::V4(ip) => u32::from(ip),
                _ => unreachable!(),
            };
            let l_v4_srcip_ok = b.new_label();
            b.push(stmt(BPF_LD | BPF_W | BPF_ABS, 12));
            b.push_jeq(src_ip, l_v4_srcip_ok, l_reject);
            b.set_label(l_v4_srcip_ok);
        }

        b.push(stmt(BPF_LDX | BPF_B | BPF_MSH, 0));

        let l_v4_dstport_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_H | BPF_IND, 2));
        b.push_jeq(dst_addr.port() as u32, l_v4_dstport_ok, l_reject);

        b.set_label(l_v4_dstport_ok);
        if let Some(src) = src_addr {
            b.push(stmt(BPF_LD | BPF_H | BPF_IND, 0));
            b.push_jeq(src.port() as u32, l_accept, l_reject);
        } else {
            b.push_ja(l_accept);
        }
    } else {
        let l_v6_proto_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, 6));
        b.push_jeq(IPPROTO_TCP_U32, l_v6_proto_ok, l_reject);

        b.set_label(l_v6_proto_ok);
        let dst_ip = match dst_addr.ip() {
            IpAddr::V6(ip) => ip.octets(),
            _ => unreachable!(),
        };
        for (i, chunk) in dst_ip.chunks_exact(4).enumerate() {
            let off = 24 + (i * 4);
            let v = u32::from_be_bytes(chunk.try_into().unwrap());
            let l_v6_dstip_word_ok = b.new_label();
            b.push(stmt(BPF_LD | BPF_W | BPF_ABS, off as u32));
            b.push_jeq(v, l_v6_dstip_word_ok, l_reject);
            b.set_label(l_v6_dstip_word_ok);
        }

        if let Some(src) = src_addr {
            let src_ip = match src.ip() {
                IpAddr::V6(ip) => ip.octets(),
                _ => unreachable!(),
            };
            for (i, chunk) in src_ip.chunks_exact(4).enumerate() {
                let off = 8 + (i * 4);
                let v = u32::from_be_bytes(chunk.try_into().unwrap());
                let l_v6_srcip_word_ok = b.new_label();
                b.push(stmt(BPF_LD | BPF_W | BPF_ABS, off as u32));
                b.push_jeq(v, l_v6_srcip_word_ok, l_reject);
                b.set_label(l_v6_srcip_word_ok);
            }
        }

        let l_v6_dstport_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_H | BPF_ABS, 42));
        b.push_jeq(dst_addr.port() as u32, l_v6_dstport_ok, l_reject);

        b.set_label(l_v6_dstport_ok);
        if let Some(src) = src_addr {
            b.push(stmt(BPF_LD | BPF_H | BPF_ABS, 40));
            b.push_jeq(src.port() as u32, l_accept, l_reject);
        } else {
            b.push_ja(l_accept);
        }
    }

    b.set_label(l_accept);
    b.push(stmt(BPF_RET | BPF_K, 0xFFFF));

    b.set_label(l_reject);
    b.push(stmt(BPF_RET | BPF_K, 0));

    b.finish()
}

fn ether_type_for_ip(packet: &[u8]) -> io::Result<u16> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) => Ok(ETHERTYPE_IPV4),
        Some(6) => Ok(ETHERTYPE_IPV6),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet has no valid IP header",
        )),
    }
}

fn normalize_rx_packet(packet: &[u8], link_addr: &libc::sockaddr_ll) -> io::Result<Vec<u8>> {
    let ether_type = ether_type_for_ip(packet)?;
    let mut frame = vec![0; ETH_HDR_LEN + packet.len()];
    if link_addr.sll_halen == 6 {
        frame[6..12].copy_from_slice(&link_addr.sll_addr[..6]);
    }
    frame[12..14].copy_from_slice(&ether_type.to_be_bytes());
    frame[ETH_HDR_LEN..].copy_from_slice(packet);
    Ok(frame)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PacketSocketStats {
    tp_packets: u32,
    tp_drops: u32,
}

fn set_socket_rcvbuf(fd: i32, desired_bytes: i32) -> io::Result<i32> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &desired_bytes as *const _ as *const libc::c_void,
            mem::size_of_val(&desired_bytes) as u32,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut actual: i32 = 0;
    let mut len = mem::size_of_val(&actual) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &mut actual as *mut _ as *mut libc::c_void,
            &mut len as *mut _,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(actual)
}

fn read_packet_socket_stats(fd: i32) -> io::Result<PacketSocketStats> {
    let mut stats = PacketSocketStats::default();
    let mut len = mem::size_of_val(&stats) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            SOL_PACKET,
            PACKET_STATISTICS,
            &mut stats as *mut _ as *mut libc::c_void,
            &mut len as *mut _,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(stats)
}

pub struct LinuxBpfTun {
    fd: Arc<OwnedFd>,
    ifindex: i32,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    recv_queue: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl LinuxBpfTun {
    pub fn new(
        interface_name: &str,
        src_addr: Option<SocketAddr>,
        dst_addr: SocketAddr,
    ) -> io::Result<Self> {
        let c_ifname = CString::new(interface_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
        let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) as i32 };
        if ifindex <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            ));
        }

        let protocol = match dst_addr {
            SocketAddr::V4(_) => ETHERTYPE_IPV4,
            SocketAddr::V6(_) => ETHERTYPE_IPV6,
        };
        let proto = protocol.to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = protocol.to_be();
        addr.sll_ifindex = ifindex;

        let bind_ret = unsafe {
            libc::bind(
                fd.as_ref().as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if bind_ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let actual_rcvbuf = set_socket_rcvbuf(fd.as_ref().as_raw_fd(), DEFAULT_RCVBUF_BYTES)?;

        let filter = build_tcp_filter(src_addr, dst_addr)?;
        let mut prog = libc::sock_fprog {
            len: filter
                .len()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bpf program too long"))?,
            filter: filter.as_ptr() as *mut libc::sock_filter,
        };
        let opt_ret = unsafe {
            libc::setsockopt(
                fd.as_ref().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_ATTACH_FILTER,
                &mut prog as *mut _ as *mut libc::c_void,
                mem::size_of::<libc::sock_fprog>() as u32,
            )
        };
        if opt_ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        let _ = unsafe {
            libc::setsockopt(
                fd.as_ref().as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                mem::size_of::<libc::timeval>() as u32,
            )
        };

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let stop_clone = stop.clone();
        let read_fd = fd.as_ref().as_raw_fd();
        let fd_guard = fd.clone();
        let interface_name_for_worker = interface_name.to_string();

        let worker = std::thread::spawn(move || {
            // Keep the packet socket alive until the detached worker actually exits.
            let _fd_guard = fd_guard;
            let mut buf = vec![0u8; 65536];
            let mut stats_enabled = true;
            let mut total_packets: u64 = 0;
            let mut total_drops: u64 = 0;
            let mut total_bytes: u64 = 0;
            let mut dropped_by_queue_full: u64 = 0;
            let mut last_stats_log = Instant::now();
            while !stop_clone.load(AtomicOrdering::Relaxed) {
                let mut link_addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
                let mut link_addr_len = mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
                let n = unsafe {
                    libc::recvfrom(
                        read_fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                        0,
                        &mut link_addr as *mut _ as *mut libc::sockaddr,
                        &mut link_addr_len,
                    )
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if matches!(
                        err.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    break;
                }
                if n == 0 {
                    continue;
                }
                let Ok(data) = normalize_rx_packet(&buf[..n as usize], &link_addr) else {
                    continue;
                };
                total_bytes = total_bytes.wrapping_add(n as u64);
                match tx.try_send(data) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        dropped_by_queue_full = dropped_by_queue_full.wrapping_add(1);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => break,
                }

                if last_stats_log.elapsed() >= Duration::from_secs(1) {
                    if stats_enabled {
                        match read_packet_socket_stats(read_fd) {
                            Ok(delta) => {
                                total_packets = total_packets.wrapping_add(delta.tp_packets as u64);
                                total_drops = total_drops.wrapping_add(delta.tp_drops as u64);

                                let denom =
                                    (delta.tp_packets as u64).saturating_add(delta.tp_drops as u64);
                                let drop_rate = if denom == 0 {
                                    0.0
                                } else {
                                    (delta.tp_drops as f64) / (denom as f64)
                                };

                                tracing::debug!(
                                    "{}: delta_packets = {}, delta_drops = {}, delta_drop_rate = {}, total_packets = {}, total_drops = {}, total_bytes = {}, dropped_by_queue_full = {}",
                                    interface_name_for_worker,
                                    delta.tp_packets,
                                    delta.tp_drops,
                                    drop_rate,
                                    total_packets,
                                    total_drops,
                                    total_bytes,
                                    dropped_by_queue_full,
                                );
                            }
                            Err(e) => {
                                stats_enabled = false;
                                tracing::warn!(
                                    ?e,
                                    interface_name_for_worker,
                                    "LinuxBpfTun failed to read PACKET_STATISTICS, stats disabled"
                                );
                            }
                        }
                    } else {
                        tracing::debug!(
                            "{}: total_bytes = {}, dropped_by_queue_full = {}",
                            interface_name_for_worker,
                            total_bytes,
                            dropped_by_queue_full,
                        );
                    }
                    last_stats_log = Instant::now();
                }
            }
        });

        tracing::info!(
            interface_name,
            ifindex,
            desired_rcvbuf = DEFAULT_RCVBUF_BYTES,
            actual_rcvbuf,
            "LinuxBpfTun created with filter {:?}",
            filter
        );

        Ok(Self {
            fd,
            ifindex,
            stop,
            worker: Some(worker),
            recv_queue: Mutex::new(rx),
        })
    }
}

impl Drop for LinuxBpfTun {
    fn drop(&mut self) {
        self.stop.store(true, AtomicOrdering::Relaxed);
        let _ = unsafe { libc::shutdown(self.fd.as_ref().as_raw_fd(), libc::SHUT_RD) };
        if let Some(worker) = self.worker.take() {
            // Dropping the JoinHandle detaches the worker. The worker holds its own Arc<OwnedFd>
            // clone, so the packet socket stays valid until recv wakes up and the thread exits.
            drop(worker);
        }
    }
}

#[async_trait::async_trait]
impl stack::Tun for LinuxBpfTun {
    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error> {
        let mut rx = self.recv_queue.lock().await;
        match rx.recv().await {
            Some(data) => {
                packet.extend_from_slice(&data);
                Ok(data.len())
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "LinuxBpfTun channel closed",
            )),
        }
    }

    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
        if packet.len() < ETH_HDR_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "packet too short",
            ));
        }
        let payload = &packet[ETH_HDR_LEN..];
        let protocol = ether_type_for_ip(payload)?;
        let frame_protocol = u16::from_be_bytes([packet[12], packet[13]]);
        if frame_protocol != protocol {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Ethernet and IP protocol mismatch",
            ));
        }

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = protocol.to_be();
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&packet[..6]);

        let ret = unsafe {
            libc::sendto(
                self.fd.as_ref().as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if ret as usize != payload.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial packet socket write",
            ));
        }
        Ok(())
    }

    fn driver_type(&self) -> &'static str {
        "linux_bpf"
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    use crate::socket::fake_tcp::packet::{MacAddr, TCP_FLAG_SYN, build_tcp_packet};
    use crate::socket::fake_tcp::stack::Tun;
    use pnet_datalink as datalink;
    use rand::Rng;
    use serial_test::serial;
    use std::env;
    use std::process::Command;
    use tokio::time::{Duration, timeout};

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn linux_bpf_integration_enabled(test_name: &str) -> bool {
        if env::var_os("EASYTIER_LINUX_BPF_INTEGRATION").is_none() {
            eprintln!("{test_name}: skipped (EASYTIER_LINUX_BPF_INTEGRATION not set)");
            return false;
        }
        assert!(
            is_root(),
            "{test_name}: EASYTIER_LINUX_BPF_INTEGRATION requires root"
        );
        true
    }

    fn run_ip(args: &[&str]) -> io::Result<()> {
        let output = Command::new("ip").args(args).output()?;
        if output.status.success() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "ip {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        )))
    }

    fn test_frame(src_addr: SocketAddr, dst_addr: SocketAddr) -> Bytes {
        build_tcp_packet(
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 1]),
            MacAddr::from_bytes(&[0x02, 0, 0, 0, 0, 2]),
            src_addr,
            dst_addr,
            1,
            0,
            TCP_FLAG_SYN,
            Some(b"test"),
        )
    }

    fn set_ipv4_fragment_offset(packet: &mut [u8], fragment_offset: u16) {
        assert_eq!(packet[0] >> 4, 4);
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        packet[6..8].copy_from_slice(&(fragment_offset & 0x1fff).to_be_bytes());
        packet[10..12].fill(0);

        let mut sum = 0u32;
        for word in packet[..header_len].chunks_exact(2) {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        while sum > u16::MAX as u32 {
            sum = (sum & u16::MAX as u32) + (sum >> 16);
        }
        packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    }

    const TUN_DEV_PATH: &str = "/dev/net/tun";

    struct TestTun {
        name: String,
        fd: OwnedFd,
    }

    impl TestTun {
        fn create() -> io::Result<Self> {
            let name = format!("etlb{}", rand::thread_rng().gen_range(10000..99999));
            let path = CString::new(TUN_DEV_PATH)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid tun path"))?;
            let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let fd = unsafe { OwnedFd::from_raw_fd(fd) };

            let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
            for (index, byte) in name.bytes().enumerate() {
                ifr.ifr_name[index] = byte as libc::c_char;
            }
            ifr.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;

            let ret = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF, &mut ifr) };
            if ret != 0 {
                return Err(io::Error::last_os_error());
            }
            run_ip(&["link", "set", "dev", &name, "up"])?;
            Ok(Self { name, fd })
        }

        fn write_packet(&self, packet: &[u8]) -> io::Result<()> {
            let ret = unsafe {
                libc::write(
                    self.fd.as_raw_fd(),
                    packet.as_ptr() as *const libc::c_void,
                    packet.len(),
                )
            };
            if ret < 0 {
                return Err(io::Error::last_os_error());
            }
            if ret as usize != packet.len() {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "partial tun packet write",
                ));
            }
            Ok(())
        }

        fn read_matching_packet(&self, expected: &[u8]) -> io::Result<Vec<u8>> {
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out waiting for matching TUN packet",
                    ));
                }

                let mut pollfd = libc::pollfd {
                    fd: self.fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let timeout_ms = remaining.as_millis().min(i32::MAX as u128) as i32;
                let ready = unsafe { libc::poll(&mut pollfd, 1, timeout_ms) };
                if ready < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                if ready == 0 {
                    continue;
                }

                let mut packet = vec![0; 65_536];
                let len = unsafe {
                    libc::read(
                        self.fd.as_raw_fd(),
                        packet.as_mut_ptr() as *mut libc::c_void,
                        packet.len(),
                    )
                };
                if len < 0 {
                    return Err(io::Error::last_os_error());
                }
                packet.truncate(len as usize);
                if packet == expected {
                    return Ok(packet);
                }
            }
        }
    }

    impl Drop for TestTun {
        fn drop(&mut self) {
            let _ = run_ip(&["link", "del", "dev", &self.name]);
        }
    }

    struct TestVeth {
        capture_name: String,
        sender_name: String,
        capture_mac: MacAddr,
        sender_mac: MacAddr,
    }

    impl TestVeth {
        fn create() -> io::Result<Self> {
            let suffix = rand::thread_rng().gen_range(10000..99999);
            let capture_name = format!("elbc{suffix}");
            let sender_name = format!("elbs{suffix}");
            run_ip(&[
                "link",
                "add",
                &capture_name,
                "type",
                "veth",
                "peer",
                "name",
                &sender_name,
            ])?;

            let setup_result = (|| {
                run_ip(&["link", "set", "dev", &capture_name, "up"])?;
                run_ip(&["link", "set", "dev", &sender_name, "up"])?;
                let interfaces = datalink::interfaces();
                let find_mac = |name: &str| {
                    interfaces
                        .iter()
                        .find(|interface| interface.name == name)
                        .and_then(|interface| interface.mac)
                        .map(|mac| MacAddr::from_bytes(&mac.octets()))
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::NotFound, "veth MAC address not found")
                        })
                };
                Ok((find_mac(&capture_name)?, find_mac(&sender_name)?))
            })();

            let (capture_mac, sender_mac) = match setup_result {
                Ok(macs) => macs,
                Err(error) => {
                    let _ = run_ip(&["link", "del", "dev", &capture_name]);
                    return Err(error);
                }
            };

            Ok(Self {
                capture_name,
                sender_name,
                capture_mac,
                sender_mac,
            })
        }
    }

    impl Drop for TestVeth {
        fn drop(&mut self) {
            let _ = run_ip(&["link", "del", "dev", &self.capture_name]);
        }
    }

    fn open_datalink_channel(
        interface_name: &str,
    ) -> io::Result<(
        Box<dyn datalink::DataLinkSender>,
        Box<dyn datalink::DataLinkReceiver>,
    )> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|interface| interface.name == interface_name)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "interface not found"))?;
        let config = datalink::Config {
            read_timeout: Some(Duration::from_millis(100)),
            ..Default::default()
        };
        match datalink::channel(&interface, config).map_err(io::Error::other)? {
            datalink::Channel::Ethernet(sender, receiver) => Ok((sender, receiver)),
            _ => Err(io::Error::other("unsupported datalink channel")),
        }
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_receives_ipv4_from_l3_interface() -> io::Result<()> {
        let test_name = "linux_bpf_tun_receives_ipv4_from_l3_interface";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let test_tun = TestTun::create()?;
        let src_addr: SocketAddr = "192.0.2.10:12345".parse().unwrap();
        let dst_addr: SocketAddr = "198.51.100.20:23456".parse().unwrap();
        let frame = test_frame(src_addr, dst_addr);
        let tun = LinuxBpfTun::new(&test_tun.name, None, dst_addr)?;

        test_tun.write_packet(&frame[ETH_HDR_LEN..])?;

        let mut received = BytesMut::new();
        let n = timeout(Duration::from_secs(2), tun.recv(&mut received))
            .await
            .expect("timed out waiting for packet")?;
        assert_eq!(n, frame.len());
        assert!(received[..12].iter().all(|byte| *byte == 0));
        assert_eq!(&received[12..14], &frame[12..14]);
        assert_eq!(&received[ETH_HDR_LEN..], &frame[ETH_HDR_LEN..]);

        Ok(())
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_sends_ipv4_to_l3_interface() -> io::Result<()> {
        let test_name = "linux_bpf_tun_sends_ipv4_to_l3_interface";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let test_tun = TestTun::create()?;
        let src_addr: SocketAddr = "192.0.2.30:34567".parse().unwrap();
        let dst_addr: SocketAddr = "198.51.100.40:45678".parse().unwrap();
        let frame = test_frame(src_addr, dst_addr);
        let tun = LinuxBpfTun::new(&test_tun.name, None, dst_addr)?;

        tun.try_send(&frame)?;

        let packet = test_tun.read_matching_packet(&frame[ETH_HDR_LEN..])?;
        assert_eq!(packet, &frame[ETH_HDR_LEN..]);

        Ok(())
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_rejects_non_initial_ipv4_fragment() -> io::Result<()> {
        let test_name = "linux_bpf_tun_rejects_non_initial_ipv4_fragment";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let test_tun = TestTun::create()?;
        let src_addr: SocketAddr = "192.0.2.50:12345".parse().unwrap();
        let dst_addr: SocketAddr = "198.51.100.60:23456".parse().unwrap();
        let frame = test_frame(src_addr, dst_addr);
        let tun = LinuxBpfTun::new(&test_tun.name, None, dst_addr)?;

        let mut fragment = frame[ETH_HDR_LEN..].to_vec();
        set_ipv4_fragment_offset(&mut fragment, 1);
        test_tun.write_packet(&fragment)?;

        let mut received = BytesMut::new();
        assert!(
            timeout(Duration::from_millis(400), tun.recv(&mut received))
                .await
                .is_err(),
            "non-initial IPv4 fragment passed the TCP port filter"
        );

        test_tun.write_packet(&frame[ETH_HDR_LEN..])?;
        let mut received = BytesMut::new();
        timeout(Duration::from_secs(2), tun.recv(&mut received))
            .await
            .expect("timed out waiting for unfragmented packet")?;

        Ok(())
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_filters_ipv4_tuple_on_l3_interface() -> io::Result<()> {
        let test_name = "linux_bpf_tun_filters_ipv4_tuple_on_l3_interface";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let test_tun = TestTun::create()?;
        let src_addr: SocketAddr = "192.0.2.70:12345".parse().unwrap();
        let dst_addr: SocketAddr = "198.51.100.80:23456".parse().unwrap();
        let tun = LinuxBpfTun::new(&test_tun.name, Some(src_addr), dst_addr)?;

        let wrong_src_port = test_frame("192.0.2.70:12346".parse().unwrap(), dst_addr);
        let wrong_src_ip = test_frame("192.0.2.71:12345".parse().unwrap(), dst_addr);
        let wrong_dst_port = test_frame(src_addr, "198.51.100.80:23457".parse().unwrap());
        for frame in [&wrong_src_port, &wrong_src_ip, &wrong_dst_port] {
            test_tun.write_packet(&frame[ETH_HDR_LEN..])?;
        }

        let mut received = BytesMut::new();
        assert!(
            timeout(Duration::from_millis(400), tun.recv(&mut received))
                .await
                .is_err(),
            "packet outside the configured IPv4 tuple passed the filter"
        );

        let matching = test_frame(src_addr, dst_addr);
        test_tun.write_packet(&matching[ETH_HDR_LEN..])?;
        let mut received = BytesMut::new();
        timeout(Duration::from_secs(2), tun.recv(&mut received))
            .await
            .expect("timed out waiting for matching IPv4 packet")?;
        assert_eq!(&received[ETH_HDR_LEN..], &matching[ETH_HDR_LEN..]);

        Ok(())
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_receives_ipv6_from_l3_interface() -> io::Result<()> {
        let test_name = "linux_bpf_tun_receives_ipv6_from_l3_interface";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let test_tun = TestTun::create()?;
        let src_addr: SocketAddr = "[2001:db8::10]:12345".parse().unwrap();
        let dst_addr: SocketAddr = "[2001:db8::20]:23456".parse().unwrap();
        let frame = test_frame(src_addr, dst_addr);
        let tun = LinuxBpfTun::new(&test_tun.name, None, dst_addr)?;

        test_tun.write_packet(&frame[ETH_HDR_LEN..])?;

        let mut received = BytesMut::new();
        timeout(Duration::from_secs(2), tun.recv(&mut received))
            .await
            .expect("timed out waiting for IPv6 packet")?;
        assert!(received[..12].iter().all(|byte| *byte == 0));
        assert_eq!(&received[12..14], &frame[12..14]);
        assert_eq!(&received[ETH_HDR_LEN..], &frame[ETH_HDR_LEN..]);

        Ok(())
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_sends_ipv6_to_l3_interface() -> io::Result<()> {
        let test_name = "linux_bpf_tun_sends_ipv6_to_l3_interface";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let test_tun = TestTun::create()?;
        let src_addr: SocketAddr = "[2001:db8::30]:34567".parse().unwrap();
        let dst_addr: SocketAddr = "[2001:db8::40]:45678".parse().unwrap();
        let frame = test_frame(src_addr, dst_addr);
        let tun = LinuxBpfTun::new(&test_tun.name, None, dst_addr)?;

        tun.try_send(&frame)?;

        let packet = test_tun.read_matching_packet(&frame[ETH_HDR_LEN..])?;
        assert_eq!(packet, &frame[ETH_HDR_LEN..]);

        Ok(())
    }

    fn send_raw_frame(interface_name: &str, frame: &[u8]) -> io::Result<()> {
        if frame.len() < ETH_HDR_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame too short",
            ));
        }

        let c_ifname = CString::new(interface_name)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
        let ifindex = unsafe { libc::if_nametoindex(c_ifname.as_ptr()) as i32 };
        if ifindex <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "interface not found",
            ));
        }

        let frame_protocol = u16::from_be_bytes([frame[12], frame[13]]);
        let proto = frame_protocol.to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = frame_protocol.to_be();
        addr.sll_ifindex = ifindex;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&frame[..6]);

        let ret = unsafe {
            libc::sendto(
                fd.as_raw_fd(),
                frame.as_ptr() as *const libc::c_void,
                frame.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_receives_matching_ipv4_frame() -> io::Result<()> {
        let test_name = "linux_bpf_tun_receives_matching_ipv4_frame";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let veth = TestVeth::create()?;
        let src_addr: SocketAddr = "192.0.2.90:12345".parse().unwrap();
        let dst_addr: SocketAddr = "198.51.100.100:23456".parse().unwrap();
        let tun = LinuxBpfTun::new(&veth.capture_name, None, dst_addr)?;
        let frame = build_tcp_packet(
            veth.sender_mac,
            veth.capture_mac,
            src_addr,
            dst_addr,
            1,
            0,
            TCP_FLAG_SYN,
            Some(b"ping"),
        );

        send_raw_frame(&veth.sender_name, &frame)?;

        let mut received = BytesMut::new();
        let n = timeout(Duration::from_secs(2), tun.recv(&mut received))
            .await
            .expect("timed out waiting for Ethernet packet")?;
        assert_eq!(n, frame.len());
        assert!(received[..6].iter().all(|byte| *byte == 0));
        assert_eq!(&received[6..12], &frame[6..12]);
        assert_eq!(&received[12..14], &frame[12..14]);
        assert_eq!(&received[ETH_HDR_LEN..], &frame[ETH_HDR_LEN..]);

        Ok(())
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_filters_out_non_matching_ipv4_frame() -> io::Result<()> {
        let test_name = "linux_bpf_tun_filters_out_non_matching_ipv4_frame";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let veth = TestVeth::create()?;
        let src_addr: SocketAddr = "192.0.2.110:12345".parse().unwrap();
        let dst_addr: SocketAddr = "198.51.100.120:23456".parse().unwrap();
        let non_matching_dst: SocketAddr = "198.51.100.120:23457".parse().unwrap();
        let tun = LinuxBpfTun::new(&veth.capture_name, None, dst_addr)?;
        let non_matching = build_tcp_packet(
            veth.sender_mac,
            veth.capture_mac,
            src_addr,
            non_matching_dst,
            1,
            0,
            TCP_FLAG_SYN,
            Some(b"nope"),
        );
        send_raw_frame(&veth.sender_name, &non_matching)?;

        let mut received = BytesMut::new();
        assert!(
            timeout(Duration::from_millis(400), tun.recv(&mut received))
                .await
                .is_err()
        );

        let matching = build_tcp_packet(
            veth.sender_mac,
            veth.capture_mac,
            src_addr,
            dst_addr,
            2,
            0,
            TCP_FLAG_SYN,
            Some(b"ok"),
        );
        send_raw_frame(&veth.sender_name, &matching)?;

        let mut received = BytesMut::new();
        let n = timeout(Duration::from_secs(2), tun.recv(&mut received))
            .await
            .expect("timed out waiting for matching Ethernet packet")?;
        assert_eq!(n, matching.len());
        assert_eq!(&received[ETH_HDR_LEN..], &matching[ETH_HDR_LEN..]);

        Ok(())
    }

    #[tokio::test]
    #[serial(linux_bpf_cooked)]
    async fn linux_bpf_tun_sends_ipv4_frame_to_ethernet_interface() -> io::Result<()> {
        let test_name = "linux_bpf_tun_sends_ipv4_frame_to_ethernet_interface";
        if !linux_bpf_integration_enabled(test_name) {
            return Ok(());
        }

        let veth = TestVeth::create()?;
        let (_sender, mut receiver) = open_datalink_channel(&veth.sender_name)?;
        let src_addr: SocketAddr = "192.0.2.130:12345".parse().unwrap();
        let dst_addr: SocketAddr = "198.51.100.140:23456".parse().unwrap();
        let frame = build_tcp_packet(
            veth.capture_mac,
            veth.sender_mac,
            src_addr,
            dst_addr,
            1,
            0,
            TCP_FLAG_SYN,
            Some(b"ethernet send"),
        );
        let tun = LinuxBpfTun::new(&veth.capture_name, None, dst_addr)?;

        tun.try_send(&frame)?;

        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match receiver.next() {
                Ok(received)
                    if received.len() >= ETH_HDR_LEN
                        && received[ETH_HDR_LEN..] == frame[ETH_HDR_LEN..] =>
                {
                    assert_eq!(&received[..ETH_HDR_LEN], &frame[..ETH_HDR_LEN]);
                    break;
                }
                Ok(_) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) => return Err(error),
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for Ethernet frame",
                ));
            }
        }

        Ok(())
    }
}
