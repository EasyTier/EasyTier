use bytes::Bytes;
use bytes::BytesMut;
use nix::libc;
use std::ffi::CString;
use std::io;
use std::mem;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::tunnel::fake_tcp::stack;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_OFFSET: u32 = 12;
const ETHERTYPE_IPV4: u32 = 0x0800;
const ETHERTYPE_IPV6: u32 = 0x86DD;
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

const BPF_K: u16 = 0x00;

const SOL_PACKET: i32 = 263;
const PACKET_STATISTICS: i32 = 6;

const DEFAULT_RCVBUF_BYTES: i32 = 32 * 1024 * 1024;

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

struct JeqPatch {
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
    jeq_patches: Vec<JeqPatch>,
    ja_patches: Vec<JaPatch>,
}

impl BpfBuilder {
    fn new() -> Self {
        Self {
            insns: Vec::new(),
            labels: Vec::new(),
            jeq_patches: Vec::new(),
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
        self.jeq_patches.push(JeqPatch { idx, t, f });
    }

    fn push_ja(&mut self, target: Label) {
        let idx = self.insns.len();
        self.insns.push(ja(0));
        self.ja_patches.push(JaPatch { idx, target });
    }

    fn finish(mut self) -> io::Result<Vec<libc::sock_filter>> {
        for patch in self.jeq_patches {
            let JeqPatch { idx, t, f } = patch;
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
    if let Some(src) = src_addr {
        if src.is_ipv4() != dst_addr.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "src/dst addr family mismatch",
            ));
        }
    }

    let mut b = BpfBuilder::new();
    let l_check_ipv6 = b.new_label();
    let l_ipv4 = b.new_label();
    let l_ipv6 = b.new_label();
    let l_accept = b.new_label();
    let l_reject = b.new_label();

    b.push(stmt(BPF_LD | BPF_H | BPF_ABS, ETH_TYPE_OFFSET));
    b.push_jeq(ETHERTYPE_IPV4, l_ipv4, l_check_ipv6);

    b.set_label(l_check_ipv6);
    b.push_jeq(ETHERTYPE_IPV6, l_ipv6, l_reject);

    if dst_addr.is_ipv4() {
        b.set_label(l_ipv4);
        let l_v4_proto_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, (ETH_HDR_LEN + 9) as u32));
        b.push_jeq(IPPROTO_TCP_U32, l_v4_proto_ok, l_reject);

        b.set_label(l_v4_proto_ok);
        let dst_ip = match dst_addr.ip() {
            IpAddr::V4(ip) => u32::from(ip),
            _ => unreachable!(),
        };
        let l_v4_dstip_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_W | BPF_ABS, (ETH_HDR_LEN + 16) as u32));
        b.push_jeq(dst_ip, l_v4_dstip_ok, l_reject);

        b.set_label(l_v4_dstip_ok);
        if let Some(src) = src_addr {
            let src_ip = match src.ip() {
                IpAddr::V4(ip) => u32::from(ip),
                _ => unreachable!(),
            };
            let l_v4_srcip_ok = b.new_label();
            b.push(stmt(BPF_LD | BPF_W | BPF_ABS, (ETH_HDR_LEN + 12) as u32));
            b.push_jeq(src_ip, l_v4_srcip_ok, l_reject);
            b.set_label(l_v4_srcip_ok);
        }

        b.push(stmt(BPF_LDX | BPF_B | BPF_MSH, ETH_HDR_LEN as u32));

        let l_v4_dstport_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_H | BPF_IND, (ETH_HDR_LEN + 2) as u32));
        b.push_jeq(dst_addr.port() as u32, l_v4_dstport_ok, l_reject);

        b.set_label(l_v4_dstport_ok);
        if let Some(src) = src_addr {
            b.push(stmt(BPF_LD | BPF_H | BPF_IND, ETH_HDR_LEN as u32));
            b.push_jeq(src.port() as u32, l_accept, l_reject);
        } else {
            b.push_ja(l_accept);
        }
    } else {
        b.set_label(l_ipv6);
        let l_v6_proto_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, (ETH_HDR_LEN + 6) as u32));
        b.push_jeq(IPPROTO_TCP_U32, l_v6_proto_ok, l_reject);

        b.set_label(l_v6_proto_ok);
        let dst_ip = match dst_addr.ip() {
            IpAddr::V6(ip) => ip.octets(),
            _ => unreachable!(),
        };
        for (i, chunk) in dst_ip.chunks_exact(4).enumerate() {
            let off = ETH_HDR_LEN + 24 + (i * 4);
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
                let off = ETH_HDR_LEN + 8 + (i * 4);
                let v = u32::from_be_bytes(chunk.try_into().unwrap());
                let l_v6_srcip_word_ok = b.new_label();
                b.push(stmt(BPF_LD | BPF_W | BPF_ABS, off as u32));
                b.push_jeq(v, l_v6_srcip_word_ok, l_reject);
                b.set_label(l_v6_srcip_word_ok);
            }
        }

        let l_v6_dstport_ok = b.new_label();
        b.push(stmt(
            BPF_LD | BPF_H | BPF_ABS,
            (ETH_HDR_LEN + 40 + 2) as u32,
        ));
        b.push_jeq(dst_addr.port() as u32, l_v6_dstport_ok, l_reject);

        b.set_label(l_v6_dstport_ok);
        if let Some(src) = src_addr {
            b.push(stmt(BPF_LD | BPF_H | BPF_ABS, (ETH_HDR_LEN + 40) as u32));
            b.push_jeq(src.port() as u32, l_accept, l_reject);
        } else {
            b.push_ja(l_accept);
        }
    }

    b.set_label(l_accept);
    b.push(stmt(BPF_RET | BPF_K, 0xFFFF));

    b.set_label(l_reject);
    if dst_addr.is_ipv4() {
        b.set_label(l_ipv6);
    } else {
        b.set_label(l_ipv4);
    }
    b.push(stmt(BPF_RET | BPF_K, 0));

    b.finish()
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
    fd: OwnedFd,
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

        let proto: i32 = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = ifindex;

        let bind_ret = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if bind_ret != 0 {
            return Err(io::Error::last_os_error());
        }

        let actual_rcvbuf = set_socket_rcvbuf(fd.as_raw_fd(), DEFAULT_RCVBUF_BYTES)?;

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
                fd.as_raw_fd(),
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
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const libc::c_void,
                mem::size_of::<libc::timeval>() as u32,
            )
        };

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let stop_clone = stop.clone();
        let read_fd = fd.as_raw_fd();
        let interface_name_for_worker = interface_name.to_string();

        let worker = std::thread::spawn(move || {
            let mut buf = vec![0u8; 65536];
            let mut stats_enabled = true;
            let mut total_packets: u64 = 0;
            let mut total_drops: u64 = 0;
            let mut total_bytes: u64 = 0;
            let mut dropped_by_queue_full: u64 = 0;
            let mut last_stats_log = Instant::now();
            while !stop_clone.load(AtomicOrdering::Relaxed) {
                let n = unsafe {
                    libc::recv(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0)
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
                let data = buf[..(n as usize)].to_vec();
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
        let _ = unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_RD) };
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
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
        if packet.len() < 6 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "packet too short",
            ));
        }

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = 6;
        addr.sll_addr[..6].copy_from_slice(&packet[..6]);

        let ret = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_ll>() as u32,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
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

    use crate::tunnel::fake_tcp::packet::build_tcp_packet;
    use crate::tunnel::fake_tcp::stack::Tun;
    use pnet::datalink;
    use pnet::packet::tcp::TcpFlags;
    use pnet::util::MacAddr;
    use rand::Rng;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::time::{timeout, Duration};

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn pick_interface_v4() -> Option<(String, Ipv4Addr, MacAddr)> {
        let interfaces = datalink::interfaces();
        for iface in interfaces {
            let Some(mac) = iface.mac else {
                continue;
            };
            if iface.is_loopback() {
                continue;
            }
            let ipv4 = iface.ips.iter().find_map(|n| match n.ip() {
                IpAddr::V4(ip) => Some(ip),
                IpAddr::V6(_) => None,
            })?;
            return Some((iface.name, ipv4, mac));
        }
        None
    }

    fn send_raw_frame(interface_name: &str, frame: &[u8]) -> io::Result<()> {
        if frame.len() < 6 {
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

        let proto: i32 = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
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
    async fn linux_bpf_tun_receives_matching_ipv4_frame() {
        if !is_root() {
            eprintln!("linux_bpf_tun_receives_matching_ipv4_frame: skipped (not root)");
            return;
        }

        let Some((ifname, dst_ip, mac)) = pick_interface_v4() else {
            eprintln!("linux_bpf_tun_receives_matching_ipv4_frame: skipped (no suitable iface)");
            return;
        };

        let dst_port: u16 = rand::thread_rng().gen_range(40000..60000);
        let dst_addr = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
        eprintln!(
            "linux_bpf_tun_receives_matching_ipv4_frame: ifname={ifname} dst_addr={dst_addr} mac={mac}"
        );

        let tun = LinuxBpfTun::new(&ifname, None, dst_addr).unwrap();

        let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 123, 0, 1)), 12345);
        eprintln!(
            "linux_bpf_tun_receives_matching_ipv4_frame: sending frame src_addr={src_addr} -> dst_addr={dst_addr}"
        );
        let frame = build_tcp_packet(
            mac,
            mac,
            src_addr,
            dst_addr,
            1,
            0,
            TcpFlags::SYN,
            Some(b"ping"),
        );

        send_raw_frame(&ifname, &frame).unwrap();

        let mut received = BytesMut::new();
        let n = timeout(Duration::from_secs(2), tun.recv(&mut received))
            .await
            .unwrap()
            .unwrap();
        eprintln!(
            "linux_bpf_tun_receives_matching_ipv4_frame: received {} bytes",
            n
        );
        assert_eq!(n, frame.len());
        assert_eq!(&received[..], &frame[..]);
    }

    #[tokio::test]
    async fn linux_bpf_tun_filters_out_non_matching_ipv4_frame() {
        if !is_root() {
            eprintln!("linux_bpf_tun_filters_out_non_matching_ipv4_frame: skipped (not root)");
            return;
        }

        let Some((ifname, dst_ip, mac)) = pick_interface_v4() else {
            eprintln!(
                "linux_bpf_tun_filters_out_non_matching_ipv4_frame: skipped (no suitable iface)"
            );
            return;
        };

        let dst_port: u16 = rand::thread_rng().gen_range(40000..60000);
        let dst_addr = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);
        eprintln!(
            "linux_bpf_tun_filters_out_non_matching_ipv4_frame: ifname={ifname} dst_addr={dst_addr} mac={mac}"
        );

        let tun = LinuxBpfTun::new(&ifname, None, dst_addr).unwrap();

        let src_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 123, 0, 2)), 23456);
        let non_matching_dst = SocketAddr::new(IpAddr::V4(dst_ip), dst_port.wrapping_add(1));
        eprintln!(
            "linux_bpf_tun_filters_out_non_matching_ipv4_frame: sending non-matching src_addr={src_addr} -> dst_addr={non_matching_dst}"
        );
        let non_matching = build_tcp_packet(
            mac,
            mac,
            src_addr,
            non_matching_dst,
            1,
            0,
            TcpFlags::SYN,
            Some(b"nope"),
        );
        send_raw_frame(&ifname, &non_matching).unwrap();

        let mut received = BytesMut::new();
        let non_matching_timeout = timeout(Duration::from_millis(400), tun.recv(&mut received))
            .await
            .is_err();
        eprintln!(
            "linux_bpf_tun_filters_out_non_matching_ipv4_frame: non-matching recv timeout={}",
            non_matching_timeout
        );
        assert!(non_matching_timeout);

        eprintln!(
            "linux_bpf_tun_filters_out_non_matching_ipv4_frame: sending matching src_addr={src_addr} -> dst_addr={dst_addr}"
        );
        let matching = build_tcp_packet(
            mac,
            mac,
            src_addr,
            dst_addr,
            2,
            0,
            TcpFlags::SYN,
            Some(b"ok"),
        );
        send_raw_frame(&ifname, &matching).unwrap();

        let mut received2 = BytesMut::new();
        let n = timeout(Duration::from_secs(2), tun.recv(&mut received2))
            .await
            .unwrap()
            .unwrap();
        eprintln!(
            "linux_bpf_tun_filters_out_non_matching_ipv4_frame: received {} bytes",
            n
        );
        assert_eq!(n, matching.len());
        assert_eq!(&received2[..], &matching[..]);
    }
}
