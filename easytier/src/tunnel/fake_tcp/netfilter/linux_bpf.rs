use bytes::Bytes;
use bytes::BytesMut;
use nix::libc;
use std::ffi::CString;
use std::fs;
use std::io;
use std::mem;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::tunnel::fake_tcp::stack;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_OFFSET: u32 = 12;
const ETHERTYPE_IPV4: u32 = 0x0800;
const ETHERTYPE_IPV6: u32 = 0x86DD;
const IPPROTO_TCP_U32: u32 = 6;
const ARPHRD_PPP: i32 = 512;

const BPF_LD: u16 = 0x00;
const BPF_LDX: u16 = 0x01;
const BPF_ALU: u16 = 0x04;
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

const BPF_AND: u16 = 0x50;
const BPF_K: u16 = 0x00;

const SOL_PACKET: i32 = 263;
const PACKET_STATISTICS: i32 = 6;

const DEFAULT_RCVBUF_BYTES: i32 = 32 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinkMode {
    EthernetRaw,
    RawIp,
}

impl LinkMode {
    fn from_arphrd(arphrd: i32) -> Self {
        match arphrd {
            ARPHRD_PPP => Self::RawIp,
            _ => Self::EthernetRaw,
        }
    }
}

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

fn validate_addr_family(src_addr: Option<SocketAddr>, dst_addr: SocketAddr) -> io::Result<()> {
    if let Some(src) = src_addr
        && src.is_ipv4() != dst_addr.is_ipv4()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "src/dst addr family mismatch",
        ));
    }
    Ok(())
}

fn build_tcp_filter_ip(
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Vec<libc::sock_filter>> {
    validate_addr_family(src_addr, dst_addr)?;

    let mut b = BpfBuilder::new();
    let l_accept = b.new_label();
    let l_reject = b.new_label();

    if dst_addr.is_ipv4() {
        let l_v4_version_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, 0));
        b.push(stmt(BPF_ALU | BPF_AND | BPF_K, 0xF0));
        b.push_jeq(0x40, l_v4_version_ok, l_reject);

        b.set_label(l_v4_version_ok);
        let l_v4_proto_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, 9));
        b.push_jeq(IPPROTO_TCP_U32, l_v4_proto_ok, l_reject);

        b.set_label(l_v4_proto_ok);
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
        let l_v6_version_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, 0));
        b.push(stmt(BPF_ALU | BPF_AND | BPF_K, 0xF0));
        b.push_jeq(0x60, l_v6_version_ok, l_reject);

        b.set_label(l_v6_version_ok);
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
        b.push(stmt(BPF_LD | BPF_H | BPF_ABS, 40 + 2));
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

fn build_tcp_filter_ethernet(
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Vec<libc::sock_filter>> {
    validate_addr_family(src_addr, dst_addr)?;

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

fn build_tcp_filter(
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
    link_mode: LinkMode,
) -> io::Result<Vec<libc::sock_filter>> {
    match link_mode {
        LinkMode::EthernetRaw => build_tcp_filter_ethernet(src_addr, dst_addr),
        LinkMode::RawIp => build_tcp_filter_ip(src_addr, dst_addr),
    }
}

fn detect_link_mode(interface_name: &str) -> io::Result<(i32, LinkMode)> {
    let path = format!("/sys/class/net/{interface_name}/type");
    let arphrd_text = fs::read_to_string(path)?;
    let arphrd = arphrd_text.trim().parse::<i32>().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid interface type: {e}"),
        )
    })?;
    Ok((arphrd, LinkMode::from_arphrd(arphrd)))
}

fn ether_type_from_ip_packet(ip: &[u8]) -> Option<u16> {
    match ip.first().map(|b| b >> 4) {
        Some(4) => Some(ETHERTYPE_IPV4 as u16),
        Some(6) => Some(ETHERTYPE_IPV6 as u16),
        _ => None,
    }
}

fn wrap_ip_with_ethernet(ip: &[u8]) -> io::Result<Vec<u8>> {
    let ether_type = ether_type_from_ip_packet(ip).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidData, "invalid raw IP packet version")
    })?;
    let mut out = vec![0u8; ETH_HDR_LEN + ip.len()];
    out[12..14].copy_from_slice(&ether_type.to_be_bytes());
    out[ETH_HDR_LEN..].copy_from_slice(ip);
    Ok(out)
}

fn normalize_rx_packet(link_mode: LinkMode, packet: &[u8]) -> io::Result<Vec<u8>> {
    match link_mode {
        LinkMode::EthernetRaw => Ok(packet.to_vec()),
        LinkMode::RawIp => wrap_ip_with_ethernet(packet),
    }
}

struct TxPacket<'a> {
    payload: &'a [u8],
    protocol: u16,
    halen: u8,
    addr: [u8; 8],
}

fn encode_tx_packet(link_mode: LinkMode, packet: &[u8]) -> io::Result<TxPacket<'_>> {
    match link_mode {
        LinkMode::EthernetRaw => {
            if packet.len() < 6 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet too short",
                ));
            }
            let mut addr = [0u8; 8];
            addr[..6].copy_from_slice(&packet[..6]);
            Ok(TxPacket {
                payload: packet,
                protocol: (libc::ETH_P_ALL as u16).to_be(),
                halen: 6,
                addr,
            })
        }
        LinkMode::RawIp => {
            if packet.len() < ETH_HDR_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "packet too short",
                ));
            }
            let payload = &packet[ETH_HDR_LEN..];
            let ether_type = ether_type_from_ip_packet(payload).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid raw IP packet version")
            })?;
            Ok(TxPacket {
                payload,
                protocol: ether_type.to_be(),
                halen: 0,
                addr: [0u8; 8],
            })
        }
    }
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
    link_mode: LinkMode,
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
        let (arphrd, link_mode) = detect_link_mode(interface_name)?;

        let proto: i32 = (libc::ETH_P_ALL as u16).to_be() as i32;
        let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, proto) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = Arc::new(unsafe { OwnedFd::from_raw_fd(fd) });

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = (libc::ETH_P_ALL as u16).to_be();
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

        let filter = build_tcp_filter(src_addr, dst_addr, link_mode)?;
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
        let worker_link_mode = link_mode;

        let worker = std::thread::spawn(move || {
            // Keep the packet socket alive until the detached worker actually exits.
            let _fd_guard = fd_guard;
            let mut buf = vec![0u8; 65536];
            let mut wrap_fail_logs_left = 5u32;
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
                let data = match normalize_rx_packet(worker_link_mode, &buf[..(n as usize)]) {
                    Ok(data) => data,
                    Err(err) => {
                        if wrap_fail_logs_left > 0 {
                            wrap_fail_logs_left -= 1;
                            tracing::warn!(
                                ?err,
                                interface_name = interface_name_for_worker,
                                link_mode = ?worker_link_mode,
                                packet_len = n,
                                "LinuxBpfTun failed to normalize packet"
                            );
                        }
                        continue;
                    }
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
            arphrd,
            link_mode = ?link_mode,
            desired_rcvbuf = DEFAULT_RCVBUF_BYTES,
            actual_rcvbuf,
            "LinuxBpfTun created with filter {:?}",
            filter
        );

        Ok(Self {
            fd,
            ifindex,
            link_mode,
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
        let tx_packet = encode_tx_packet(self.link_mode, packet)?;

        let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = tx_packet.protocol;
        addr.sll_ifindex = self.ifindex;
        addr.sll_halen = tx_packet.halen;
        addr.sll_addr.copy_from_slice(&tx_packet.addr);

        let ret = unsafe {
            libc::sendto(
                self.fd.as_ref().as_raw_fd(),
                tx_packet.payload.as_ptr() as *const libc::c_void,
                tx_packet.payload.len(),
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tokio::time::{Duration, timeout};

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

    fn test_frame(src_addr: SocketAddr, dst_addr: SocketAddr) -> Bytes {
        build_tcp_packet(
            MacAddr::new(0x02, 0, 0, 0, 0, 1),
            MacAddr::new(0x02, 0, 0, 0, 0, 2),
            src_addr,
            dst_addr,
            1,
            0,
            TcpFlags::SYN,
            Some(b"test"),
        )
    }

    #[test]
    fn link_mode_maps_ppp_to_raw_ip() {
        assert_eq!(LinkMode::from_arphrd(ARPHRD_PPP), LinkMode::RawIp);
        assert_eq!(LinkMode::from_arphrd(1), LinkMode::EthernetRaw);
    }

    #[test]
    fn raw_ip_recv_wraps_ipv4_and_ipv6_with_fake_ethernet() {
        let frame4 = test_frame(
            "192.0.2.1:12345".parse().unwrap(),
            "198.51.100.2:23456".parse().unwrap(),
        );
        let raw4 = &frame4[ETH_HDR_LEN..];
        let normalized4 = normalize_rx_packet(LinkMode::RawIp, raw4).unwrap();

        assert!(normalized4[..12].iter().all(|b| *b == 0));
        assert_eq!(&normalized4[12..14], &(ETHERTYPE_IPV4 as u16).to_be_bytes());
        assert_eq!(&normalized4[ETH_HDR_LEN..], raw4);

        let frame6 = test_frame(
            "[2001:db8::1]:12345".parse().unwrap(),
            "[2001:db8::2]:23456".parse().unwrap(),
        );
        let raw6 = &frame6[ETH_HDR_LEN..];
        let normalized6 = normalize_rx_packet(LinkMode::RawIp, raw6).unwrap();

        assert!(normalized6[..12].iter().all(|b| *b == 0));
        assert_eq!(&normalized6[12..14], &(ETHERTYPE_IPV6 as u16).to_be_bytes());
        assert_eq!(&normalized6[ETH_HDR_LEN..], raw6);
    }

    #[test]
    fn raw_ip_recv_rejects_empty_and_unknown_ip_version() {
        let err = normalize_rx_packet(LinkMode::RawIp, &[]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        let err = normalize_rx_packet(LinkMode::RawIp, &[0x70, 0, 0, 0]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn raw_ip_encode_tx_strips_fake_ethernet_header_and_sets_protocol() {
        let frame4 = test_frame(
            "192.0.2.1:12345".parse().unwrap(),
            "198.51.100.2:23456".parse().unwrap(),
        );
        let tx4 = encode_tx_packet(LinkMode::RawIp, &frame4).unwrap();

        assert_eq!(tx4.payload, &frame4[ETH_HDR_LEN..]);
        assert_eq!(tx4.protocol, (ETHERTYPE_IPV4 as u16).to_be());
        assert_eq!(tx4.halen, 0);
        assert_eq!(tx4.addr, [0u8; 8]);

        let frame6 = test_frame(
            "[2001:db8::1]:12345".parse().unwrap(),
            "[2001:db8::2]:23456".parse().unwrap(),
        );
        let tx6 = encode_tx_packet(LinkMode::RawIp, &frame6).unwrap();

        assert_eq!(tx6.payload, &frame6[ETH_HDR_LEN..]);
        assert_eq!(tx6.protocol, (ETHERTYPE_IPV6 as u16).to_be());
        assert_eq!(tx6.halen, 0);
        assert_eq!(tx6.addr, [0u8; 8]);
    }

    #[test]
    fn ethernet_raw_encode_tx_keeps_frame_and_mac_address() {
        let frame = test_frame(
            "192.0.2.1:12345".parse().unwrap(),
            "198.51.100.2:23456".parse().unwrap(),
        );
        let tx = encode_tx_packet(LinkMode::EthernetRaw, &frame).unwrap();

        assert_eq!(tx.payload, &frame[..]);
        assert_eq!(tx.protocol, (libc::ETH_P_ALL as u16).to_be());
        assert_eq!(tx.halen, 6);
        assert_eq!(&tx.addr[..6], &frame[..6]);
    }

    #[test]
    fn ethernet_raw_filter_keeps_ethertype_check() {
        let dst_addr = "198.51.100.2:23456".parse().unwrap();
        let filter = build_tcp_filter(None, dst_addr, LinkMode::EthernetRaw).unwrap();
        let load_ethertype = BPF_LD | BPF_H | BPF_ABS;

        assert!(
            filter
                .iter()
                .any(|insn| insn.code == load_ethertype && insn.k == ETH_TYPE_OFFSET)
        );
    }

    #[test]
    fn raw_ip_filter_reads_ip_header_without_ethernet_ethertype() {
        let dst_addr = "198.51.100.2:23456".parse().unwrap();
        let filter = build_tcp_filter(None, dst_addr, LinkMode::RawIp).unwrap();
        let load_ethertype = BPF_LD | BPF_H | BPF_ABS;
        let load_byte_abs = BPF_LD | BPF_B | BPF_ABS;

        assert!(
            !filter
                .iter()
                .any(|insn| insn.code == load_ethertype && insn.k == ETH_TYPE_OFFSET)
        );
        assert!(
            filter
                .iter()
                .any(|insn| insn.code == load_byte_abs && insn.k == 9)
        );
        assert!(
            !filter
                .iter()
                .any(|insn| insn.code == load_byte_abs && insn.k == (ETH_HDR_LEN + 9) as u32)
        );
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
