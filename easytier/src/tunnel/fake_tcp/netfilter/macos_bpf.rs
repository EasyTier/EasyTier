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
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::tunnel::fake_tcp::stack;

const ETH_HDR_LEN: usize = 14;
const ETH_TYPE_OFFSET: u32 = 12;
const ETHERTYPE_IPV4: u32 = 0x0800;
const ETHERTYPE_IPV6: u32 = 0x86DD;
const IPPROTO_TCP_U32: u32 = 6;

const DLT_EN10MB: u32 = 1;
const DLT_NULL: u32 = 4;
const DLT_RAW: u32 = 12;
const DLT_LOOP: u32 = 108;

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

const BPF_GROUP: u8 = b'B';

const BIOCGBLEN_NUM: u8 = 102;
const BIOCSBLEN_NUM: u8 = 102;
const BIOCSETF_NUM: u8 = 103;
const BIOCFLUSH_NUM: u8 = 104;
const BIOCGDLT_NUM: u8 = 106;
const BIOCSETIF_NUM: u8 = 108;
const BIOCSRTIMEOUT_NUM: u8 = 109;
const BIOCIMMEDIATE_NUM: u8 = 112;
const BIOCSHDRCMPLT_NUM: u8 = 117;
const BIOCSSEESENT_NUM: u8 = 119;

const IOCPARM_MASK: u32 = 0x1fff;
const IOC_VOID: u32 = 0x2000_0000;
const IOC_OUT: u32 = 0x4000_0000;
const IOC_IN: u32 = 0x8000_0000;
const IOC_INOUT: u32 = IOC_IN | IOC_OUT;

#[derive(Clone, Copy)]
enum LinkType {
    En10Mb,
    Null,
    Raw,
    Loop,
    Utun,
}

impl LinkType {
    fn from_dlt(dlt: u32) -> Option<Self> {
        match dlt {
            DLT_EN10MB => Some(Self::En10Mb),
            DLT_NULL => Some(Self::Null),
            DLT_RAW => Some(Self::Raw),
            DLT_LOOP => Some(Self::Loop),
            _ => None,
        }
    }
}

fn looks_like_ip(packet: &[u8]) -> bool {
    matches!(packet.first().map(|b| b >> 4), Some(4 | 6))
}

fn maybe_unwrap_utun_payload(packet: &[u8]) -> Option<&[u8]> {
    if looks_like_ip(packet) {
        return Some(packet);
    }
    if packet.len() < 5 {
        return None;
    }
    let payload = &packet[4..];
    if !looks_like_ip(payload) {
        return None;
    }
    Some(payload)
}

fn ether_type_from_ip_packet(ip: &[u8]) -> Option<u16> {
    let v = *ip.first()?;
    match v >> 4 {
        4 => Some(0x0800),
        6 => Some(0x86DD),
        _ => None,
    }
}

fn wrap_ip_with_ethernet(ip: &[u8]) -> Option<Vec<u8>> {
    let ether_type = ether_type_from_ip_packet(ip)?;
    let mut out = vec![0u8; ETH_HDR_LEN + ip.len()];
    out[12..14].copy_from_slice(&ether_type.to_be_bytes());
    out[ETH_HDR_LEN..].copy_from_slice(ip);
    Some(out)
}

fn family_word_for_null(family: u32) -> u32 {
    u32::from_be_bytes(family.to_ne_bytes())
}

#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *mut BpfInsn,
}

fn read_u16_ne(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes([bytes[0], bytes[1]])
}

fn read_u32_ne(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn bpf_word_align_with(align: usize, x: usize) -> usize {
    (x + (align - 1)) & !(align - 1)
}

fn parse_bpf_record(buf: &[u8], align: usize) -> Option<(usize, std::ops::Range<usize>, u16, u32)> {
    let max_shift = std::cmp::min(align, buf.len());
    for shift in 0..max_shift {
        let rest = &buf[shift..];

        let try_ts8 = || -> Option<(usize, std::ops::Range<usize>, u16, u32)> {
            let base_hdr_len = 18usize;
            if rest.len() < base_hdr_len {
                return None;
            }
            let caplen = read_u32_ne(rest.get(8..12)?) as usize;
            let datalen = read_u32_ne(rest.get(12..16)?) as usize;
            let hdrlen = read_u16_ne(rest.get(16..18)?) as usize;
            if hdrlen < base_hdr_len || hdrlen > 512 {
                return None;
            }
            if caplen > datalen {
                return None;
            }
            let pkt_start = shift + hdrlen;
            let pkt_end = pkt_start.checked_add(caplen)?;
            if pkt_end > buf.len() {
                return None;
            }
            let advance = shift + bpf_word_align_with(align, hdrlen + caplen);
            Some((advance, pkt_start..pkt_end, hdrlen as u16, caplen as u32))
        };

        if let Some(v) = try_ts8() {
            return Some(v);
        }

        let try_ts16 = || -> Option<(usize, std::ops::Range<usize>, u16, u32)> {
            let base_hdr_len = 26usize;
            if rest.len() < base_hdr_len {
                return None;
            }
            let caplen = read_u32_ne(rest.get(16..20)?) as usize;
            let datalen = read_u32_ne(rest.get(20..24)?) as usize;
            let hdrlen = read_u16_ne(rest.get(24..26)?) as usize;
            if hdrlen < base_hdr_len || hdrlen > 512 {
                return None;
            }
            if caplen > datalen {
                return None;
            }
            let pkt_start = shift + hdrlen;
            let pkt_end = pkt_start.checked_add(caplen)?;
            if pkt_end > buf.len() {
                return None;
            }
            let advance = shift + bpf_word_align_with(align, hdrlen + caplen);
            Some((advance, pkt_start..pkt_end, hdrlen as u16, caplen as u32))
        };

        if let Some(v) = try_ts16() {
            return Some(v);
        }
    }
    None
}

fn ioc(inout: u32, group: u8, num: u8, len: u32) -> libc::c_ulong {
    (inout | ((len & IOCPARM_MASK) << 16) | ((group as u32) << 8) | (num as u32)) as libc::c_ulong
}

fn io(group: u8, num: u8) -> libc::c_ulong {
    ioc(IOC_VOID, group, num, 0)
}

fn ior<T>(group: u8, num: u8) -> libc::c_ulong {
    ioc(IOC_OUT, group, num, mem::size_of::<T>() as u32)
}

fn iow<T>(group: u8, num: u8) -> libc::c_ulong {
    ioc(IOC_IN, group, num, mem::size_of::<T>() as u32)
}

fn iowr<T>(group: u8, num: u8) -> libc::c_ulong {
    ioc(IOC_INOUT, group, num, mem::size_of::<T>() as u32)
}

unsafe fn ioctl_ptr<T>(fd: libc::c_int, req: libc::c_ulong, arg: *mut T) -> io::Result<()> {
    let ret = libc::ioctl(fd, req, arg);
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

unsafe fn ioctl_void(fd: libc::c_int, req: libc::c_ulong) -> io::Result<()> {
    let ret = libc::ioctl(fd, req);
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn stmt(code: u16, k: u32) -> BpfInsn {
    BpfInsn {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jeq(k: u32, jt: u8, jf: u8) -> BpfInsn {
    BpfInsn {
        code: BPF_JMP | BPF_JEQ | BPF_K,
        jt,
        jf,
        k,
    }
}

fn ja(k: u32) -> BpfInsn {
    BpfInsn {
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
    insns: Vec<BpfInsn>,
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

    fn push(&mut self, insn: BpfInsn) {
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

    fn finish(mut self) -> io::Result<Vec<BpfInsn>> {
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

fn build_tcp_filter_ethernet(
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Vec<BpfInsn>> {
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

fn build_tcp_filter_ip(
    base: u32,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
    family_word: Option<u32>,
) -> io::Result<Vec<BpfInsn>> {
    if let Some(src) = src_addr {
        if src.is_ipv4() != dst_addr.is_ipv4() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "src/dst addr family mismatch",
            ));
        }
    }

    let mut b = BpfBuilder::new();
    let l_accept = b.new_label();
    let l_reject = b.new_label();

    if let Some(family_word) = family_word {
        let l_family_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_W | BPF_ABS, 0));
        b.push_jeq(family_word, l_family_ok, l_reject);
        b.set_label(l_family_ok);
    }

    if dst_addr.is_ipv4() {
        let l_v4_proto_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, base + 9));
        b.push_jeq(IPPROTO_TCP_U32, l_v4_proto_ok, l_reject);

        b.set_label(l_v4_proto_ok);
        let dst_ip = match dst_addr.ip() {
            IpAddr::V4(ip) => u32::from(ip),
            _ => unreachable!(),
        };
        let l_v4_dstip_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_W | BPF_ABS, base + 16));
        b.push_jeq(dst_ip, l_v4_dstip_ok, l_reject);

        b.set_label(l_v4_dstip_ok);
        if let Some(src) = src_addr {
            let src_ip = match src.ip() {
                IpAddr::V4(ip) => u32::from(ip),
                _ => unreachable!(),
            };
            let l_v4_srcip_ok = b.new_label();
            b.push(stmt(BPF_LD | BPF_W | BPF_ABS, base + 12));
            b.push_jeq(src_ip, l_v4_srcip_ok, l_reject);
            b.set_label(l_v4_srcip_ok);
        }

        b.push(stmt(BPF_LDX | BPF_B | BPF_MSH, base));

        let l_v4_dstport_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_H | BPF_IND, base + 2));
        b.push_jeq(dst_addr.port() as u32, l_v4_dstport_ok, l_reject);

        b.set_label(l_v4_dstport_ok);
        if let Some(src) = src_addr {
            b.push(stmt(BPF_LD | BPF_H | BPF_IND, base));
            b.push_jeq(src.port() as u32, l_accept, l_reject);
        } else {
            b.push_ja(l_accept);
        }
    } else {
        let l_v6_proto_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_B | BPF_ABS, base + 6));
        b.push_jeq(IPPROTO_TCP_U32, l_v6_proto_ok, l_reject);

        b.set_label(l_v6_proto_ok);
        let dst_ip = match dst_addr.ip() {
            IpAddr::V6(ip) => ip.octets(),
            _ => unreachable!(),
        };
        for (i, chunk) in dst_ip.chunks_exact(4).enumerate() {
            let off = base + 24 + (i * 4) as u32;
            let v = u32::from_be_bytes(chunk.try_into().unwrap());
            let l_v6_dstip_word_ok = b.new_label();
            b.push(stmt(BPF_LD | BPF_W | BPF_ABS, off));
            b.push_jeq(v, l_v6_dstip_word_ok, l_reject);
            b.set_label(l_v6_dstip_word_ok);
        }

        if let Some(src) = src_addr {
            let src_ip = match src.ip() {
                IpAddr::V6(ip) => ip.octets(),
                _ => unreachable!(),
            };
            for (i, chunk) in src_ip.chunks_exact(4).enumerate() {
                let off = base + 8 + (i * 4) as u32;
                let v = u32::from_be_bytes(chunk.try_into().unwrap());
                let l_v6_srcip_word_ok = b.new_label();
                b.push(stmt(BPF_LD | BPF_W | BPF_ABS, off));
                b.push_jeq(v, l_v6_srcip_word_ok, l_reject);
                b.set_label(l_v6_srcip_word_ok);
            }
        }

        let l_v6_dstport_ok = b.new_label();
        b.push(stmt(BPF_LD | BPF_H | BPF_ABS, base + 40 + 2));
        b.push_jeq(dst_addr.port() as u32, l_v6_dstport_ok, l_reject);

        b.set_label(l_v6_dstport_ok);
        if let Some(src) = src_addr {
            b.push(stmt(BPF_LD | BPF_H | BPF_ABS, base + 40));
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

fn build_tcp_filter_utun(
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Vec<BpfInsn>> {
    let raw = build_tcp_filter_ip(0, src_addr, dst_addr, None)?;

    let family = if dst_addr.is_ipv4() {
        libc::AF_INET as u32
    } else {
        libc::AF_INET6 as u32
    };
    let family_hdr =
        build_tcp_filter_ip(4, src_addr, dst_addr, Some(family_word_for_null(family)))?;

    if raw.is_empty() {
        return Ok(family_hdr);
    }

    let mut combined = raw;
    if let Some(last) = combined.last_mut() {
        if last.code == (BPF_RET | BPF_K) && last.k == 0 {
            *last = ja(0);
        } else {
            combined.push(ja(0));
        }
    }
    combined.extend(family_hdr);
    Ok(combined)
}

fn build_tcp_filter(
    link_type: LinkType,
    src_addr: Option<SocketAddr>,
    dst_addr: SocketAddr,
) -> io::Result<Vec<BpfInsn>> {
    match link_type {
        LinkType::En10Mb => build_tcp_filter_ethernet(src_addr, dst_addr),
        LinkType::Raw => build_tcp_filter_ip(0, src_addr, dst_addr, None),
        LinkType::Null => {
            let family = if dst_addr.is_ipv4() {
                libc::AF_INET as u32
            } else {
                libc::AF_INET6 as u32
            };
            build_tcp_filter_ip(4, src_addr, dst_addr, Some(family_word_for_null(family)))
        }
        LinkType::Loop => {
            let family = if dst_addr.is_ipv4() {
                libc::AF_INET as u32
            } else {
                libc::AF_INET6 as u32
            };
            build_tcp_filter_ip(4, src_addr, dst_addr, Some(family))
        }
        LinkType::Utun => build_tcp_filter_utun(src_addr, dst_addr),
    }
}

fn open_bpf_device() -> io::Result<OwnedFd> {
    let mut last_err: Option<io::Error> = None;
    for i in 0..256 {
        let path = format!("/dev/bpf{}", i);
        let c_path = CString::new(path.as_str())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path"))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            debug!(path, "opened bpf device");
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EBUSY) {
            last_err = Some(err);
            continue;
        }
        last_err = Some(err);
    }
    Err(last_err
        .unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no available /dev/bpf device")))
}

fn set_ifreq_name(ifr: &mut libc::ifreq, interface_name: &str) -> io::Result<()> {
    let bytes = interface_name.as_bytes();
    let ifnamsiz = libc::IFNAMSIZ as usize;
    if bytes.len() >= ifnamsiz {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "interface name too long",
        ));
    }
    for i in 0..ifnamsiz {
        ifr.ifr_name[i] = 0;
    }
    for (i, &b) in bytes.iter().enumerate() {
        ifr.ifr_name[i] = b as libc::c_char;
    }
    Ok(())
}

pub struct MacosBpfTun {
    fd: OwnedFd,
    link_type: LinkType,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    recv_queue: Mutex<tokio::sync::mpsc::Receiver<Vec<u8>>>,
}

impl MacosBpfTun {
    pub fn new(
        interface_name: &str,
        src_addr: Option<SocketAddr>,
        dst_addr: SocketAddr,
    ) -> io::Result<Self> {
        let fd = open_bpf_device()?;
        let raw_fd = fd.as_raw_fd();

        let mut buf_len: libc::c_uint = 0;
        unsafe {
            ioctl_ptr(
                raw_fd,
                ior::<libc::c_uint>(BPF_GROUP, BIOCGBLEN_NUM),
                &mut buf_len,
            )
        }?;
        if buf_len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bpf buffer length is zero",
            ));
        }

        let mut desired_buf_len: libc::c_uint = buf_len;
        let _ = unsafe {
            ioctl_ptr(
                raw_fd,
                iowr::<libc::c_uint>(BPF_GROUP, BIOCSBLEN_NUM),
                &mut desired_buf_len,
            )
        };

        let mut immediate: libc::c_uint = 1;
        unsafe {
            ioctl_ptr(
                raw_fd,
                iow::<libc::c_uint>(BPF_GROUP, BIOCIMMEDIATE_NUM),
                &mut immediate,
            )
        }?;

        let mut seesent: libc::c_uint = 0;
        unsafe {
            ioctl_ptr(
                raw_fd,
                iow::<libc::c_uint>(BPF_GROUP, BIOCSSEESENT_NUM),
                &mut seesent,
            )
        }?;

        let mut hdr_complete: libc::c_uint = 1;
        match unsafe {
            ioctl_ptr(
                raw_fd,
                iow::<libc::c_uint>(BPF_GROUP, BIOCSHDRCMPLT_NUM),
                &mut hdr_complete,
            )
        } {
            Ok(()) => {}
            Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {}
            Err(e) => return Err(e),
        }

        let timeout = libc::timeval {
            tv_sec: 0,
            tv_usec: 200_000,
        };
        let mut timeout_mut = timeout;
        unsafe {
            ioctl_ptr(
                raw_fd,
                iow::<libc::timeval>(BPF_GROUP, BIOCSRTIMEOUT_NUM),
                &mut timeout_mut,
            )
        }?;

        unsafe { ioctl_void(raw_fd, io(BPF_GROUP, BIOCFLUSH_NUM)) }?;

        let mut ifr: libc::ifreq = unsafe { mem::zeroed() };
        set_ifreq_name(&mut ifr, interface_name)?;
        unsafe {
            ioctl_ptr(
                raw_fd,
                iow::<libc::ifreq>(BPF_GROUP, BIOCSETIF_NUM),
                &mut ifr,
            )
        }?;

        let mut dlt: libc::c_uint = 0;
        unsafe {
            ioctl_ptr(
                raw_fd,
                ior::<libc::c_uint>(BPF_GROUP, BIOCGDLT_NUM),
                &mut dlt,
            )
        }?;

        let link_type = if interface_name.starts_with("utun") {
            LinkType::Utun
        } else {
            LinkType::from_dlt(dlt as u32).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unsupported datalink type {}", dlt),
                )
            })?
        };

        let filter = build_tcp_filter(link_type, src_addr, dst_addr)?;

        let mut bpf_insns: Vec<BpfInsn> = filter;
        let mut prog = BpfProgram {
            bf_len: bpf_insns
                .len()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "bpf program too long"))?,
            bf_insns: bpf_insns.as_mut_ptr(),
        };
        unsafe {
            ioctl_ptr(
                raw_fd,
                iow::<BpfProgram>(BPF_GROUP, BIOCSETF_NUM),
                &mut prog,
            )
        }?;

        info!(
            interface_name,
            ?src_addr,
            ?dst_addr,
            dlt,
            link_type = match link_type {
                LinkType::En10Mb => "en10mb",
                LinkType::Null => "null",
                LinkType::Raw => "raw",
                LinkType::Loop => "loop",
                LinkType::Utun => "utun",
            },
            filter_len = bpf_insns.len(),
            buf_len,
            desired_buf_len,
            "MacosBpfTun created"
        );

        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = tokio::sync::mpsc::channel(1024);
        let stop_clone = stop.clone();
        let read_fd = raw_fd;
        let worker_link_type = link_type;
        let worker = std::thread::spawn(move || {
            let mut buf = vec![0u8; desired_buf_len as usize];
            let mut wrap_fail_logs_left: u8 = 5;
            let mut bad_record_logs_left: u8 = 8;
            let mut shifted_record_logs_left: u8 = 8;
            let align = mem::size_of::<libc::c_long>();
            while !stop_clone.load(AtomicOrdering::Relaxed) {
                let n = unsafe {
                    libc::read(read_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
                };
                if n < 0 {
                    let err = io::Error::last_os_error();
                    if matches!(
                        err.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    warn!(?err, "MacosBpfTun bpf read failed");
                    break;
                }
                if n == 0 {
                    continue;
                }
                let mut off = 0usize;
                let n = n as usize;
                while off < n {
                    let window = &buf[off..n];
                    let Some((advance, pkt_range, hdr_len, cap_len)) =
                        parse_bpf_record(window, align)
                    else {
                        if bad_record_logs_left > 0 {
                            bad_record_logs_left -= 1;
                            let preview_len = std::cmp::min(window.len(), 48);
                            let preview = &window[..preview_len];
                            warn!(off, read_len = n, preview = ?preview, "MacosBpfTun failed to parse bpf records");
                        }
                        break;
                    };

                    let pkt_start = off + pkt_range.start;
                    let pkt_end = off + pkt_range.end;
                    let shift = (pkt_range.start as usize).saturating_sub(hdr_len as usize);
                    if shift != 0 && shifted_record_logs_left > 0 {
                        shifted_record_logs_left -= 1;
                        warn!(
                            off,
                            record_start = off + shift,
                            shift,
                            hdr_len,
                            cap_len,
                            read_len = n,
                            "MacosBpfTun parsed bpf record with non-zero offset"
                        );
                    }

                    let packet = &buf[pkt_start..pkt_end];
                    let framed = match worker_link_type {
                        LinkType::En10Mb => Some(packet.to_vec()),
                        LinkType::Raw => wrap_ip_with_ethernet(packet),
                        LinkType::Null | LinkType::Loop => {
                            if packet.len() < 4 {
                                None
                            } else {
                                wrap_ip_with_ethernet(&packet[4..])
                            }
                        }
                        LinkType::Utun => {
                            maybe_unwrap_utun_payload(packet).and_then(wrap_ip_with_ethernet)
                        }
                    };
                    if let Some(framed) = framed {
                        if tx.blocking_send(framed).is_err() {
                            return;
                        }
                    } else if wrap_fail_logs_left > 0 {
                        wrap_fail_logs_left -= 1;
                        warn!(
                            link_type = match worker_link_type {
                                LinkType::En10Mb => "en10mb",
                                LinkType::Null => "null",
                                LinkType::Raw => "raw",
                                LinkType::Loop => "loop",
                                LinkType::Utun => "utun",
                            },
                            packet_len = packet.len(),
                            "MacosBpfTun failed to wrap packet"
                        );
                    }
                    if advance == 0 {
                        break;
                    }
                    off = off.saturating_add(advance);
                }
            }
        });

        Ok(Self {
            fd,
            link_type,
            stop,
            worker: Some(worker),
            recv_queue: Mutex::new(rx),
        })
    }
}

impl Drop for MacosBpfTun {
    fn drop(&mut self) {
        self.stop.store(true, AtomicOrdering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[async_trait::async_trait]
impl stack::Tun for MacosBpfTun {
    async fn recv(&self, packet: &mut BytesMut) -> Result<usize, std::io::Error> {
        let mut rx = self.recv_queue.lock().await;
        match rx.recv().await {
            Some(data) => {
                packet.extend_from_slice(&data);
                Ok(data.len())
            }
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "MacosBpfTun channel closed",
            )),
        }
    }

    #[tracing::instrument(ret, skip(self))]
    fn try_send(&self, packet: &Bytes) -> Result<(), std::io::Error> {
        if packet.len() < ETH_HDR_LEN {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "packet too short",
            ));
        }
        let payload = &packet[ETH_HDR_LEN..];
        let write_all = |ptr: *const u8, len: usize| -> Result<(), std::io::Error> {
            let ret = unsafe { libc::write(self.fd.as_raw_fd(), ptr as *const libc::c_void, len) };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        };

        let mut out_len = 0usize;
        let res = match self.link_type {
            LinkType::En10Mb => {
                out_len = packet.len();
                write_all(packet.as_ptr(), packet.len())
            }
            LinkType::Raw => {
                out_len = payload.len();
                write_all(payload.as_ptr(), payload.len())
            }
            LinkType::Null | LinkType::Loop | LinkType::Utun => {
                let family = match payload.first().map(|b| b >> 4) {
                    Some(4) => libc::AF_INET as u32,
                    Some(6) => libc::AF_INET6 as u32,
                    _ => {
                        warn!(
                            first_byte = payload.first().copied(),
                            payload_len = payload.len(),
                            "MacosBpfTun try_send invalid ip version"
                        );
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "invalid ip version",
                        ));
                    }
                };

                let primary_hdr = match self.link_type {
                    LinkType::Null => family.to_ne_bytes(),
                    LinkType::Loop => family.to_be_bytes(),
                    LinkType::Utun => family.to_ne_bytes(),
                    _ => unreachable!(),
                };

                let mut out = vec![0u8; 4 + payload.len()];
                out[..4].copy_from_slice(&primary_hdr);
                out[4..].copy_from_slice(payload);
                out_len = out.len();

                match write_all(out.as_ptr(), out.len()) {
                    Ok(()) => Ok(()),
                    Err(e)
                        if matches!(self.link_type, LinkType::Utun)
                            && e.raw_os_error() == Some(libc::EINVAL)
                            && primary_hdr != family.to_be_bytes() =>
                    {
                        let mut out = vec![0u8; 4 + payload.len()];
                        out[..4].copy_from_slice(&family.to_be_bytes());
                        out[4..].copy_from_slice(payload);
                        out_len = out.len();
                        write_all(out.as_ptr(), out.len())
                    }
                    Err(e) => Err(e),
                }
            }
        };

        if let Err(err) = res {
            warn!(
                ?err,
                link_type = match self.link_type {
                    LinkType::En10Mb => "en10mb",
                    LinkType::Null => "null",
                    LinkType::Raw => "raw",
                    LinkType::Loop => "loop",
                    LinkType::Utun => "utun",
                },
                in_len = packet.len(),
                out_len,
                "MacosBpfTun bpf write failed"
            );
            return Err(err);
        }

        Ok(())
    }

    fn driver_type(&self) -> &'static str {
        "macos_bpf"
    }
}
