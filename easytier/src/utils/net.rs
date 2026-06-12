use bytes::{Bytes, BytesMut};
use etherparse::{
    Ipv4Slice, Ipv6ExtensionSlice, Ipv6Slice, NetSlice, SlicedPacket, TcpSlice, TransportSlice,
};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Flags, MutableIpv4Packet};
use pnet::packet::ipv6::MutableIpv6Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};

pub const PI_LEN: usize = 4;

pub fn ipv6_skip_exthdr(packet: &[u8]) -> Option<(usize, IpNextHeaderProtocol)> {
    if packet.len() < 40 {
        return None;
    }

    let mut next_hdr = IpNextHeaderProtocol(packet[6]);
    let mut offset = 40;

    loop {
        let ext_len = match next_hdr {
            IpNextHeaderProtocols::Hopopt
            | IpNextHeaderProtocols::Ipv6Opts
            | IpNextHeaderProtocols::Ipv6Route => (*packet.get(offset + 1)? as usize + 1) * 8,
            IpNextHeaderProtocols::Ah => (*packet.get(offset + 1)? as usize + 2) * 4,
            IpNextHeaderProtocols::Ipv6Frag => {
                if packet.len() < offset + 8 {
                    return None;
                }
                if u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) & 0xFFF8 != 0 {
                    return Some((offset, next_hdr));
                }
                8
            }
            IpNextHeaderProtocol(59) => return None,
            _ => return Some((offset, next_hdr)),
        };

        if packet.len() < offset + ext_len {
            return None;
        }

        next_hdr = IpNextHeaderProtocol(packet[offset]);
        offset += ext_len;
    }
}

#[cfg(target_os = "linux")]
mod virtio {
    mod constants {
        use virtio_bindings::virtio_net::{
            VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6,
        };

        pub const VNET_HDR_LEN: usize = 10;
        pub const VNET_HDR_F_NEEDS_CSUM: u8 = VIRTIO_NET_HDR_F_NEEDS_CSUM as _;
        pub const VNET_HDR_GSO_TCPV4: u8 = VIRTIO_NET_HDR_GSO_TCPV4 as _;
        pub const VNET_HDR_GSO_TCPV6: u8 = VIRTIO_NET_HDR_GSO_TCPV6 as _;
    }

    pub use constants::*;

    use super::PI_LEN;

    pub fn write_checksum(frame: &mut [u8], has_pi: bool) {
        let len = frame.len();
        if len < VNET_HDR_LEN {
            return;
        }

        let flags = frame[0];

        if (flags & VNET_HDR_F_NEEDS_CSUM) != 0 {
            let hdr_len = VNET_HDR_LEN + if has_pi { PI_LEN } else { 0 };
            let csum_start = u16::from_ne_bytes([frame[6], frame[7]]) as usize;
            let csum_offset = u16::from_ne_bytes([frame[8], frame[9]]) as usize;

            if hdr_len + csum_start + csum_offset + 2 <= len {
                let data = &mut frame[hdr_len + csum_start..];
                let csum = internet_checksum::checksum(data);
                data[csum_offset..csum_offset + 2].copy_from_slice(&csum);
            }
        }
    }

    pub fn write_vnet_hdr(
        vnet_hdr: &mut [u8],
        len: usize,
        mtu: usize,
        gso_type: u8,
        hdr_len: usize,
        csum_start: usize,
    ) {
        vnet_hdr[0] = VNET_HDR_F_NEEDS_CSUM;
        vnet_hdr[6..8].copy_from_slice(&(csum_start as u16).to_ne_bytes());
        vnet_hdr[8..10].copy_from_slice(&16u16.to_ne_bytes());

        if len > mtu && hdr_len > 0 && len > hdr_len {
            vnet_hdr[1] = gso_type;
            vnet_hdr[2..4].copy_from_slice(&(hdr_len as u16).to_ne_bytes());
            let gso_size = (len - hdr_len).min(mtu.saturating_sub(hdr_len)) as u16;
            vnet_hdr[4..6].copy_from_slice(&gso_size.to_ne_bytes());
        } else {
            vnet_hdr[1] = 0;
            vnet_hdr[2..6].fill(0);
        }
    }
}

#[cfg(target_os = "linux")]
pub use virtio::*;

pub struct Segmenter {
    mtu: usize,
    vnet_hdr_len: usize,
    buf: Option<BytesMut>,
}

impl Segmenter {
    pub fn new(mtu: usize, vnet_hdr_len: usize) -> Segmenter {
        Segmenter {
            mtu,
            vnet_hdr_len,
            buf: (vnet_hdr_len == 0).then(|| BytesMut::with_capacity(1 << 20)),
        }
    }

    pub fn has_vnet_hdr(&self) -> bool {
        self.vnet_hdr_len > 0
    }

    pub fn segment(&mut self, hdr: &mut [u8], packet: &mut [u8]) -> Option<Vec<Bytes>> {
        match SlicedPacket::from_ip(packet) {
            Ok(SlicedPacket {
                net: Some(NetSlice::Ipv4(ip)),
                transport: Some(TransportSlice::Tcp(tcp)),
                ..
            }) => {
                let ip_hdr_len = ip.header().slice().len();
                let tcp_data_off = (tcp.data_offset() as usize) * 4;

                #[cfg(target_os = "linux")]
                if self.has_vnet_hdr() {
                    write_vnet_hdr(
                        &mut hdr[..VNET_HDR_LEN],
                        ip.header().total_len() as _,
                        self.mtu,
                        VNET_HDR_GSO_TCPV4,
                        ip_hdr_len + tcp_data_off,
                        ip_hdr_len,
                    );
                    return None;
                }

                self.segment_tcp4(hdr, &ip, ip_hdr_len, &tcp, tcp_data_off)
            }
            Ok(SlicedPacket {
                net: Some(NetSlice::Ipv6(ip)),
                transport: Some(TransportSlice::Tcp(tcp)),
                ..
            }) => {
                let ip_hdr_len = ip.header().slice().len() + ip.extensions().slice().len();
                let tcp_data_off = (tcp.data_offset() as usize) * 4;

                #[cfg(target_os = "linux")]
                if self.has_vnet_hdr() {
                    write_vnet_hdr(
                        &mut hdr[..VNET_HDR_LEN],
                        40 + ip.header().payload_length() as usize,
                        self.mtu,
                        VNET_HDR_GSO_TCPV6,
                        ip_hdr_len + tcp_data_off,
                        ip_hdr_len,
                    );
                    return None;
                }

                self.segment_tcp6(hdr, &ip, ip_hdr_len, &tcp, tcp_data_off)
            }
            _ => {
                hdr[..self.vnet_hdr_len].fill(0);
                None
            }
        }
    }
}

impl Segmenter {
    fn segment_tcp4(
        &mut self,
        header: &[u8],
        ip: &Ipv4Slice,
        ip_hdr_len: usize,
        tcp: &TcpSlice,
        tcp_data_off: usize,
    ) -> Option<Vec<Bytes>> {
        let len = tcp.payload().len();
        if len == 0 {
            return None;
        }

        let hdr_len = ip_hdr_len + tcp_data_off;

        let seg_len = self.mtu.saturating_sub(hdr_len);
        if seg_len == 0 {
            return None;
        }

        let n = len.div_ceil(seg_len);

        let mut pseudo_hdr = [0u8; 12];
        pseudo_hdr[0..4].copy_from_slice(&ip.header().source());
        pseudo_hdr[4..8].copy_from_slice(&ip.header().destination());
        pseudo_hdr[8] = 0;
        pseudo_hdr[9] = 6;

        let seq = tcp.sequence_number();
        let urg_ptr = tcp.urgent_pointer();

        let flags = tcp.slice()[13];
        let cwr = flags & TcpFlags::CWR;
        let urg = flags & TcpFlags::URG;
        let psh = flags & TcpFlags::PSH;
        let fin = flags & TcpFlags::FIN;
        let flags = flags & !(TcpFlags::CWR | TcpFlags::URG | TcpFlags::PSH | TcpFlags::FIN);

        let buf = self.buf.as_mut().unwrap();
        if buf.capacity() < n * (header.len() + hdr_len) + len {
            buf.reserve(1 << 20);
        }
        let mut offset = 0;
        let mut frames = Vec::with_capacity(n);

        for idx in 0..n as u16 {
            let last = idx as usize == n - 1;
            let seg_len = if last { len - offset } else { seg_len };

            buf.extend_from_slice(header);
            buf.extend_from_slice(ip.header().slice());
            buf.extend_from_slice(tcp.header_slice());
            buf.extend_from_slice(&tcp.payload()[offset..offset + seg_len]);

            let mut buf = buf.split();

            {
                let buf = &mut buf[header.len()..];
                let mut ip = MutableIpv4Packet::new(buf).unwrap();
                ip.set_total_length((hdr_len + seg_len) as u16);
                if ip.get_flags() != Ipv4Flags::DontFragment {
                    ip.set_identification(ip.get_identification().wrapping_add(idx));
                }
                ip.set_checksum(0);
                let csum = internet_checksum::checksum(&buf[..ip_hdr_len]);
                buf[10..12].copy_from_slice(&csum);

                pseudo_hdr[10..12]
                    .copy_from_slice(&((tcp_data_off + seg_len) as u16).to_be_bytes());

                let buf = &mut buf[ip_hdr_len..];
                let mut tcp = MutableTcpPacket::new(buf).unwrap();
                tcp.set_sequence(seq.wrapping_add(offset as u32));

                let mut flags = flags;
                if idx == 0 {
                    flags |= cwr;
                }
                if last {
                    flags |= psh | fin;
                }
                let offset = offset as u16;
                if urg != 0 && offset <= urg_ptr {
                    flags |= urg;
                    tcp.set_urgent_ptr(urg_ptr - offset);
                } else {
                    tcp.set_urgent_ptr(0);
                }
                tcp.set_flags(flags);

                tcp.set_checksum(0);
                let csum = {
                    let mut csum = internet_checksum::Checksum::new();
                    csum.add_bytes(&pseudo_hdr);
                    csum.add_bytes(buf);
                    csum.checksum()
                };
                buf[16..18].copy_from_slice(&csum);
            }

            frames.push(buf.freeze());

            offset += seg_len;
        }

        Some(frames)
    }

    fn segment_tcp6(
        &mut self,
        header: &[u8],
        ip: &Ipv6Slice,
        ip_hdr_len: usize,
        tcp: &TcpSlice,
        tcp_data_off: usize,
    ) -> Option<Vec<Bytes>> {
        let len = tcp.payload().len();
        if len == 0 {
            return None;
        }

        let hdr_len = ip_hdr_len + tcp_data_off;

        let seg_len = self.mtu.saturating_sub(hdr_len);
        if seg_len == 0 {
            return None;
        }

        let n = len.div_ceil(seg_len);

        let mut dst = ip.header().destination();
        for ext in ip.extensions().clone().into_iter() {
            if let Ipv6ExtensionSlice::Routing(routing) = ext {
                let routing = routing.slice();
                let len = routing.len();
                if len >= 24 && routing[3] > 0 {
                    match routing[2] {
                        0 | 2 => dst.copy_from_slice(&routing[len - 16..len]),
                        4 => dst.copy_from_slice(&routing[8..24]),
                        _ => {}
                    }
                }
            }
        }

        let mut pseudo_hdr = [0u8; 40];
        pseudo_hdr[0..16].copy_from_slice(&ip.header().source());
        pseudo_hdr[16..32].copy_from_slice(&dst);
        pseudo_hdr[39] = 6;

        let seq = tcp.sequence_number();
        let urg_ptr = tcp.urgent_pointer();

        let flags = tcp.slice()[13];
        let cwr = flags & TcpFlags::CWR;
        let urg = flags & TcpFlags::URG;
        let psh = flags & TcpFlags::PSH;
        let fin = flags & TcpFlags::FIN;
        let flags = flags & !(TcpFlags::CWR | TcpFlags::URG | TcpFlags::PSH | TcpFlags::FIN);

        let buf = self.buf.as_mut().unwrap();
        if buf.capacity() < n * (header.len() + hdr_len) + len {
            buf.reserve(1 << 20);
        }
        let mut offset = 0;
        let mut frames = Vec::with_capacity(n);

        for idx in 0..n as u16 {
            let last = idx as usize == n - 1;
            let seg_len = if last { len - offset } else { seg_len };

            buf.extend_from_slice(header);
            buf.extend_from_slice(ip.header().slice());
            buf.extend_from_slice(tcp.header_slice());
            buf.extend_from_slice(&tcp.payload()[offset..offset + seg_len]);

            let mut buf = buf.split();

            {
                let buf = &mut buf[header.len()..];
                let mut ipv6 = MutableIpv6Packet::new(buf).unwrap();
                ipv6.set_payload_length((hdr_len - 40 + seg_len) as u16);

                pseudo_hdr[32..36]
                    .copy_from_slice(&((tcp_data_off + seg_len) as u32).to_be_bytes());

                let buf = &mut buf[ip_hdr_len..];
                let mut tcp_mut = MutableTcpPacket::new(buf).unwrap();
                tcp_mut.set_sequence(seq.wrapping_add(offset as u32));

                let mut flags = flags;
                if idx == 0 {
                    flags |= cwr;
                }
                if last {
                    flags |= psh | fin;
                }
                let offset = offset as u16;
                if urg != 0 && offset <= urg_ptr {
                    flags |= urg;
                    tcp_mut.set_urgent_ptr(urg_ptr - offset);
                } else {
                    tcp_mut.set_urgent_ptr(0);
                }
                tcp_mut.set_flags(flags);

                tcp_mut.set_checksum(0);
                let csum = {
                    let mut csum = internet_checksum::Checksum::new();
                    csum.add_bytes(&pseudo_hdr);
                    csum.add_bytes(buf);
                    csum.checksum()
                };
                buf[16..18].copy_from_slice(&csum);
            }

            frames.push(buf.freeze());

            offset += seg_len;
        }

        Some(frames)
    }
}
