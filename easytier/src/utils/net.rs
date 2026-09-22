use bytes::{Bytes, BytesMut};
use etherparse::{
    Ipv4Slice, Ipv6ExtensionSlice, Ipv6Slice, NetSlice, SlicedPacket, TcpSlice, TransportSlice,
};

pub const PI_LEN: usize = 4;

#[allow(dead_code)]
mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
    pub const CWR: u8 = 0x80;
}

#[cfg(target_os = "linux")]
mod virtio {
    use super::PI_LEN;
    use virtio_bindings::virtio_net::{
        VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_TCPV4, VIRTIO_NET_HDR_GSO_TCPV6,
    };

    pub const VNET_HDR_LEN: usize = 10;
    pub const VNET_HDR_F_NEEDS_CSUM: u8 = VIRTIO_NET_HDR_F_NEEDS_CSUM as _;
    pub const VNET_HDR_GSO_TCPV4: u8 = VIRTIO_NET_HDR_GSO_TCPV4 as _;
    pub const VNET_HDR_GSO_TCPV6: u8 = VIRTIO_NET_HDR_GSO_TCPV6 as _;

    pub fn write_checksum(frame: &mut [u8], has_pi: bool) {
        let len = frame.len();
        if len < VNET_HDR_LEN {
            return;
        }

        let (flags, gso_type) = (frame[0], frame[1]);
        if (flags & VNET_HDR_F_NEEDS_CSUM) != 0 && gso_type == 0 {
            let hdr_len = VNET_HDR_LEN + if has_pi { PI_LEN } else { 0 };
            let csum_start = u16::from_ne_bytes([frame[6], frame[7]]) as usize;
            let csum_offset = u16::from_ne_bytes([frame[8], frame[9]]) as usize;

            if hdr_len + csum_start + csum_offset + 2 <= len {
                let data = &mut frame[hdr_len + csum_start..];
                let csum = match internet_checksum::checksum(data) {
                    [0, 0] => [0xff, 0xff],
                    csum => csum,
                };
                data[csum_offset..csum_offset + 2].copy_from_slice(&csum);
            }
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

#[cfg(target_os = "linux")]
impl Segmenter {
    fn write_vnet_hdr(
        vnet_hdr: &mut [u8],
        len: usize,
        mtu: usize,
        gso_type: u8,
        hdr_len: usize,
        csum_start: usize,
    ) {
        if len > mtu && mtu > hdr_len {
            vnet_hdr[0] = VNET_HDR_F_NEEDS_CSUM;
            vnet_hdr[1] = gso_type;
            vnet_hdr[2..4].copy_from_slice(&(hdr_len as u16).to_ne_bytes());
            let gso_size = (len - hdr_len).min(mtu - hdr_len) as u16;
            vnet_hdr[4..6].copy_from_slice(&gso_size.to_ne_bytes());
            vnet_hdr[6..8].copy_from_slice(&(csum_start as u16).to_ne_bytes());
            vnet_hdr[8..10].copy_from_slice(&16u16.to_ne_bytes());
        } else {
            vnet_hdr.fill(0);
        }
    }
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
                    Self::write_vnet_hdr(
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
                    Self::write_vnet_hdr(
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
                if let Some(vnet_hdr) = hdr.get_mut(..self.vnet_hdr_len) {
                    vnet_hdr.fill(0);
                }
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
        if n <= 1 {
            return None;
        }

        let mut pseudo_hdr = [0u8; 12];
        pseudo_hdr[0..4].copy_from_slice(&ip.header().source());
        pseudo_hdr[4..8].copy_from_slice(&ip.header().destination());
        pseudo_hdr[8] = 0;
        pseudo_hdr[9] = 6;

        let seq = tcp.sequence_number();
        let urg_ptr = tcp.urgent_pointer();

        let flags = tcp.slice()[13];
        let cwr = flags & tcp_flags::CWR;
        let urg = flags & tcp_flags::URG;
        let psh = flags & tcp_flags::PSH;
        let fin = flags & tcp_flags::FIN;
        let flags = flags & !(tcp_flags::CWR | tcp_flags::URG | tcp_flags::PSH | tcp_flags::FIN);

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
                let ip_buf = &mut buf[header.len()..];
                ip_buf[2..4].copy_from_slice(&((hdr_len + seg_len) as u16).to_be_bytes());
                let is_dont_fragment = (ip_buf[6] & 0x40) != 0;
                if !is_dont_fragment {
                    let ident = u16::from_be_bytes([ip_buf[4], ip_buf[5]]).wrapping_add(idx);
                    ip_buf[4..6].copy_from_slice(&ident.to_be_bytes());
                }
                ip_buf[10..12].copy_from_slice(&[0, 0]);
                let csum = internet_checksum::checksum(&ip_buf[..ip_hdr_len]);
                ip_buf[10..12].copy_from_slice(&csum);

                pseudo_hdr[10..12]
                    .copy_from_slice(&((tcp_data_off + seg_len) as u16).to_be_bytes());

                let tcp_buf = &mut ip_buf[ip_hdr_len..];
                tcp_buf[4..8].copy_from_slice(&seq.wrapping_add(offset as u32).to_be_bytes());

                let mut flags = flags;
                if idx == 0 {
                    flags |= cwr;
                }
                if last {
                    flags |= psh | fin;
                }
                let offset_u16 = offset as u16;
                if urg != 0 && offset_u16 <= urg_ptr {
                    flags |= urg;
                    tcp_buf[18..20].copy_from_slice(&(urg_ptr - offset_u16).to_be_bytes());
                } else {
                    tcp_buf[18..20].copy_from_slice(&[0, 0]);
                }
                tcp_buf[13] = flags;

                tcp_buf[16..18].copy_from_slice(&[0, 0]);
                let csum = {
                    let mut csum = internet_checksum::Checksum::new();
                    csum.add_bytes(&pseudo_hdr);
                    csum.add_bytes(tcp_buf);
                    csum.checksum()
                };
                tcp_buf[16..18].copy_from_slice(&csum);
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
        if n <= 1 {
            return None;
        }

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
        let cwr = flags & tcp_flags::CWR;
        let urg = flags & tcp_flags::URG;
        let psh = flags & tcp_flags::PSH;
        let fin = flags & tcp_flags::FIN;
        let flags = flags & !(tcp_flags::CWR | tcp_flags::URG | tcp_flags::PSH | tcp_flags::FIN);

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
                let ip_buf = &mut buf[header.len()..];
                ip_buf[4..6].copy_from_slice(&((hdr_len - 40 + seg_len) as u16).to_be_bytes());

                pseudo_hdr[32..36]
                    .copy_from_slice(&((tcp_data_off + seg_len) as u32).to_be_bytes());

                let tcp_buf = &mut ip_buf[ip_hdr_len..];
                tcp_buf[4..8].copy_from_slice(&seq.wrapping_add(offset as u32).to_be_bytes());

                let mut flags = flags;
                if idx == 0 {
                    flags |= cwr;
                }
                if last {
                    flags |= psh | fin;
                }
                let offset_u16 = offset as u16;
                if urg != 0 && offset_u16 <= urg_ptr {
                    flags |= urg;
                    tcp_buf[18..20].copy_from_slice(&(urg_ptr - offset_u16).to_be_bytes());
                } else {
                    tcp_buf[18..20].copy_from_slice(&[0, 0]);
                }
                tcp_buf[13] = flags;

                tcp_buf[16..18].copy_from_slice(&[0, 0]);
                let csum = {
                    let mut csum = internet_checksum::Checksum::new();
                    csum.add_bytes(&pseudo_hdr);
                    csum.add_bytes(tcp_buf);
                    csum.checksum()
                };
                tcp_buf[16..18].copy_from_slice(&csum);
            }

            frames.push(buf.freeze());

            offset += seg_len;
        }

        Some(frames)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segmenter_disabled() {
        let mut segmenter = Segmenter::new(1500, 10);
        let mut hdr = vec![0u8; 10];
        let mut data = vec![0u8; 2000];
        assert!(segmenter.segment(&mut hdr, &mut data).is_none());
    }

    #[test]
    fn test_segmenter_tcp4() {
        let mut segmenter = Segmenter::new(1500, 0);

        // Build a synthetic IPv4 TCP packet with 3000 bytes payload
        let payload = vec![0xAB; 3000];
        let ip_hdr_len = 20;
        let tcp_hdr_len = 20;
        let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

        let mut packet = vec![0u8; total_len];
        // IPv4 Header
        packet[0] = 0x45; // Version 4, IHL 5 (20 bytes)
        packet[1] = 0;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[4..6].copy_from_slice(&1234u16.to_be_bytes()); // identification
        packet[6] = 0x40; // DF flag
        packet[7] = 0;
        packet[8] = 64; // TTL
        packet[9] = 6; // TCP
        packet[12..16].copy_from_slice(&[192, 168, 1, 1]); // src IP
        packet[16..20].copy_from_slice(&[192, 168, 1, 2]); // dst IP

        let ip_csum = internet_checksum::checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_csum);

        // TCP Header
        let tcp = &mut packet[20..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes()); // src port
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes()); // dst port
        tcp[4..8].copy_from_slice(&1000u32.to_be_bytes()); // seq
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes()); // ack
        tcp[12] = 0x50; // data offset 5 (20 bytes)
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK; // flags
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes()); // window size
        tcp[20..].copy_from_slice(&payload);

        let segments = segmenter.segment(&mut [], &mut packet);
        assert!(segments.is_some());
        let segments = segments.unwrap();
        assert_eq!(segments.len(), 3); // 3000 / (1500 - 40) = 3000 / 1460 = 2 full + 1 partial (80 bytes)

        // Verify segment 0
        assert_eq!(segments[0].len(), 1500);
        let parsed = SlicedPacket::from_ip(&segments[0]).unwrap();
        assert!(matches!(parsed.net, Some(NetSlice::Ipv4(_))));
        let TransportSlice::Tcp(tcp_slice) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp_slice.sequence_number(), 1000);
        assert_eq!(tcp_slice.payload().len(), 1460);
        assert_eq!(tcp_slice.slice()[13] & tcp_flags::PSH, 0); // PSH cleared on non-last segment

        // Verify segment 1
        assert_eq!(segments[1].len(), 1500);
        let parsed = SlicedPacket::from_ip(&segments[1]).unwrap();
        let TransportSlice::Tcp(tcp_slice) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp_slice.sequence_number(), 1000 + 1460);
        assert_eq!(tcp_slice.payload().len(), 1460);

        // Verify segment 2
        assert_eq!(segments[2].len(), 40 + 80);
        let parsed = SlicedPacket::from_ip(&segments[2]).unwrap();
        let TransportSlice::Tcp(tcp_slice) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp_slice.sequence_number(), 1000 + 2920);
        assert_eq!(tcp_slice.payload().len(), 80);
        assert_ne!(tcp_slice.slice()[13] & tcp_flags::PSH, 0); // PSH preserved on last segment
    }

    #[test]
    fn test_segmenter_tcp6() {
        let mut segmenter = Segmenter::new(1500, 0);

        // Build a synthetic IPv6 TCP packet with 3000 bytes payload
        let payload = vec![0xCD; 3000];
        let ip_hdr_len = 40;
        let tcp_hdr_len = 20;
        let total_len = ip_hdr_len + tcp_hdr_len + payload.len();

        let mut packet = vec![0u8; total_len];
        // IPv6 Header
        packet[0] = 0x60; // Version 6
        packet[4..6].copy_from_slice(&((tcp_hdr_len + payload.len()) as u16).to_be_bytes()); // payload length
        packet[6] = 6; // Next header: TCP
        packet[7] = 64; // Hop limit
        packet[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]); // src IP
        packet[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]); // dst IP

        // TCP Header
        let tcp = &mut packet[40..];
        tcp[0..2].copy_from_slice(&12345u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[4..8].copy_from_slice(&2000u32.to_be_bytes());
        tcp[8..12].copy_from_slice(&0u32.to_be_bytes());
        tcp[12] = 0x50; // data offset 5
        tcp[13] = tcp_flags::PSH | tcp_flags::ACK;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        tcp[20..].copy_from_slice(&payload);

        let segments = segmenter.segment(&mut [], &mut packet);
        assert!(segments.is_some());
        let segments = segments.unwrap();
        // 3000 / (1500 - 60) = 3000 / 1440 = 2 full (1440) + 1 partial (120)
        assert_eq!(segments.len(), 3);

        assert_eq!(segments[0].len(), 1500);
        let parsed = SlicedPacket::from_ip(&segments[0]).unwrap();
        assert!(matches!(parsed.net, Some(NetSlice::Ipv6(_))));
        let TransportSlice::Tcp(tcp_slice) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp_slice.sequence_number(), 2000);
        assert_eq!(tcp_slice.payload().len(), 1440);

        assert_eq!(segments[2].len(), 60 + 120);
        let parsed = SlicedPacket::from_ip(&segments[2]).unwrap();
        let TransportSlice::Tcp(tcp_slice) = parsed.transport.unwrap() else {
            panic!()
        };
        assert_eq!(tcp_slice.sequence_number(), 2000 + 2880);
        assert_eq!(tcp_slice.payload().len(), 120);
        assert_ne!(tcp_slice.slice()[13] & tcp_flags::PSH, 0);
    }
}
