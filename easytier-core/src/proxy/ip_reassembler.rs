use std::{
    net::Ipv4Addr,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use smoltcp::wire::Ipv4Packet;
pub use smoltcp::wire::{IpProtocol, Ipv4Packet as SmolIpv4Packet};

#[derive(Debug, Hash, PartialEq, Eq, Clone)]
struct IpReassemblerKey {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    id: u16,
}

#[derive(Debug, Clone)]
struct IpFragment {
    offset: u16,
    data: Vec<u8>,
}

#[derive(Debug)]
struct IpPacket {
    total_length: Option<u16>,
    fragments: Vec<IpFragment>,
}

impl IpPacket {
    fn new() -> Self {
        Self {
            total_length: None,
            fragments: Vec::new(),
        }
    }

    fn add_fragment(&mut self, fragment: IpFragment) {
        for existing in &self.fragments {
            let existing_end = existing.offset + existing.data.len() as u16;
            let fragment_end = fragment.offset + fragment.data.len() as u16;
            if existing.offset <= fragment.offset && fragment.offset < existing_end {
                tracing::trace!(
                    existing_offset = existing.offset,
                    fragment_offset = fragment.offset,
                    existing_len = existing.data.len(),
                    fragment_len = fragment.data.len(),
                    "fragment overlap"
                );
                return;
            }
            if fragment.offset <= existing.offset && existing.offset < fragment_end {
                tracing::trace!(
                    existing_offset = existing.offset,
                    fragment_offset = fragment.offset,
                    existing_len = existing.data.len(),
                    fragment_len = fragment.data.len(),
                    "fragment overlap"
                );
                return;
            }
        }
        self.fragments.push(fragment);
    }

    fn set_total_length(&mut self, total_length: u16) {
        self.total_length = Some(total_length);
    }

    fn assemble(&mut self) -> Option<Vec<u8>> {
        let total_length = self.total_length?;
        self.fragments.sort_by_key(|fragment| fragment.offset);

        let mut offset = 0;
        let mut ret = Vec::with_capacity(total_length as usize);
        for fragment in &self.fragments {
            if fragment.offset != offset {
                return None;
            }
            ret.extend_from_slice(&fragment.data);
            offset += fragment.data.len() as u16;
        }

        (offset == total_length).then_some(ret)
    }
}

impl<T: AsRef<[u8]> + ?Sized> From<&Ipv4Packet<&T>> for IpFragment {
    fn from(packet: &Ipv4Packet<&T>) -> Self {
        Self {
            offset: packet.frag_offset(),
            data: packet.payload().to_vec(),
        }
    }
}

#[derive(Debug)]
struct IpReassemblerValue {
    packet: IpPacket,
    timestamp: Instant,
}

#[derive(Debug)]
pub struct IpReassembler {
    packets: DashMap<IpReassemblerKey, IpReassemblerValue>,
    timeout: Duration,
}

impl IpReassembler {
    pub fn new(timeout: Duration) -> Self {
        Self {
            packets: DashMap::new(),
            timeout,
        }
    }

    pub fn is_packet_fragmented<T: AsRef<[u8]>>(packet: &Ipv4Packet<T>) -> bool {
        packet.frag_offset() != 0 || packet.more_frags()
    }

    pub fn is_last_fragment<T: AsRef<[u8]>>(packet: &Ipv4Packet<T>) -> bool {
        !packet.more_frags()
    }

    pub fn add_fragment<T: AsRef<[u8]> + ?Sized>(
        &self,
        packet: &Ipv4Packet<&T>,
    ) -> Option<Vec<u8>> {
        let total_length = packet.total_len() - packet.header_len() as u16;
        if total_length != packet.payload().len() as u16 {
            tracing::trace!(
                ?total_length,
                payload_len = ?packet.payload().len(),
                "unexpected total length",
            );
            return None;
        }

        let key = IpReassemblerKey {
            source: packet.src_addr(),
            destination: packet.dst_addr(),
            id: packet.ident(),
        };
        let fragment: IpFragment = packet.into();

        tracing::trace!(?key, offset = fragment.offset, total_length, "add fragment");

        let mut entry = self.packets.entry(key.clone()).or_insert_with(|| {
            let packet = IpPacket::new();
            let timestamp = Instant::now();
            IpReassemblerValue { packet, timestamp }
        });
        let value_mut = entry.value_mut();

        if Self::is_last_fragment(packet) {
            value_mut
                .packet
                .set_total_length(total_length + fragment.offset);
        }

        value_mut.packet.add_fragment(fragment);
        if let Some(data) = value_mut.packet.assemble() {
            drop(entry);
            self.packets.remove(&key);
            Some(data)
        } else {
            value_mut.timestamp = Instant::now();
            None
        }
    }

    pub fn remove_expired_packets(&self) {
        let timeout = self.timeout;
        self.packets
            .retain(|_, value| value.timestamp.elapsed() <= timeout);
        self.packets.shrink_to_fit();
    }
}

pub struct ComposeIpv4PacketArgs<'a> {
    pub buf: &'a mut [u8],
    pub src_v4: &'a Ipv4Addr,
    pub dst_v4: &'a Ipv4Addr,
    pub next_protocol: IpProtocol,
    pub payload_len: usize,
    pub payload_mtu: usize,
    pub ip_id: u16,
}

pub fn compose_ipv4_packet<F>(args: ComposeIpv4PacketArgs, mut cb: F) -> anyhow::Result<()>
where
    F: FnMut(&[u8]) -> anyhow::Result<()>,
{
    let total_pieces = args.payload_len.div_ceil(args.payload_mtu);
    let mut buf_offset = 0;
    let mut fragment_offset = 0;
    let mut cur_piece = 0;
    while fragment_offset < args.payload_len {
        let next_fragment_offset =
            std::cmp::min(fragment_offset + args.payload_mtu, args.payload_len);
        let fragment_len = next_fragment_offset - fragment_offset;
        let packet_len = fragment_len + smoltcp::wire::IPV4_HEADER_LEN;
        let mut ipv4_packet =
            Ipv4Packet::new_checked(&mut args.buf[buf_offset..buf_offset + packet_len])
                .map_err(|_| anyhow::anyhow!("invalid ipv4 output buffer"))?;
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_len(smoltcp::wire::IPV4_HEADER_LEN as u8);
        ipv4_packet.set_total_len(packet_len as u16);
        ipv4_packet.set_ident(args.ip_id);
        ipv4_packet.clear_flags();
        if total_pieces > 1 {
            ipv4_packet.set_more_frags(cur_piece != total_pieces - 1);
            ipv4_packet.set_frag_offset(fragment_offset as u16);
        } else {
            ipv4_packet.set_dont_frag(true);
            ipv4_packet.set_frag_offset(0);
        }
        ipv4_packet.set_dscp(0);
        ipv4_packet.set_ecn(0);
        ipv4_packet.set_hop_limit(32);
        ipv4_packet.set_src_addr(*args.src_v4);
        ipv4_packet.set_dst_addr(*args.dst_v4);
        ipv4_packet.set_next_header(args.next_protocol);
        ipv4_packet.fill_checksum();

        tracing::trace!(?ipv4_packet, "proxy ipv4 packet composed");

        cb(ipv4_packet.as_ref())?;

        buf_offset += next_fragment_offset - fragment_offset;
        fragment_offset = next_fragment_offset;
        cur_piece += 1;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembler() {
        let raw_packets = [
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x20, 0x01, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0x05, 0x06, 0x07, 0x04, 0x05, 0x06, 0x07,
            ],
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x00, 0x02, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x08, 0x09, 0x0a, 0x0b, 0x04, 0x05, 0x06, 0x07,
            ],
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x20, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ],
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x1c, 0x47, 0x20, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ],
        ];

        let reassembler = IpReassembler::new(Duration::from_secs(1));

        for (idx, raw_packet) in raw_packets.iter().enumerate() {
            let packet = Ipv4Packet::new_checked(raw_packet.as_slice()).unwrap();
            let ret = reassembler.add_fragment(&packet);
            if idx != 2 {
                assert!(ret.is_none());
            } else {
                assert!(ret.is_some());
            }
        }

        reassembler.remove_expired_packets();
        assert_eq!(1, reassembler.packets.len());

        std::thread::sleep(Duration::from_secs(2));
        reassembler.remove_expired_packets();
        assert_eq!(0, reassembler.packets.len());
    }
}
