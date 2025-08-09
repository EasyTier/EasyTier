use dashmap::DashMap;
use pnet::packet::ip::IpNextHeaderProtocol;
use pnet::packet::ipv4::{self, Ipv4Flags, Ipv4Packet, MutableIpv4Packet};
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::common::error::Error;

#[derive(Debug, Clone)]
pub(crate) struct IpFragment {
    id: u16,
    offset: u16,
    data: Vec<u8>,
}

impl<'a> From<&Ipv4Packet<'a>> for IpFragment {
    fn from(packet: &Ipv4Packet<'a>) -> Self {
        let id = packet.get_identification();
        let offset = packet.get_fragment_offset() * 8;
        let data = packet.payload().to_vec();
        IpFragment { id, offset, data }
    }
}

#[derive(Debug, Clone)]
struct IpPacket {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    total_length: Option<u16>,
    fragments: Vec<IpFragment>,
}

impl IpPacket {
    fn new(source: Ipv4Addr, destination: Ipv4Addr) -> Self {
        IpPacket {
            source,
            destination,
            total_length: None,
            fragments: Vec::new(),
        }
    }

    fn add_fragment(&mut self, fragment: IpFragment) {
        // make sure the fragment doesn't overlap with existing fragments
        for f in &self.fragments {
            if f.offset <= fragment.offset && fragment.offset < f.offset + f.data.len() as u16 {
                tracing::trace!("fragment overlap 1, f.offset = {}, fragment.offset = {}, f.data.len() = {}, fragment.data.len() = {}", f.offset, fragment.offset, f.data.len(), fragment.data.len());
                return;
            }
            if fragment.offset <= f.offset
                && f.offset < fragment.offset + fragment.data.len() as u16
            {
                tracing::trace!("fragment overlap 2, f.offset = {}, fragment.offset = {}, f.data.len() = {}, fragment.data.len() = {}", f.offset, fragment.offset, f.data.len(), fragment.data.len());
                return;
            }
        }
        self.fragments.push(fragment);
    }

    fn is_complete(&self) -> bool {
        if self.total_length.is_none() {
            return false;
        }
        let mut total_length = 0;
        for fragment in &self.fragments {
            total_length += fragment.data.len() as u16;
        }
        tracing::trace!(?total_length, ?self.total_length, "ip resembler checking is_complete");
        Some(total_length) == self.total_length
    }

    fn set_total_length(&mut self, total_length: u16) {
        self.total_length = Some(total_length);
    }

    fn assemble(&mut self) -> Option<Vec<u8>> {
        if !self.is_complete() {
            return None;
        }

        // sort fragments by offset
        self.fragments.sort_by_key(|f| f.offset);

        let mut packet = vec![0u8; self.total_length.unwrap() as usize];
        for fragment in &self.fragments {
            let start = fragment.offset as usize;
            let end = start + fragment.data.len();
            packet[start..end].copy_from_slice(&fragment.data);
        }

        Some(packet)
    }
}

#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct IpResemblerKey {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    id: u16,
}

#[derive(Debug)]
struct IpResemblerValue {
    packet: IpPacket,
    timestamp: Instant,
}

#[derive(Debug)]
pub(crate) struct IpReassembler {
    packets: DashMap<IpResemblerKey, IpResemblerValue>,
    timeout: Duration,
}

impl IpReassembler {
    pub fn new(timeout: Duration) -> Self {
        IpReassembler {
            packets: DashMap::new(),
            timeout,
        }
    }

    pub fn is_packet_fragmented(packet: &Ipv4Packet) -> bool {
        packet.get_fragment_offset() != 0 || packet.get_flags() & Ipv4Flags::MoreFragments != 0
    }

    pub fn is_last_fragment(packet: &Ipv4Packet) -> bool {
        packet.get_flags() & Ipv4Flags::MoreFragments == 0
    }

    pub fn add_fragment(
        &self,
        source: Ipv4Addr,
        destination: Ipv4Addr,
        packet: &Ipv4Packet,
    ) -> Option<Vec<u8>> {
        let id = packet.get_identification();
        let total_length = packet.get_total_length() - packet.get_header_length() as u16 * 4;
        if total_length != packet.payload().len() as u16 {
            tracing::trace!(
                ?packet,
                ?total_length,
                payload_len = ?packet.payload().len(),
                "unexpected total length",
            );
            return None;
        }

        let fragment: IpFragment = packet.into();
        let key = IpResemblerKey {
            source,
            destination,
            id,
        };

        tracing::trace!(
            ?key,
            "add fragment, offset = {}, total_length = {}",
            fragment.offset,
            total_length
        );

        let mut entry = self.packets.entry(key.clone()).or_insert_with(|| {
            let packet = IpPacket::new(source, destination);
            let timestamp = Instant::now();
            IpResemblerValue { packet, timestamp }
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
        self.packets.retain(|_, v| v.timestamp.elapsed() <= timeout);
    }
}

pub struct ComposeIpv4PacketArgs<'a> {
    pub buf: &'a mut [u8],
    pub src_v4: &'a Ipv4Addr,
    pub dst_v4: &'a Ipv4Addr,
    pub next_protocol: IpNextHeaderProtocol,
    pub payload_len: usize,
    pub payload_mtu: usize,
    pub ip_id: u16,
}

// ip payload should be in buf[20..]
pub fn compose_ipv4_packet<F>(args: ComposeIpv4PacketArgs, cb: F) -> Result<(), Error>
where
    F: Fn(&[u8]) -> Result<(), Error>,
{
    let total_pieces = args.payload_len.div_ceil(args.payload_mtu);
    let mut buf_offset = 0;
    let mut fragment_offset = 0;
    let mut cur_piece = 0;
    while fragment_offset < args.payload_len {
        let next_fragment_offset =
            std::cmp::min(fragment_offset + args.payload_mtu, args.payload_len);
        let fragment_len = next_fragment_offset - fragment_offset;
        let mut ipv4_packet =
            MutableIpv4Packet::new(&mut args.buf[buf_offset..buf_offset + fragment_len + 20])
                .unwrap();
        ipv4_packet.set_version(4);
        ipv4_packet.set_header_length(5);
        ipv4_packet.set_total_length((fragment_len + 20) as u16);
        ipv4_packet.set_identification(args.ip_id);
        if total_pieces > 1 {
            if cur_piece != total_pieces - 1 {
                ipv4_packet.set_flags(Ipv4Flags::MoreFragments);
            } else {
                ipv4_packet.set_flags(0);
            }
            assert_eq!(0, fragment_offset % 8);
            ipv4_packet.set_fragment_offset(fragment_offset as u16 / 8);
        } else {
            ipv4_packet.set_flags(Ipv4Flags::DontFragment);
            ipv4_packet.set_fragment_offset(0);
        }
        ipv4_packet.set_ecn(0);
        ipv4_packet.set_dscp(0);
        ipv4_packet.set_ttl(32);
        ipv4_packet.set_source(*args.src_v4);
        ipv4_packet.set_destination(*args.dst_v4);
        ipv4_packet.set_next_level_protocol(args.next_protocol);
        ipv4_packet.set_checksum(ipv4::checksum(&ipv4_packet.to_immutable()));

        tracing::trace!(?ipv4_packet, "udp nat packet response send");

        cb(ipv4_packet.packet())?;

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
    fn resembler() {
        let raw_packets = [
            // last packet
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x20, 0x01, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0x05, 0x06, 0x07, 0x04, 0x05, 0x06, 0x07,
            ],
            // 1st packet
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x00, 0x02, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x08, 0x09, 0x0a, 0x0b, 0x04, 0x05, 0x06, 0x07,
            ],
            // 2nd packet
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x1c, 0x46, 0x20, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ],
            // expired packet
            vec![
                0x45, 0x00, 0x00, 0x1c, 0x1c, 0x47, 0x20, 0x00, 0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8,
                0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            ],
        ];

        let source = "192.168.0.1".parse().unwrap();
        let destination = "192.168.0.2".parse().unwrap();
        let resembler = IpReassembler::new(Duration::from_secs(1));

        for (idx, raw_packet) in raw_packets.iter().enumerate() {
            if let Some(packet) = Ipv4Packet::new(raw_packet) {
                let ret = resembler.add_fragment(source, destination, &packet);
                if idx != 2 {
                    assert!(ret.is_none());
                } else {
                    assert!(ret.is_some());
                }
                println!(
                    "packet: {:?}, ret: {:?}, palyload_len: {}",
                    packet,
                    ret,
                    packet.payload().len()
                );
            }
        }

        resembler.remove_expired_packets();
        assert_eq!(1, resembler.packets.len());

        std::thread::sleep(Duration::from_secs(2));
        resembler.remove_expired_packets();
        assert_eq!(0, resembler.packets.len());
    }
}
