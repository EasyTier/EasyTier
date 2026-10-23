//! Local IP flow metadata for unfragmented TCP and UDP packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::ZCPacket;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct FlowKey {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub protocol: u8,
}

pub(crate) fn parse_flow_key(packet: &ZCPacket) -> Option<FlowKey> {
    let payload = packet.payload();
    let (src, dst, mut protocol, mut offset, end) = match payload.first()? >> 4 {
        4 => {
            let header = payload.get(..20)?;
            let offset = usize::from(header[0] & 0xf) * 4;
            let end = usize::from(u16::from_be_bytes([header[2], header[3]]));
            if offset < 20 || end < offset || end > payload.len() {
                return None;
            }
            let flags = u16::from_be_bytes([header[6], header[7]]);
            // Skip every actual fragment, including the first one with ports.
            if flags & 0x3fff != 0 {
                return None;
            }
            (
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&header[12..16]).ok()?)),
                IpAddr::V4(Ipv4Addr::from(<[u8; 4]>::try_from(&header[16..20]).ok()?)),
                header[9],
                offset,
                end,
            )
        }
        6 => {
            let header = payload.get(..40)?;
            let end = 40 + usize::from(u16::from_be_bytes([header[4], header[5]]));
            if end > payload.len() {
                return None;
            }
            (
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&header[8..24]).ok()?)),
                IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&header[24..40]).ok()?)),
                header[6],
                40,
                end,
            )
        }
        _ => return None,
    };

    if src.is_ipv6() {
        loop {
            let header = payload.get(offset..end)?;
            match protocol {
                0 | 43 | 60 | 51 => {
                    let len = usize::from(*header.get(1)?);
                    offset += if protocol == 51 {
                        (len + 2) * 4
                    } else {
                        (len + 1) * 8
                    };
                    if offset > end {
                        return None;
                    }
                    protocol = header[0];
                }
                44 => {
                    let header = header.get(..8)?;
                    let flags = u16::from_be_bytes([header[2], header[3]]);
                    // An atomic fragment has its complete transport header.
                    if flags & 0xfff9 != 0 {
                        return None;
                    }
                    protocol = header[0];
                    offset += 8;
                }
                _ => break,
            }
        }
    }

    if !matches!(protocol, 6 | 17) {
        return None;
    }
    let ports = payload.get(offset..end)?.get(..4)?;
    Some(FlowKey {
        src: SocketAddr::new(src, u16::from_be_bytes([ports[0], ports[1]])),
        dst: SocketAddr::new(dst, u16::from_be_bytes([ports[2], ports[3]])),
        protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{PacketType, ZCPacketType};

    fn ipv4(protocol: u8, flags: u16, id: u16) -> ZCPacket {
        let mut bytes = vec![0; 28];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&28u16.to_be_bytes());
        bytes[4..6].copy_from_slice(&id.to_be_bytes());
        bytes[6..8].copy_from_slice(&flags.to_be_bytes());
        bytes[9] = protocol;
        bytes[12..16].copy_from_slice(&[10, 0, 0, 1]);
        bytes[16..20].copy_from_slice(&[10, 0, 0, 2]);
        bytes[20..24].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        packet(bytes)
    }

    fn packet(bytes: Vec<u8>) -> ZCPacket {
        let mut packet = ZCPacket::new_with_payload(&bytes);
        packet.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        packet
    }

    fn ipv6(fragment: Option<u16>) -> ZCPacket {
        let mut bytes = vec![0; if fragment.is_some() { 64 } else { 56 }];
        bytes[0] = 0x60;
        let len = (bytes.len() - 40) as u16;
        bytes[4..6].copy_from_slice(&len.to_be_bytes());
        bytes[6] = 0; // Hop-by-hop options before the transport/fragment header.
        bytes[23] = 1;
        bytes[39] = 2;
        bytes[40] = if fragment.is_some() { 44 } else { 17 };
        let offset = if let Some(flags) = fragment {
            bytes[48] = 17;
            bytes[50..52].copy_from_slice(&flags.to_be_bytes());
            bytes[52..56].copy_from_slice(&99u32.to_be_bytes());
            56
        } else {
            48
        };
        bytes[offset..offset + 4].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
        packet(bytes)
    }

    #[test]
    fn identifies_ipv4_tcp_udp_and_ipv6_extension_headers() {
        let udp = parse_flow_key(&ipv4(17, 0, 0)).unwrap();
        assert_eq!(udp.src, "10.0.0.1:4660".parse().unwrap());
        assert_eq!(udp.dst, "10.0.0.2:22136".parse().unwrap());
        assert_ne!(Some(udp), parse_flow_key(&ipv4(6, 0, 0)));
        assert_eq!(Some(udp), parse_flow_key(&ipv4(17, 0x4000, 0)));
        let v6 = parse_flow_key(&ipv6(None)).unwrap();
        assert_eq!(v6.src, "[::1]:4660".parse().unwrap());
        assert_eq!(Some(v6), parse_flow_key(&ipv6(Some(0))));
    }

    #[test]
    fn first_middle_and_last_fragments_do_not_supply_a_flow_key() {
        for protocol in [6, 17, 1, 50] {
            for flags in [0x2000, 0x2001, 1] {
                assert!(parse_flow_key(&ipv4(protocol, flags, 99)).is_none());
            }
        }
        for protocol in [6, 17, 58, 50] {
            for flags in [1, 9, 8] {
                let mut fragment = ipv6(Some(flags));
                fragment.mut_payload()[48] = protocol;
                assert!(parse_flow_key(&fragment).is_none());
            }
        }
    }

    #[test]
    fn flow_key_survives_local_conversions_but_is_not_on_the_wire() {
        let mut original = ipv4(17, 0, 0);
        original.flow_key = parse_flow_key(&original);
        let key = original.flow_key;
        assert!(key.is_some());
        let mut converted = original.clone();
        for kind in [
            ZCPacketType::TCP,
            ZCPacketType::UDP,
            ZCPacketType::DummyTunnel,
            ZCPacketType::TCP,
        ] {
            converted = converted.convert_type(kind);
            assert_eq!(converted.flow_key, key);
            assert_eq!(converted.payload(), original.payload());
        }
        let received = ZCPacket::new_from_buf(converted.inner(), ZCPacketType::TCP);
        assert!(received.flow_key.is_none());
        let wrapped = ZCPacket::new_for_foreign_network(&"network".to_owned(), 2, &original);
        assert_eq!(wrapped.flow_key, key);
        let unwrapped = wrapped.foreign_network_packet();
        assert_eq!(unwrapped.flow_key, key);
        assert_eq!(unwrapped.payload(), original.payload());
    }

    #[test]
    fn truncated_headers_never_supply_a_flow_key() {
        for original in [ipv4(17, 0, 0), ipv6(None), ipv6(Some(0))] {
            for len in 0..original.payload().len() {
                assert!(parse_flow_key(&packet(original.payload()[..len].to_vec())).is_none());
            }
        }
    }

    #[cfg(all(feature = "zstd", feature = "aes-gcm"))]
    #[tokio::test]
    async fn compression_and_encryption_preserve_local_flow_metadata() {
        use crate::packet::{
            CompressorAlgo,
            compressor::{Compressor, DefaultCompressor},
        };
        let mut original = ipv4(17, 0, 0);
        let offset = original.payload_offset();
        original.mut_inner().resize(offset + 1024, 0);
        original.mut_payload()[2..4].copy_from_slice(&1024u16.to_be_bytes());
        original.fill_peer_manager_hdr(1, 2, PacketType::Data as u8);
        let mut packet = original.clone();
        packet.flow_key = parse_flow_key(&packet);
        let key = packet.flow_key;
        assert!(key.is_some());
        let compressor = DefaultCompressor::new();
        compressor
            .compress(&mut packet, CompressorAlgo::ZstdDefault)
            .await
            .unwrap();
        assert!(packet.peer_manager_header().unwrap().is_compressed());
        let encryptor = crate::tunnel::encrypt::create_encryptor("aes-gcm", [1; 16], [2; 32]);
        encryptor.encrypt(&mut packet).unwrap();
        assert_eq!(packet.flow_key, key);
        let mut packet = packet.convert_type(ZCPacketType::UDP);
        encryptor.decrypt(&mut packet).unwrap();
        compressor.decompress(&mut packet).await.unwrap();
        assert_eq!(packet.flow_key, key);
        assert_eq!(packet.payload(), original.payload());
    }
}
