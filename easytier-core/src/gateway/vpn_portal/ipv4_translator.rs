use std::net::Ipv4Addr;

const IPV4_MIN_HEADER_LEN: usize = 20;
const TCP_MIN_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const ICMP_MIN_HEADER_LEN: usize = 8;

const IP_PROTOCOL_ICMP: u8 = 1;
const IP_PROTOCOL_TCP: u8 = 6;
const IP_PROTOCOL_UDP: u8 = 17;

const IPV4_CHECKSUM_OFFSET: usize = 10;
const IPV4_SOURCE_OFFSET: usize = 12;
const IPV4_DESTINATION_OFFSET: usize = 16;
const TCP_CHECKSUM_OFFSET: usize = 16;
const UDP_CHECKSUM_OFFSET: usize = 6;
const ICMP_CHECKSUM_OFFSET: usize = 2;
const ICMP_QUOTED_PACKET_OFFSET: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Ipv4TranslationError {
    #[error("IPv4 packet is too short: expected at least 20 bytes, got {actual}")]
    PacketTooShort { actual: usize },
    #[error("unsupported IP version {version}; expected IPv4")]
    UnsupportedIpVersion { version: u8 },
    #[error("invalid IPv4 IHL {ihl_words}; expected at least 5 words")]
    InvalidHeaderLength { ihl_words: u8 },
    #[error("truncated IPv4 header: header is {header_len} bytes, packet is {actual} bytes")]
    TruncatedHeader { header_len: usize, actual: usize },
    #[error("IPv4 total length {declared} does not match payload length {actual}")]
    TotalLengthMismatch { declared: usize, actual: usize },
    #[error("unexpected IPv4 source: expected {expected}, got {actual}")]
    UnexpectedSource {
        expected: Ipv4Addr,
        actual: Ipv4Addr,
    },
    #[error("unexpected IPv4 destination: expected {expected}, got {actual}")]
    UnexpectedDestination {
        expected: Ipv4Addr,
        actual: Ipv4Addr,
    },
    #[error("unsupported IPv4 protocol {protocol}")]
    UnsupportedProtocol { protocol: u8 },
    #[error("truncated {protocol} header: expected at least {required} bytes, got {actual}")]
    TruncatedTransportHeader {
        protocol: &'static str,
        required: usize,
        actual: usize,
    },
    #[error("invalid TCP data offset {data_offset_words}; expected at least 5 words")]
    InvalidTcpHeaderLength { data_offset_words: u8 },
    #[error("truncated TCP header: header is {header_len} bytes, fragment carries {actual} bytes")]
    TruncatedTcpHeader { header_len: usize, actual: usize },
    #[error("invalid UDP length {declared} for an IPv4 payload carrying {actual} UDP bytes")]
    InvalidUdpLength { declared: usize, actual: usize },
    #[error("non-final IPv4 fragment carries {actual} bytes; expected a multiple of 8")]
    InvalidFragmentLength { actual: usize },
    #[error("ICMP error quotes only {actual} IPv4 bytes; expected at least 20")]
    QuotedPacketTooShort { actual: usize },
    #[error("ICMP error quotes IP version {version}; expected IPv4")]
    UnsupportedQuotedIpVersion { version: u8 },
    #[error("ICMP error quotes an invalid IPv4 IHL {ihl_words}; expected at least 5 words")]
    InvalidQuotedHeaderLength { ihl_words: u8 },
    #[error(
        "ICMP error quotes a truncated IPv4 header: header is {header_len} bytes, quote is {actual} bytes"
    )]
    TruncatedQuotedHeader { header_len: usize, actual: usize },
    #[error(
        "ICMP error quotes an IPv4 total length {declared} smaller than its {header_len}-byte header"
    )]
    InvalidQuotedTotalLength { declared: usize, header_len: usize },
    #[error("unsupported protocol {protocol} in translated ICMP IPv4 quote")]
    UnsupportedQuotedProtocol { protocol: u8 },
}

#[derive(Clone, Copy)]
enum AddressField {
    Source,
    Destination,
}

impl AddressField {
    fn offset(self) -> usize {
        match self {
            Self::Source => IPV4_SOURCE_OFFSET,
            Self::Destination => IPV4_DESTINATION_OFFSET,
        }
    }
}

#[derive(Clone, Copy)]
struct Ipv4Layout {
    header_len: usize,
    protocol: u8,
    fragment_offset: u16,
    more_fragments: bool,
}

#[derive(Clone, Copy)]
struct ChecksumField {
    offset: usize,
    udp: bool,
}

#[derive(Clone, Copy)]
struct QuotedIpv4Plan {
    header_offset: usize,
    header_len: usize,
    replace_source: bool,
    replace_destination: bool,
    transport_checksum: Option<ChecksumField>,
}

#[derive(Clone, Copy)]
enum TransportPlan {
    HeaderOnly,
    WithPseudoHeaderChecksum(ChecksumField),
    Icmp {
        checksum_offset: usize,
        quoted: Option<QuotedIpv4Plan>,
    },
}

pub(crate) fn rewrite_ipv4_source(
    packet: &mut [u8],
    old_address: Ipv4Addr,
    new_address: Ipv4Addr,
) -> Result<(), Ipv4TranslationError> {
    rewrite_ipv4_address(packet, AddressField::Source, old_address, new_address)
}

pub(crate) fn rewrite_ipv4_destination(
    packet: &mut [u8],
    old_address: Ipv4Addr,
    new_address: Ipv4Addr,
) -> Result<(), Ipv4TranslationError> {
    rewrite_ipv4_address(packet, AddressField::Destination, old_address, new_address)
}

fn rewrite_ipv4_address(
    packet: &mut [u8],
    field: AddressField,
    old_address: Ipv4Addr,
    new_address: Ipv4Addr,
) -> Result<(), Ipv4TranslationError> {
    let layout = parse_complete_ipv4(packet)?;
    let actual_address = read_ipv4_address(packet, field.offset());
    if actual_address != old_address {
        return Err(match field {
            AddressField::Source => Ipv4TranslationError::UnexpectedSource {
                expected: old_address,
                actual: actual_address,
            },
            AddressField::Destination => Ipv4TranslationError::UnexpectedDestination {
                expected: old_address,
                actual: actual_address,
            },
        });
    }

    let transport_plan = analyze_transport(packet, layout, old_address)?;

    match transport_plan {
        TransportPlan::HeaderOnly => {}
        TransportPlan::WithPseudoHeaderChecksum(checksum) => {
            rewrite_pseudo_header_checksum(packet, checksum, old_address, new_address);
        }
        TransportPlan::Icmp {
            checksum_offset,
            quoted,
        } => {
            let mut fragmented_checksum = read_u16(packet, checksum_offset);
            if let Some(quoted) = quoted {
                rewrite_quoted_ipv4(
                    packet,
                    quoted,
                    old_address,
                    new_address,
                    &mut fragmented_checksum,
                );
            }

            if layout.more_fragments {
                write_u16(packet, checksum_offset, fragmented_checksum);
            } else {
                let icmp = &packet[layout.header_len..];
                let checksum = checksum_with_zeroed_word(icmp, ICMP_CHECKSUM_OFFSET);
                write_u16(packet, checksum_offset, checksum);
            }
        }
    }

    packet[field.offset()..field.offset() + 4].copy_from_slice(&new_address.octets());
    let checksum = checksum_with_zeroed_word(&packet[..layout.header_len], IPV4_CHECKSUM_OFFSET);
    write_u16(packet, IPV4_CHECKSUM_OFFSET, checksum);
    Ok(())
}

fn parse_complete_ipv4(packet: &[u8]) -> Result<Ipv4Layout, Ipv4TranslationError> {
    if packet.len() < IPV4_MIN_HEADER_LEN {
        return Err(Ipv4TranslationError::PacketTooShort {
            actual: packet.len(),
        });
    }

    let version = packet[0] >> 4;
    if version != 4 {
        return Err(Ipv4TranslationError::UnsupportedIpVersion { version });
    }
    let ihl_words = packet[0] & 0x0f;
    if ihl_words < 5 {
        return Err(Ipv4TranslationError::InvalidHeaderLength { ihl_words });
    }
    let header_len = usize::from(ihl_words) * 4;
    if header_len > packet.len() {
        return Err(Ipv4TranslationError::TruncatedHeader {
            header_len,
            actual: packet.len(),
        });
    }

    let declared = usize::from(read_u16(packet, 2));
    if declared != packet.len() {
        return Err(Ipv4TranslationError::TotalLengthMismatch {
            declared,
            actual: packet.len(),
        });
    }

    let fragment = read_u16(packet, 6);
    let layout = Ipv4Layout {
        header_len,
        protocol: packet[9],
        fragment_offset: fragment & 0x1fff,
        more_fragments: fragment & 0x2000 != 0,
    };
    let fragment_payload_len = packet.len() - header_len;
    if layout.more_fragments && !fragment_payload_len.is_multiple_of(8) {
        return Err(Ipv4TranslationError::InvalidFragmentLength {
            actual: fragment_payload_len,
        });
    }
    Ok(layout)
}

fn analyze_transport(
    packet: &[u8],
    layout: Ipv4Layout,
    old_address: Ipv4Addr,
) -> Result<TransportPlan, Ipv4TranslationError> {
    if !matches!(
        layout.protocol,
        IP_PROTOCOL_TCP | IP_PROTOCOL_UDP | IP_PROTOCOL_ICMP
    ) {
        return Err(Ipv4TranslationError::UnsupportedProtocol {
            protocol: layout.protocol,
        });
    }
    if layout.fragment_offset != 0 {
        return Ok(TransportPlan::HeaderOnly);
    }

    let transport_len = packet.len() - layout.header_len;
    match layout.protocol {
        IP_PROTOCOL_TCP => {
            let required = if layout.more_fragments {
                TCP_CHECKSUM_OFFSET + 2
            } else {
                TCP_MIN_HEADER_LEN
            };
            if transport_len < required {
                return Err(Ipv4TranslationError::TruncatedTransportHeader {
                    protocol: "TCP",
                    required,
                    actual: transport_len,
                });
            }
            let data_offset_words = packet[layout.header_len + 12] >> 4;
            if data_offset_words < 5 {
                return Err(Ipv4TranslationError::InvalidTcpHeaderLength { data_offset_words });
            }
            let tcp_header_len = usize::from(data_offset_words) * 4;
            if !layout.more_fragments && tcp_header_len > transport_len {
                return Err(Ipv4TranslationError::TruncatedTcpHeader {
                    header_len: tcp_header_len,
                    actual: transport_len,
                });
            }
            Ok(TransportPlan::WithPseudoHeaderChecksum(ChecksumField {
                offset: layout.header_len + TCP_CHECKSUM_OFFSET,
                udp: false,
            }))
        }
        IP_PROTOCOL_UDP => {
            if transport_len < UDP_HEADER_LEN {
                return Err(Ipv4TranslationError::TruncatedTransportHeader {
                    protocol: "UDP",
                    required: UDP_HEADER_LEN,
                    actual: transport_len,
                });
            }
            let udp_len = usize::from(read_u16(packet, layout.header_len + 4));
            let invalid = udp_len < UDP_HEADER_LEN
                || (!layout.more_fragments && udp_len != transport_len)
                || (layout.more_fragments && udp_len <= transport_len);
            if invalid {
                return Err(Ipv4TranslationError::InvalidUdpLength {
                    declared: udp_len,
                    actual: transport_len,
                });
            }
            Ok(TransportPlan::WithPseudoHeaderChecksum(ChecksumField {
                offset: layout.header_len + UDP_CHECKSUM_OFFSET,
                udp: true,
            }))
        }
        IP_PROTOCOL_ICMP => {
            if transport_len < ICMP_MIN_HEADER_LEN {
                return Err(Ipv4TranslationError::TruncatedTransportHeader {
                    protocol: "ICMP",
                    required: ICMP_MIN_HEADER_LEN,
                    actual: transport_len,
                });
            }
            let icmp_offset = layout.header_len;
            let quoted = if is_icmp_error(packet[icmp_offset]) {
                Some(analyze_quoted_ipv4(
                    packet,
                    icmp_offset + ICMP_QUOTED_PACKET_OFFSET,
                    old_address,
                )?)
            } else {
                None
            };
            Ok(TransportPlan::Icmp {
                checksum_offset: icmp_offset + ICMP_CHECKSUM_OFFSET,
                quoted,
            })
        }
        _ => unreachable!("supported protocol checked above"),
    }
}

fn analyze_quoted_ipv4(
    packet: &[u8],
    header_offset: usize,
    old_address: Ipv4Addr,
) -> Result<QuotedIpv4Plan, Ipv4TranslationError> {
    let quote = &packet[header_offset..];
    if quote.len() < IPV4_MIN_HEADER_LEN {
        return Err(Ipv4TranslationError::QuotedPacketTooShort {
            actual: quote.len(),
        });
    }
    let version = quote[0] >> 4;
    if version != 4 {
        return Err(Ipv4TranslationError::UnsupportedQuotedIpVersion { version });
    }
    let ihl_words = quote[0] & 0x0f;
    if ihl_words < 5 {
        return Err(Ipv4TranslationError::InvalidQuotedHeaderLength { ihl_words });
    }
    let header_len = usize::from(ihl_words) * 4;
    if header_len > quote.len() {
        return Err(Ipv4TranslationError::TruncatedQuotedHeader {
            header_len,
            actual: quote.len(),
        });
    }
    let total_len = usize::from(read_u16(quote, 2));
    if total_len < header_len {
        return Err(Ipv4TranslationError::InvalidQuotedTotalLength {
            declared: total_len,
            header_len,
        });
    }

    let replace_source = read_ipv4_address(quote, IPV4_SOURCE_OFFSET) == old_address;
    let replace_destination = read_ipv4_address(quote, IPV4_DESTINATION_OFFSET) == old_address;
    let fragment_offset = read_u16(quote, 6) & 0x1fff;
    let visible_len = total_len.min(quote.len());
    let protocol = quote[9];
    let transport_checksum = if (!replace_source && !replace_destination) || fragment_offset != 0 {
        None
    } else {
        let relative_checksum_offset = match protocol {
            IP_PROTOCOL_TCP => header_len + TCP_CHECKSUM_OFFSET,
            IP_PROTOCOL_UDP => header_len + UDP_CHECKSUM_OFFSET,
            IP_PROTOCOL_ICMP => usize::MAX,
            _ => {
                return Err(Ipv4TranslationError::UnsupportedQuotedProtocol { protocol });
            }
        };
        let checksum_visible =
            relative_checksum_offset != usize::MAX && relative_checksum_offset + 2 <= visible_len;
        checksum_visible.then_some(ChecksumField {
            offset: header_offset + relative_checksum_offset,
            udp: protocol == IP_PROTOCOL_UDP,
        })
    };

    Ok(QuotedIpv4Plan {
        header_offset,
        header_len,
        replace_source,
        replace_destination,
        transport_checksum,
    })
}

fn rewrite_quoted_ipv4(
    packet: &mut [u8],
    plan: QuotedIpv4Plan,
    old_address: Ipv4Addr,
    new_address: Ipv4Addr,
    outer_icmp_checksum: &mut u16,
) {
    if !plan.replace_source && !plan.replace_destination {
        return;
    }

    if let Some(checksum) = plan.transport_checksum {
        let current = read_u16(packet, checksum.offset);
        if !checksum.udp || current != 0 {
            let mut updated = current;
            if plan.replace_source {
                updated = update_checksum_for_address(updated, old_address, new_address);
            }
            if plan.replace_destination {
                updated = update_checksum_for_address(updated, old_address, new_address);
            }
            if checksum.udp && updated == 0 {
                updated = u16::MAX;
            }
            write_tracked_word(packet, checksum.offset, updated, outer_icmp_checksum);
        }
    }

    if plan.replace_source {
        write_tracked_address(
            packet,
            plan.header_offset + IPV4_SOURCE_OFFSET,
            new_address,
            outer_icmp_checksum,
        );
    }
    if plan.replace_destination {
        write_tracked_address(
            packet,
            plan.header_offset + IPV4_DESTINATION_OFFSET,
            new_address,
            outer_icmp_checksum,
        );
    }

    let inner_header = &packet[plan.header_offset..plan.header_offset + plan.header_len];
    let checksum = checksum_with_zeroed_word(inner_header, IPV4_CHECKSUM_OFFSET);
    write_tracked_word(
        packet,
        plan.header_offset + IPV4_CHECKSUM_OFFSET,
        checksum,
        outer_icmp_checksum,
    );
}

fn rewrite_pseudo_header_checksum(
    packet: &mut [u8],
    checksum: ChecksumField,
    old_address: Ipv4Addr,
    new_address: Ipv4Addr,
) {
    let current = read_u16(packet, checksum.offset);
    if checksum.udp && current == 0 {
        return;
    }
    let mut updated = update_checksum_for_address(current, old_address, new_address);
    if checksum.udp && updated == 0 {
        updated = u16::MAX;
    }
    write_u16(packet, checksum.offset, updated);
}

fn write_tracked_address(
    packet: &mut [u8],
    offset: usize,
    address: Ipv4Addr,
    enclosing_checksum: &mut u16,
) {
    let octets = address.octets();
    write_tracked_word(
        packet,
        offset,
        u16::from_be_bytes([octets[0], octets[1]]),
        enclosing_checksum,
    );
    write_tracked_word(
        packet,
        offset + 2,
        u16::from_be_bytes([octets[2], octets[3]]),
        enclosing_checksum,
    );
}

fn write_tracked_word(
    packet: &mut [u8],
    offset: usize,
    new_value: u16,
    enclosing_checksum: &mut u16,
) {
    let old_value = read_u16(packet, offset);
    if old_value == new_value {
        return;
    }
    *enclosing_checksum = update_checksum_word(*enclosing_checksum, old_value, new_value);
    write_u16(packet, offset, new_value);
}

fn update_checksum_for_address(checksum: u16, old_address: Ipv4Addr, new_address: Ipv4Addr) -> u16 {
    let old = old_address.octets();
    let new = new_address.octets();
    let checksum = update_checksum_word(
        checksum,
        u16::from_be_bytes([old[0], old[1]]),
        u16::from_be_bytes([new[0], new[1]]),
    );
    update_checksum_word(
        checksum,
        u16::from_be_bytes([old[2], old[3]]),
        u16::from_be_bytes([new[2], new[3]]),
    )
}

fn update_checksum_word(checksum: u16, old_value: u16, new_value: u16) -> u16 {
    let mut sum = u32::from(!checksum) + u32::from(!old_value) + u32::from(new_value);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn checksum_with_zeroed_word(bytes: &[u8], zero_offset: usize) -> u16 {
    let mut sum = 0u32;
    for (offset, chunk) in bytes.chunks(2).enumerate() {
        let byte_offset = offset * 2;
        let word = if byte_offset == zero_offset {
            0
        } else if let [high, low] = chunk {
            u16::from_be_bytes([*high, *low])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn is_icmp_error(icmp_type: u8) -> bool {
    matches!(icmp_type, 3 | 4 | 5 | 11 | 12)
}

fn read_ipv4_address(bytes: &[u8], offset: usize) -> Ipv4Addr {
    Ipv4Addr::new(
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    )
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([bytes[offset], bytes[offset + 1]])
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const VIRTUAL_IP: Ipv4Addr = Ipv4Addr::new(10, 144, 144, 10);
    const REMOTE_IP: Ipv4Addr = Ipv4Addr::new(10, 144, 144, 20);

    fn build_ipv4(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
        options: &[u8],
        fragment: u16,
    ) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let header_len = IPV4_MIN_HEADER_LEN + options.len();
        let mut packet = vec![0; header_len + payload.len()];
        packet[0] = 0x40 | u8::try_from(header_len / 4).unwrap();
        let packet_len = u16::try_from(packet.len()).unwrap();
        write_u16(&mut packet, 2, packet_len);
        write_u16(&mut packet, 4, 0x1234);
        write_u16(&mut packet, 6, fragment);
        packet[8] = 64;
        packet[9] = protocol;
        packet[IPV4_SOURCE_OFFSET..IPV4_SOURCE_OFFSET + 4].copy_from_slice(&source.octets());
        packet[IPV4_DESTINATION_OFFSET..IPV4_DESTINATION_OFFSET + 4]
            .copy_from_slice(&destination.octets());
        packet[IPV4_MIN_HEADER_LEN..header_len].copy_from_slice(options);
        packet[header_len..].copy_from_slice(payload);
        let checksum = checksum_with_zeroed_word(&packet[..header_len], IPV4_CHECKSUM_OFFSET);
        write_u16(&mut packet, IPV4_CHECKSUM_OFFSET, checksum);
        packet
    }

    fn tcp_segment(source: Ipv4Addr, destination: Ipv4Addr, data: &[u8]) -> Vec<u8> {
        let mut tcp = vec![0; TCP_MIN_HEADER_LEN + data.len()];
        write_u16(&mut tcp, 0, 12345);
        write_u16(&mut tcp, 2, 443);
        tcp[12] = 5 << 4;
        tcp[13] = 0x18;
        write_u16(&mut tcp, 14, 4096);
        tcp[TCP_MIN_HEADER_LEN..].copy_from_slice(data);
        let checksum = transport_checksum(source, destination, IP_PROTOCOL_TCP, &tcp);
        write_u16(&mut tcp, TCP_CHECKSUM_OFFSET, checksum);
        tcp
    }

    fn udp_datagram(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        data: &[u8],
        checksum_enabled: bool,
    ) -> Vec<u8> {
        let mut udp = vec![0; UDP_HEADER_LEN + data.len()];
        write_u16(&mut udp, 0, 5353);
        write_u16(&mut udp, 2, 53);
        let udp_len = u16::try_from(udp.len()).unwrap();
        write_u16(&mut udp, 4, udp_len);
        udp[UDP_HEADER_LEN..].copy_from_slice(data);
        if checksum_enabled {
            let checksum = transport_checksum(source, destination, IP_PROTOCOL_UDP, &udp);
            write_u16(
                &mut udp,
                UDP_CHECKSUM_OFFSET,
                if checksum == 0 { u16::MAX } else { checksum },
            );
        }
        udp
    }

    fn icmp_message(icmp_type: u8, body: &[u8]) -> Vec<u8> {
        let mut icmp = vec![0; ICMP_MIN_HEADER_LEN + body.len()];
        icmp[0] = icmp_type;
        icmp[1] = 0;
        icmp[4..8].copy_from_slice(&[0x12, 0x34, 0, 1]);
        icmp[ICMP_MIN_HEADER_LEN..].copy_from_slice(body);
        let checksum = checksum_with_zeroed_word(&icmp, ICMP_CHECKSUM_OFFSET);
        write_u16(&mut icmp, ICMP_CHECKSUM_OFFSET, checksum);
        icmp
    }

    fn transport_checksum(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        protocol: u8,
        transport: &[u8],
    ) -> u16 {
        let mut bytes = Vec::with_capacity(12 + transport.len());
        bytes.extend_from_slice(&source.octets());
        bytes.extend_from_slice(&destination.octets());
        bytes.push(0);
        bytes.push(protocol);
        bytes.extend_from_slice(&u16::try_from(transport.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(transport);
        checksum_with_zeroed_word(
            &bytes,
            12 + if protocol == IP_PROTOCOL_TCP {
                TCP_CHECKSUM_OFFSET
            } else {
                UDP_CHECKSUM_OFFSET
            },
        )
    }

    fn assert_valid_ipv4_checksum(packet: &[u8]) {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        assert_eq!(
            read_u16(packet, IPV4_CHECKSUM_OFFSET),
            checksum_with_zeroed_word(&packet[..header_len], IPV4_CHECKSUM_OFFSET)
        );
    }

    fn assert_valid_transport_checksum(packet: &[u8], protocol: u8) {
        let header_len = usize::from(packet[0] & 0x0f) * 4;
        let source = read_ipv4_address(packet, IPV4_SOURCE_OFFSET);
        let destination = read_ipv4_address(packet, IPV4_DESTINATION_OFFSET);
        let transport = &packet[header_len..];
        let offset = if protocol == IP_PROTOCOL_TCP {
            TCP_CHECKSUM_OFFSET
        } else {
            UDP_CHECKSUM_OFFSET
        };
        assert_eq!(
            read_u16(transport, offset),
            transport_checksum(source, destination, protocol, transport)
        );
    }

    #[test]
    fn rewrites_tcp_source_with_ipv4_options() {
        let tcp = tcp_segment(CLIENT_IP, REMOTE_IP, b"tcp payload");
        let mut packet = build_ipv4(
            CLIENT_IP,
            REMOTE_IP,
            IP_PROTOCOL_TCP,
            &tcp,
            &[1, 1, 1, 0],
            0,
        );

        rewrite_ipv4_source(&mut packet, CLIENT_IP, VIRTUAL_IP).unwrap();

        assert_eq!(read_ipv4_address(&packet, IPV4_SOURCE_OFFSET), VIRTUAL_IP);
        assert_eq!(
            read_ipv4_address(&packet, IPV4_DESTINATION_OFFSET),
            REMOTE_IP
        );
        assert_valid_ipv4_checksum(&packet);
        assert_valid_transport_checksum(&packet, IP_PROTOCOL_TCP);
    }

    #[test]
    fn rewrites_tcp_destination() {
        let tcp = tcp_segment(REMOTE_IP, VIRTUAL_IP, b"reply");
        let mut packet = build_ipv4(REMOTE_IP, VIRTUAL_IP, IP_PROTOCOL_TCP, &tcp, &[], 0);

        rewrite_ipv4_destination(&mut packet, VIRTUAL_IP, CLIENT_IP).unwrap();

        assert_eq!(read_ipv4_address(&packet, IPV4_SOURCE_OFFSET), REMOTE_IP);
        assert_eq!(
            read_ipv4_address(&packet, IPV4_DESTINATION_OFFSET),
            CLIENT_IP
        );
        assert_valid_ipv4_checksum(&packet);
        assert_valid_transport_checksum(&packet, IP_PROTOCOL_TCP);
    }

    #[test]
    fn rewrites_udp_checksum_and_preserves_disabled_checksum() {
        for checksum_enabled in [true, false] {
            let udp = udp_datagram(CLIENT_IP, REMOTE_IP, b"dns", checksum_enabled);
            let mut packet = build_ipv4(CLIENT_IP, REMOTE_IP, IP_PROTOCOL_UDP, &udp, &[], 0);

            rewrite_ipv4_source(&mut packet, CLIENT_IP, VIRTUAL_IP).unwrap();

            assert_valid_ipv4_checksum(&packet);
            let udp_offset = IPV4_MIN_HEADER_LEN + UDP_CHECKSUM_OFFSET;
            if checksum_enabled {
                assert_valid_transport_checksum(&packet, IP_PROTOCOL_UDP);
                assert_ne!(read_u16(&packet, udp_offset), 0);
            } else {
                assert_eq!(read_u16(&packet, udp_offset), 0);
            }
        }
    }

    #[test]
    fn rewrites_icmp_echo_outer_address_and_checksum() {
        let icmp = icmp_message(8, b"echo payload");
        let original_icmp_checksum = read_u16(&icmp, ICMP_CHECKSUM_OFFSET);
        let mut packet = build_ipv4(CLIENT_IP, REMOTE_IP, IP_PROTOCOL_ICMP, &icmp, &[], 0);

        rewrite_ipv4_source(&mut packet, CLIENT_IP, VIRTUAL_IP).unwrap();

        assert_valid_ipv4_checksum(&packet);
        let translated_icmp = &packet[IPV4_MIN_HEADER_LEN..];
        assert_eq!(
            read_u16(translated_icmp, ICMP_CHECKSUM_OFFSET),
            original_icmp_checksum
        );
        assert_eq!(
            read_u16(translated_icmp, ICMP_CHECKSUM_OFFSET),
            checksum_with_zeroed_word(translated_icmp, ICMP_CHECKSUM_OFFSET)
        );
    }

    #[test]
    fn rewrites_icmp_error_quoted_ipv4_and_visible_udp_checksum() {
        let udp = udp_datagram(VIRTUAL_IP, REMOTE_IP, b"request", true);
        let quoted = build_ipv4(VIRTUAL_IP, REMOTE_IP, IP_PROTOCOL_UDP, &udp, &[], 0);
        let icmp = icmp_message(3, &quoted);
        let mut packet = build_ipv4(REMOTE_IP, VIRTUAL_IP, IP_PROTOCOL_ICMP, &icmp, &[], 0);

        rewrite_ipv4_destination(&mut packet, VIRTUAL_IP, CLIENT_IP).unwrap();

        assert_valid_ipv4_checksum(&packet);
        let outer_ihl = IPV4_MIN_HEADER_LEN;
        let translated_icmp = &packet[outer_ihl..];
        assert_eq!(
            read_u16(translated_icmp, ICMP_CHECKSUM_OFFSET),
            checksum_with_zeroed_word(translated_icmp, ICMP_CHECKSUM_OFFSET)
        );
        let translated_quote = &translated_icmp[ICMP_QUOTED_PACKET_OFFSET..];
        assert_eq!(
            read_ipv4_address(translated_quote, IPV4_SOURCE_OFFSET),
            CLIENT_IP
        );
        assert_valid_ipv4_checksum(translated_quote);
        assert_valid_transport_checksum(translated_quote, IP_PROTOCOL_UDP);
    }

    #[test]
    fn rewrites_icmp_error_quoted_destination_and_visible_tcp_checksum() {
        let tcp = tcp_segment(REMOTE_IP, CLIENT_IP, b"request");
        let quoted = build_ipv4(REMOTE_IP, CLIENT_IP, IP_PROTOCOL_TCP, &tcp, &[], 0);
        let icmp = icmp_message(11, &quoted);
        let mut packet = build_ipv4(CLIENT_IP, REMOTE_IP, IP_PROTOCOL_ICMP, &icmp, &[], 0);

        rewrite_ipv4_source(&mut packet, CLIENT_IP, VIRTUAL_IP).unwrap();

        assert_valid_ipv4_checksum(&packet);
        let translated_icmp = &packet[IPV4_MIN_HEADER_LEN..];
        assert_eq!(
            read_u16(translated_icmp, ICMP_CHECKSUM_OFFSET),
            checksum_with_zeroed_word(translated_icmp, ICMP_CHECKSUM_OFFSET)
        );
        let translated_quote = &translated_icmp[ICMP_QUOTED_PACKET_OFFSET..];
        assert_eq!(
            read_ipv4_address(translated_quote, IPV4_DESTINATION_OFFSET),
            VIRTUAL_IP
        );
        assert_valid_ipv4_checksum(translated_quote);
        assert_valid_transport_checksum(translated_quote, IP_PROTOCOL_TCP);
    }

    #[test]
    fn rewrites_fragmented_tcp_checksum_only_in_first_fragment() {
        let tcp = tcp_segment(CLIENT_IP, REMOTE_IP, b"0123456789abcdef01234567");
        let split = 24;
        let mut first = build_ipv4(
            CLIENT_IP,
            REMOTE_IP,
            IP_PROTOCOL_TCP,
            &tcp[..split],
            &[],
            0x2000,
        );
        let mut second = build_ipv4(
            CLIENT_IP,
            REMOTE_IP,
            IP_PROTOCOL_TCP,
            &tcp[split..],
            &[],
            u16::try_from(split / 8).unwrap(),
        );
        let second_payload_before = second[IPV4_MIN_HEADER_LEN..].to_vec();

        rewrite_ipv4_source(&mut first, CLIENT_IP, VIRTUAL_IP).unwrap();
        rewrite_ipv4_source(&mut second, CLIENT_IP, VIRTUAL_IP).unwrap();

        assert_valid_ipv4_checksum(&first);
        assert_valid_ipv4_checksum(&second);
        assert_eq!(&second[IPV4_MIN_HEADER_LEN..], second_payload_before);
        let mut translated_tcp = first[IPV4_MIN_HEADER_LEN..].to_vec();
        translated_tcp.extend_from_slice(&second[IPV4_MIN_HEADER_LEN..]);
        assert_eq!(
            read_u16(&translated_tcp, TCP_CHECKSUM_OFFSET),
            transport_checksum(VIRTUAL_IP, REMOTE_IP, IP_PROTOCOL_TCP, &translated_tcp)
        );
    }

    #[test]
    fn rejects_truncated_and_length_mismatched_ipv4_packets() {
        let mut short = vec![0; IPV4_MIN_HEADER_LEN - 1];
        assert_eq!(
            rewrite_ipv4_source(&mut short, CLIENT_IP, VIRTUAL_IP),
            Err(Ipv4TranslationError::PacketTooShort {
                actual: IPV4_MIN_HEADER_LEN - 1
            })
        );

        let udp = udp_datagram(CLIENT_IP, REMOTE_IP, b"data", true);
        let mut mismatched = build_ipv4(CLIENT_IP, REMOTE_IP, IP_PROTOCOL_UDP, &udp, &[], 0);
        let declared = mismatched.len();
        mismatched.push(0);
        assert_eq!(
            rewrite_ipv4_source(&mut mismatched, CLIENT_IP, VIRTUAL_IP),
            Err(Ipv4TranslationError::TotalLengthMismatch {
                declared,
                actual: declared + 1,
            })
        );

        let mut truncated_options = vec![0; IPV4_MIN_HEADER_LEN];
        truncated_options[0] = 0x46;
        write_u16(&mut truncated_options, 2, IPV4_MIN_HEADER_LEN as u16);
        assert_eq!(
            rewrite_ipv4_source(&mut truncated_options, CLIENT_IP, VIRTUAL_IP),
            Err(Ipv4TranslationError::TruncatedHeader {
                header_len: 24,
                actual: IPV4_MIN_HEADER_LEN,
            })
        );
    }

    #[test]
    fn rejects_unsupported_protocol_without_mutating_packet() {
        let mut packet = build_ipv4(CLIENT_IP, REMOTE_IP, 47, &[0; 8], &[], 0);
        let original = packet.clone();

        assert_eq!(
            rewrite_ipv4_source(&mut packet, CLIENT_IP, VIRTUAL_IP),
            Err(Ipv4TranslationError::UnsupportedProtocol { protocol: 47 })
        );
        assert_eq!(packet, original);
    }

    #[test]
    fn rejects_unexpected_source_and_destination_without_mutating_packet() {
        let tcp = tcp_segment(CLIENT_IP, REMOTE_IP, b"payload");
        let packet = build_ipv4(CLIENT_IP, REMOTE_IP, IP_PROTOCOL_TCP, &tcp, &[], 0);

        let mut source_packet = packet.clone();
        assert_eq!(
            rewrite_ipv4_source(&mut source_packet, VIRTUAL_IP, CLIENT_IP),
            Err(Ipv4TranslationError::UnexpectedSource {
                expected: VIRTUAL_IP,
                actual: CLIENT_IP,
            })
        );
        assert_eq!(source_packet, packet);

        let mut destination_packet = packet.clone();
        assert_eq!(
            rewrite_ipv4_destination(&mut destination_packet, VIRTUAL_IP, CLIENT_IP),
            Err(Ipv4TranslationError::UnexpectedDestination {
                expected: VIRTUAL_IP,
                actual: REMOTE_IP,
            })
        );
        assert_eq!(destination_packet, packet);
    }

    #[test]
    fn rejects_truncated_transport_and_icmp_quote() {
        let mut tcp = build_ipv4(
            CLIENT_IP,
            REMOTE_IP,
            IP_PROTOCOL_TCP,
            &[0; TCP_MIN_HEADER_LEN - 1],
            &[],
            0,
        );
        assert_eq!(
            rewrite_ipv4_source(&mut tcp, CLIENT_IP, VIRTUAL_IP),
            Err(Ipv4TranslationError::TruncatedTransportHeader {
                protocol: "TCP",
                required: TCP_MIN_HEADER_LEN,
                actual: TCP_MIN_HEADER_LEN - 1,
            })
        );

        let icmp = icmp_message(11, &[0; IPV4_MIN_HEADER_LEN - 1]);
        let mut packet = build_ipv4(REMOTE_IP, VIRTUAL_IP, IP_PROTOCOL_ICMP, &icmp, &[], 0);
        assert_eq!(
            rewrite_ipv4_destination(&mut packet, VIRTUAL_IP, CLIENT_IP),
            Err(Ipv4TranslationError::QuotedPacketTooShort {
                actual: IPV4_MIN_HEADER_LEN - 1,
            })
        );
    }
}
