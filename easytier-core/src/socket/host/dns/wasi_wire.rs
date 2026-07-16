use std::{io, net::IpAddr};

use crate::socket::{
    IpVersion,
    dns::{DnsQuery, DnsSrvRecord},
};

const DNS_WIRE_VERSION: u8 = 1;
#[cfg(target_os = "wasi")]
pub(super) const MAX_DNS_RESULT_LEN: usize = 1024 * 1024;

pub(super) fn encode_query(query: &DnsQuery) -> io::Result<Vec<u8>> {
    let host = query.host.as_bytes();
    let netns = query
        .context
        .netns
        .as_ref()
        .map(|netns| netns.token().as_bytes());
    let host_len = encoded_len("DNS host", host.len())?;
    let netns_len = encoded_len("DNS netns token", netns.map_or(0, <[u8]>::len))?;
    let mut encoded = Vec::with_capacity(16 + host.len() + netns.map_or(0, <[u8]>::len));
    encoded.push(DNS_WIRE_VERSION);
    encoded.push(match query.context.ip_version {
        IpVersion::V4 => 4,
        IpVersion::V6 => 6,
        IpVersion::Both => 0,
    });
    encoded.push(u8::from(query.context.socket_mark.is_some()));
    encoded.extend_from_slice(&query.context.socket_mark.unwrap_or_default().to_be_bytes());
    encoded.push(u8::from(netns.is_some()));
    encoded.extend_from_slice(&netns_len.to_be_bytes());
    if let Some(netns) = netns {
        encoded.extend_from_slice(netns);
    }
    encoded.extend_from_slice(&host_len.to_be_bytes());
    encoded.extend_from_slice(host);
    Ok(encoded)
}

pub(super) fn decode_addresses(encoded: &[u8]) -> io::Result<Vec<IpAddr>> {
    let mut decoder = Decoder::new(encoded);
    let count = decoder.take_count("DNS address count")?;
    let mut addresses = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let family = decoder.take_u8("DNS address family")?;
        let address = match family {
            4 => IpAddr::V4(decoder.take_array::<4>("IPv4 address")?.into()),
            6 => IpAddr::V6(decoder.take_array::<16>("IPv6 address")?.into()),
            _ => return Err(invalid_data("invalid DNS address family")),
        };
        addresses.push(address);
    }
    decoder.finish()?;
    Ok(addresses)
}

pub(super) fn decode_txt(encoded: &[u8]) -> io::Result<String> {
    let mut decoder = Decoder::new(encoded);
    let length = decoder.take_count("DNS TXT length")?;
    let text = decoder.take(length, "DNS TXT value")?;
    decoder.finish()?;
    String::from_utf8(text.to_vec()).map_err(|_| invalid_data("DNS TXT is not UTF-8"))
}

pub(super) fn decode_srv(encoded: &[u8]) -> io::Result<Vec<DnsSrvRecord>> {
    let mut decoder = Decoder::new(encoded);
    let count = decoder.take_count("DNS SRV count")?;
    let mut records = Vec::with_capacity(count.min(64));
    for _ in 0..count {
        let priority = decoder.take_u16("DNS SRV priority")?;
        let weight = decoder.take_u16("DNS SRV weight")?;
        let port = decoder.take_u16("DNS SRV port")?;
        let target_len = decoder.take_count("DNS SRV target length")?;
        let target = String::from_utf8(decoder.take(target_len, "DNS SRV target")?.to_vec())
            .map_err(|_| invalid_data("DNS SRV target is not UTF-8"))?;
        records.push(DnsSrvRecord {
            priority,
            weight,
            port,
            target,
        });
    }
    decoder.finish()?;
    Ok(records)
}

fn encoded_len(description: &str, length: usize) -> io::Result<u32> {
    u32::try_from(length).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{description} is too long"),
        )
    })
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Decoder<'a> {
    encoded: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(encoded: &'a [u8]) -> Self {
        Self { encoded, offset: 0 }
    }

    fn take(&mut self, length: usize, description: &'static str) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| invalid_data("DNS result length overflow"))?;
        let value = self
            .encoded
            .get(self.offset..end)
            .ok_or_else(|| invalid_data(description))?;
        self.offset = end;
        Ok(value)
    }

    fn take_u8(&mut self, description: &'static str) -> io::Result<u8> {
        Ok(self.take(1, description)?[0])
    }

    fn take_u16(&mut self, description: &'static str) -> io::Result<u16> {
        Ok(u16::from_be_bytes(self.take_array::<2>(description)?))
    }

    fn take_count(&mut self, description: &'static str) -> io::Result<usize> {
        usize::try_from(u32::from_be_bytes(self.take_array::<4>(description)?))
            .map_err(|_| invalid_data("DNS result count exceeds guest usize"))
    }

    fn take_array<const N: usize>(&mut self, description: &'static str) -> io::Result<[u8; N]> {
        self.take(N, description)?
            .try_into()
            .map_err(|_| invalid_data(description))
    }

    fn finish(self) -> io::Result<()> {
        if self.offset == self.encoded.len() {
            Ok(())
        } else {
            Err(invalid_data("DNS result has trailing bytes"))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::socket::{NetNamespace, SocketContext};

    use super::*;

    #[test]
    fn query_encoding_has_stable_versioned_layout() {
        let query = DnsQuery::new(
            "peer.example",
            SocketContext {
                ip_version: IpVersion::V6,
                socket_mark: Some(0x01020304),
                netns: Some(NetNamespace::new("mihomo")),
            },
        );
        let encoded = encode_query(&query).unwrap();

        let mut expected = vec![DNS_WIRE_VERSION, 6, 1, 1, 2, 3, 4, 1];
        expected.extend_from_slice(&6_u32.to_be_bytes());
        expected.extend_from_slice(b"mihomo");
        expected.extend_from_slice(&12_u32.to_be_bytes());
        expected.extend_from_slice(b"peer.example");
        assert_eq!(encoded, expected);

        let without_optional = encode_query(&DnsQuery::new(
            "v4.example",
            SocketContext {
                ip_version: IpVersion::V4,
                socket_mark: None,
                netns: None,
            },
        ))
        .unwrap();
        assert_eq!(
            &without_optional[..12],
            &[1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(&without_optional[12..16], &10_u32.to_be_bytes());
        assert_eq!(&without_optional[16..], b"v4.example");
    }

    #[test]
    fn decodes_owned_address_txt_and_srv_results() {
        let mut addresses = 2_u32.to_be_bytes().to_vec();
        addresses.push(4);
        addresses.extend_from_slice(&[192, 0, 2, 1]);
        addresses.push(6);
        addresses.extend_from_slice(
            &"2001:db8::1"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets(),
        );
        assert_eq!(
            decode_addresses(&addresses).unwrap(),
            vec![
                "192.0.2.1".parse::<IpAddr>().unwrap(),
                "2001:db8::1".parse::<IpAddr>().unwrap(),
            ]
        );

        let mut txt = 12_u32.to_be_bytes().to_vec();
        txt.extend_from_slice(b"tcp://peer:1");
        assert_eq!(decode_txt(&txt).unwrap(), "tcp://peer:1");

        let mut srv = 1_u32.to_be_bytes().to_vec();
        srv.extend_from_slice(&10_u16.to_be_bytes());
        srv.extend_from_slice(&20_u16.to_be_bytes());
        srv.extend_from_slice(&11010_u16.to_be_bytes());
        srv.extend_from_slice(&13_u32.to_be_bytes());
        srv.extend_from_slice(b"peer.example.");
        assert_eq!(
            decode_srv(&srv).unwrap(),
            vec![DnsSrvRecord {
                priority: 10,
                weight: 20,
                port: 11010,
                target: "peer.example.".to_owned(),
            }]
        );
    }

    #[test]
    fn rejects_malformed_results() {
        assert!(decode_addresses(&[0, 0, 0]).is_err());
        assert!(decode_addresses(&[0, 0, 0, 1, 9]).is_err());
        assert!(decode_addresses(&[0, 0, 0, 0, 1]).is_err());

        let mut invalid_txt = 1_u32.to_be_bytes().to_vec();
        invalid_txt.push(0xff);
        assert!(decode_txt(&invalid_txt).is_err());

        let mut truncated_srv = 1_u32.to_be_bytes().to_vec();
        truncated_srv.extend_from_slice(&10_u16.to_be_bytes());
        assert!(decode_srv(&truncated_srv).is_err());

        let mut trailing_srv = 0_u32.to_be_bytes().to_vec();
        trailing_srv.push(0);
        assert!(decode_srv(&trailing_srv).is_err());
    }
}
