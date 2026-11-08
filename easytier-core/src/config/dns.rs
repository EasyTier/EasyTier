//! Shared compilation of file and management DNS input into validated RRsets.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, bail, ensure};
use easytier_proto::core_config::{
    DnsConfigRaw, DnsRecordRaw, DnsRecordType, DnsZoneConfigRaw, dns_record_raw::Data,
};
use hickory_proto::{
    rr::{
        LowerName, Name, RData, Record, RecordSet, RecordType, RrKey,
        rdata::{HTTPS, SVCB, TXT},
    },
    serialize::{
        binary::{BinEncodable, BinEncoder, EncodeMode},
        txt::RDataParser,
    },
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsZone {
    pub origin: LowerName,
    pub records: BTreeMap<RrKey, RecordSet>,
}

impl DnsZone {
    pub fn origin(&self) -> &LowerName {
        &self.origin
    }

    pub fn iter_records(&self) -> impl Iterator<Item = &Record> {
        self.records
            .values()
            .flat_map(RecordSet::records_without_rrsigs)
    }
}

pub fn parse_origin(origin: &str) -> anyhow::Result<LowerName> {
    ensure!(
        !origin.trim().is_empty(),
        "DNS zone origin must not be empty"
    );
    let mut name: Name = origin.parse().context("invalid DNS zone origin")?;
    ensure!(!name.is_root(), "DNS zone origin must not be root");
    name.set_fqdn(true);
    Ok(LowerName::new(&name))
}

/// Compile without rewriting the input: relative names and TTL presence remain
/// user intent, while the returned zones compare independently of record order.
pub fn compile_dns(config: &DnsConfigRaw) -> anyhow::Result<BTreeMap<LowerName, DnsZone>> {
    if let Some(domain) = &config.domain {
        parse_origin(domain).map_err(|error| anyhow::anyhow!("dns.domain: {error:#}"))?;
    }
    let mut zones = BTreeMap::new();
    for (index, input) in config
        .zone
        .iter()
        .flat_map(|zones| &zones.items)
        .enumerate()
    {
        let path = format!("dns.zone[{index}]");
        let zone = compile_zone(input).map_err(|error| anyhow::anyhow!("{path}.{error:#}"))?;
        ensure!(
            !zones.contains_key(&zone.origin),
            "{path}.origin: duplicate zone origin {}",
            zone.origin
        );
        zones.insert(zone.origin.clone(), zone);
    }
    Ok(zones)
}

pub fn compile_zone(input: &DnsZoneConfigRaw) -> anyhow::Result<DnsZone> {
    let origin = parse_origin(&input.origin).context("origin")?;
    let origin_name = Name::from(&origin);
    let mut records = BTreeMap::<RrKey, (u32, BTreeMap<Vec<u8>, Record>)>::new();
    let mut owner_types = BTreeMap::<LowerName, BTreeSet<RecordType>>::new();
    for (index, record_input) in input
        .records
        .iter()
        .flat_map(|records| &records.items)
        .enumerate()
    {
        let path = format!("records[{index}]");
        let record = compile_record(
            record_input,
            &origin_name,
            record_input.ttl.or(input.ttl).unwrap_or_default(),
        )
        .map_err(|error| anyhow::anyhow!("{path}.{error:#}"))?;
        let owner = LowerName::new(record.name());
        let record_type = record.record_type();
        let types = owner_types.entry(owner.clone()).or_default();
        ensure!(
            types.is_empty()
                || (!types.contains(&RecordType::CNAME) && record_type != RecordType::CNAME),
            "{path}.type: CNAME cannot coexist with another record at {owner}"
        );
        types.insert(record_type);
        ensure!(
            record_type != RecordType::SOA || owner == origin,
            "{path}.name: SOA must be at the zone origin"
        );
        let key = RrKey::new(owner, record_type);
        let (ttl, values) = records
            .entry(key)
            .or_insert_with(|| (record.ttl(), BTreeMap::new()));
        ensure!(*ttl == record.ttl(), "{path}.ttl: RRset TTLs must match");
        let data_field = if record_type == RecordType::TXT {
            "txt"
        } else {
            "value"
        };
        let mut bytes = Vec::new();
        let mut encoder = BinEncoder::with_mode(&mut bytes, EncodeMode::Signing);
        encoder.set_canonical_names(true);
        record
            .data()
            .emit(&mut encoder)
            .with_context(|| format!("{path}.{data_field}"))?;
        ensure!(
            !values.contains_key(&bytes),
            "{path}.{data_field}: duplicate RDATA"
        );
        ensure!(
            values.is_empty()
                || !matches!(
                    record_type,
                    RecordType::CNAME | RecordType::ANAME | RecordType::SOA
                ),
            "{path}.{data_field}: {record_type} permits only one value"
        );
        values.insert(bytes, record);
    }
    Ok(DnsZone {
        origin,
        records: records
            .into_iter()
            .map(|(key, (_, values))| {
                let mut records = values.into_values();
                let first = records.next().expect("each RRset has a record");
                let mut set = RecordSet::new(first.name().clone(), first.record_type(), 0);
                set.insert(first, 0);
                for record in records {
                    set.insert(record, 0);
                }
                (key, set)
            })
            .collect(),
    })
}

fn compile_record(input: &DnsRecordRaw, origin: &Name, ttl: u32) -> anyhow::Result<Record> {
    ensure!(
        !input.name.is_empty(),
        "name: record name must not be empty"
    );
    let name = if input.name == "@" {
        origin.clone()
    } else {
        Name::parse(&input.name, Some(origin)).context("name")?
    }
    .to_lowercase();
    ensure!(origin.zone_of(&name), "name: record is outside its zone");
    let kind = DnsRecordType::try_from(input.r#type).context("type: unsupported record type")?;
    ensure!(
        kind != DnsRecordType::Unspecified,
        "type: record type is required"
    );
    let record_type: RecordType = kind.as_str_name().parse().context("type")?;
    let rdata = match (&input.data, record_type) {
        (Some(Data::Txt(txt)), RecordType::TXT) => {
            ensure!(
                !txt.segments.is_empty(),
                "txt.segments: at least one segment is required"
            );
            for (index, segment) in txt.segments.iter().enumerate() {
                ensure!(
                    segment.len() <= 255,
                    "txt.segments[{index}]: exceeds 255 UTF-8 bytes"
                );
            }
            RData::TXT(TXT::new(txt.segments.clone()))
        }
        (Some(Data::Value(value)), kind) if kind != RecordType::TXT => {
            parse_value(kind, value, origin).context("value")?
        }
        (Some(Data::Txt(_)), _) => bail!("txt: only TXT records accept txt.segments"),
        (Some(Data::Value(_)), _) => bail!("value: TXT records require txt.segments"),
        (None, RecordType::TXT) => bail!("txt: at least one segment is required"),
        (None, _) => bail!("value: RDATA is required"),
    };
    let record = Record::from_rdata(name, ttl, rdata);
    record.to_bytes().with_context(|| {
        if record_type == RecordType::TXT {
            "txt.segments: invalid DNS wire encoding"
        } else {
            "value: invalid DNS wire encoding"
        }
    })?;
    Ok(record)
}

fn parse_value(kind: RecordType, value: &str, origin: &Name) -> anyhow::Result<RData> {
    let mut tokens = rdata_tokens(value)?;
    let name_fields: &[usize] = match kind {
        RecordType::ANAME | RecordType::CNAME | RecordType::NS | RecordType::PTR => &[0],
        RecordType::MX | RecordType::SVCB | RecordType::HTTPS => &[1],
        RecordType::NAPTR => &[5],
        RecordType::SOA => &[0, 1],
        RecordType::SRV => &[3],
        _ => &[],
    };
    for &index in name_fields {
        if let Some(token) = tokens.get_mut(index)
            && token == "@"
        {
            *token = origin.to_string();
        }
    }
    if matches!(kind, RecordType::SVCB | RecordType::HTTPS) {
        validate_svcb_params(&tokens)?;
    }
    let mut tokens = tokens.iter().map(String::as_str);
    let mut data = RData::parse(kind, &mut tokens, Some(origin))?;
    ensure!(tokens.next().is_none(), "unexpected trailing RDATA tokens");
    // Hickory 0.25's SVCB parser does not accept an origin. Complete only its
    // DNS target, leaving parameter strings and opaque values untouched.
    let complete = |data: &SVCB| -> anyhow::Result<SVCB> {
        let target = if data.target_name().is_fqdn() {
            data.target_name().clone()
        } else {
            data.target_name().clone().append_domain(origin)?
        };
        Ok(SVCB::new(
            data.svc_priority(),
            target,
            data.svc_params().to_vec(),
        ))
    };
    match &data {
        RData::SVCB(svcb) => data = RData::SVCB(complete(svcb)?),
        RData::HTTPS(https) => data = RData::HTTPS(HTTPS(complete(https)?)),
        _ => {}
    }
    Ok(data)
}

// Hickory 0.25.2 slices quoted values and expects ALPN decoding to be infallible.
// Reject malformed quotes and list members before entering those parser paths.
fn validate_svcb_params(tokens: &[String]) -> anyhow::Result<()> {
    for token in tokens.iter().skip(2) {
        let Some((key, value)) = token.split_once('=') else {
            continue;
        };
        let value = if let Some(value) = value.strip_prefix('"') {
            let value = value
                .strip_suffix('"')
                .context("unclosed SVCB parameter quote")?;
            ensure!(
                value.chars().rev().take_while(|&ch| ch == '\\').count() % 2 == 0,
                "unclosed SVCB parameter quote"
            );
            value
        } else {
            value
        };
        if key != "alpn" {
            continue;
        }
        let mut chars = value.chars();
        let mut member = String::new();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => {
                    if let Some(ch) = chars.next() {
                        member.push(ch);
                    }
                }
                ',' => {
                    validate_alpn_member(&member)?;
                    member.clear();
                }
                ch => member.push(ch),
            }
        }
        if !member.is_empty() {
            validate_alpn_member(&member)?;
        }
    }
    Ok(())
}

fn validate_alpn_member(value: &str) -> anyhow::Result<()> {
    // The library expects its first lexer token to be character data, rather
    // than a leading blank, @, or parenthesized list.
    ensure!(
        value
            .chars()
            .next()
            .is_some_and(|ch| !ch.is_whitespace() && !matches!(ch, '@' | '(')),
        "invalid ALPN protocol identifier"
    );
    rdata_tokens(value).context("invalid ALPN protocol identifier")?;
    Ok(())
}

/// Tokenize one RDATA, retaining the iterator for strict consumption checks.
/// Hickory's lexer is private; its TXT parser decodes individual quoted strings
/// using the same escaping rules as the previous zone-file input.
fn rdata_tokens(value: &str) -> anyhow::Result<Vec<String>> {
    let mut chars = value.char_indices().peekable();
    let mut tokens = Vec::new();
    let mut list = false;
    while let Some((start, ch)) = chars.next() {
        match ch {
            '(' => {
                ensure!(!list, "nested RDATA parentheses are not supported");
                list = true;
            }
            ')' => {
                ensure!(list, "unmatched RDATA parenthesis");
                list = false;
            }
            '\r' | '\n' => ensure!(list, "multiple RDATA lines are not supported"),
            ch if ch.is_whitespace() => {}
            ';' | '$' => bail!("zone directives and comments are not supported in RDATA"),
            '"' => {
                let mut end = None;
                let mut steps = 0;
                while let Some((index, ch)) = chars.next() {
                    if ch == '\\' {
                        let (_, escaped) = chars.next().context("incomplete RDATA escape")?;
                        if escaped.is_numeric() {
                            ensure!(
                                chars.next().is_some() && chars.next().is_some(),
                                "incomplete numeric RDATA escape"
                            );
                        }
                        steps += 1;
                        continue;
                    }
                    if ch == '"' {
                        end = Some(index + 1);
                        break;
                    }
                    steps += 1;
                }
                let end = end.context("unclosed RDATA quoted string")?;
                let token = &value[start..end];
                // The dependency's lexer asserts after 4096 steps per token.
                // Values that exceed that bound must fail rather than panic.
                ensure!(steps <= 4093, "RDATA token exceeds parser limit");
                // A leading blank enters the same lexer state as RDATA after
                // a zone-file header, including its maximum token length.
                let RData::TXT(decoded) =
                    RData::try_from_str(RecordType::TXT, &format!(" {token}"))?
                else {
                    unreachable!("the TXT parser returns TXT");
                };
                for segment in decoded.txt_data() {
                    tokens.push(String::from_utf8(segment.to_vec())?);
                }
            }
            ch => {
                ensure!(!ch.is_control(), "control character in RDATA");
                let mut end = start + ch.len_utf8();
                while let Some(&(index, ch)) = chars.peek() {
                    if ch.is_whitespace() || matches!(ch, ')' | ';') {
                        break;
                    }
                    ensure!(!ch.is_control(), "control character in RDATA");
                    chars.next();
                    end = index + ch.len_utf8();
                }
                let token = &value[start..end];
                ensure!(
                    token.chars().count() <= 4093,
                    "RDATA token exceeds parser limit"
                );
                tokens.push(token.to_owned());
            }
        }
    }
    ensure!(!list, "unclosed RDATA parenthesis");
    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier_proto::core_config::DnsTxtData;
    use hickory_proto::serialize::binary::BinDecodable;

    fn record(kind: DnsRecordType, value: &str) -> DnsRecordRaw {
        DnsRecordRaw {
            name: "service".into(),
            r#type: kind as i32,
            ttl: None,
            data: Some(Data::Value(value.into())),
        }
    }

    fn zone(records: Vec<DnsRecordRaw>) -> DnsZoneConfigRaw {
        DnsZoneConfigRaw {
            origin: "EXAMPLE.test".into(),
            ttl: Some(60),
            records: Some(records.into()),
        }
    }

    #[test]
    fn supported_rdata_compiles_and_survives_wire_encoding() {
        use DnsRecordType::*;
        for (kind, value) in [
            (A, "192.0.2.1"),
            (Aaaa, "2001:db8::1"),
            (Aname, "target"),
            (Caa, "0 issue \"letsencrypt.org\""),
            (Cert, "1 123 3 Q2VydA=="),
            (Cname, "target"),
            (Csync, "1 3 A AAAA"),
            (Hinfo, "\"cpu\" \"os\""),
            (Https, "1 target alpn=h2 port=443"),
            (Mx, "10 mail"),
            (
                Naptr,
                "100 10 \"U\" \"SIP+D2U\" \"!^.*$!sip:info@example.test!\" target",
            ),
            (Ns, "ns"),
            (Openpgpkey, "Zm9v"),
            (Ptr, "target"),
            (Soa, "ns hostmaster ( 1 2 3 4 5 )"),
            (Srv, "10 5 5060 sip"),
            (Sshfp, "1 1 ABCD"),
            (Svcb, "1 target alpn=h2 port=443"),
            (Tlsa, "3 1 1 ABCD"),
        ] {
            let mut input = record(kind, value);
            if kind == Soa {
                input.name = "@".into();
            }
            let zone = compile_zone(&zone(vec![input])).unwrap_or_else(|error| {
                panic!("{kind:?}: {error:#}");
            });
            let record = zone
                .records
                .values()
                .next()
                .unwrap()
                .records_without_rrsigs()
                .next()
                .unwrap();
            let decoded = Record::from_bytes(&record.to_bytes().unwrap()).unwrap();
            assert_eq!(&decoded, record, "{kind:?}");
            assert_eq!(record.record_type(), (kind as u16).into());
            assert_eq!(record.ttl(), 60);
            match record.data() {
                RData::CNAME(name) => assert_eq!(name.to_string(), "target.example.test."),
                RData::SVCB(data) => {
                    assert_eq!(data.target_name().to_string(), "target.example.test.")
                }
                RData::HTTPS(data) => {
                    assert_eq!(data.target_name().to_string(), "target.example.test.")
                }
                _ => {}
            }
        }
    }

    #[test]
    fn txt_segments_are_literal_ordered_utf8_strings() {
        let segments = vec!["quote\" slash\\ ;\n".into(), String::new(), "x".repeat(255)];
        let mut input = record(DnsRecordType::Txt, "");
        input.data = Some(Data::Txt(DnsTxtData {
            segments: segments.clone(),
        }));
        let parsed = compile_zone(&zone(vec![input.clone()])).unwrap();
        let record = parsed
            .records
            .values()
            .next()
            .unwrap()
            .records_without_rrsigs()
            .next()
            .unwrap();
        let decoded = Record::from_bytes(&record.to_bytes().unwrap()).unwrap();
        let RData::TXT(txt) = decoded.data() else {
            panic!("expected TXT")
        };
        assert_eq!(
            txt.txt_data(),
            segments
                .iter()
                .map(|s| s.as_bytes().to_vec().into_boxed_slice())
                .collect::<Vec<_>>()
        );
        for segments in [vec![], vec!["x".repeat(256)], vec!["é".repeat(128)]] {
            input.data = Some(Data::Txt(DnsTxtData { segments }));
            assert!(compile_zone(&zone(vec![input.clone()])).is_err());
        }
    }

    #[test]
    fn names_defaults_and_rrsets_share_one_semantics() {
        let mut a = record(DnsRecordType::A, "192.0.2.1");
        a.name = "HOST".into();
        let mut b = record(DnsRecordType::A, "192.0.2.2");
        b.name = "host.example.test.".into();
        let input = zone(vec![a.clone(), b.clone()]);
        let before = input.clone();
        let first = compile_zone(&input).unwrap();
        assert_eq!(input, before);
        assert_eq!(
            first,
            compile_zone(&zone(vec![b.clone(), a.clone()])).unwrap()
        );
        b.ttl = Some(0);
        assert!(
            compile_zone(&zone(vec![a.clone(), b]))
                .unwrap_err()
                .to_string()
                .contains("records[1].ttl")
        );
        assert!(compile_zone(&zone(vec![a.clone(), a])).is_err());
        let mut input = record(DnsRecordType::Cname, "@");
        input.name = "_service._tcp".into();
        input.ttl = Some(0);
        let parsed = compile_zone(&zone(vec![input])).unwrap();
        let rr = parsed
            .records
            .values()
            .next()
            .unwrap()
            .records_without_rrsigs()
            .next()
            .unwrap();
        assert_eq!(rr.name().to_string(), "_service._tcp.example.test.");
        assert_eq!(rr.ttl(), 0);
        assert_eq!(rr.data().to_string(), "example.test.");
        for value in ["external.invalid.", "."] {
            let input = record(DnsRecordType::Srv, &format!("0 0 0 {value}"));
            assert!(compile_zone(&zone(vec![input])).is_ok());
        }
        let mut wildcard = record(DnsRecordType::A, "192.0.2.1");
        wildcard.name = "*.example.test.".into();
        let mut input = zone(vec![wildcard]);
        input.ttl = None;
        let parsed = compile_zone(&input).unwrap();
        assert_eq!(parsed.records.values().next().unwrap().ttl(), 0);
        assert!(
            compile_zone(&zone(vec![
                record(DnsRecordType::A, "192.0.2.1"),
                record(DnsRecordType::Cname, "target"),
            ]))
            .is_err()
        );
    }

    #[test]
    fn rdata_token_boundaries_preserve_existing_library_data() {
        use hickory_proto::serialize::txt::Parser;
        let origin: Name = "example.test.".parse().unwrap();
        for value in [
            format!("0 custom \"{}\"", "a".repeat(4092)),
            format!("0 \"custom\"\"{}\"", "a".repeat(4093)),
            format!("0 custom \"{}\"", "\\a".repeat(3000)),
            r#"0 custom "a\077b""#.into(),
        ] {
            let content = format!("$ORIGIN example.test.\n$TTL 60\nservice IN CAA {value}\n");
            let (_, existing) = Parser::new(content, None, Some(origin.clone()))
                .parse()
                .unwrap();
            let parsed = compile_zone(&zone(vec![record(DnsRecordType::Caa, &value)])).unwrap();
            assert_eq!(parsed.records, existing);
        }
        let input = record(
            DnsRecordType::Caa,
            &format!("0 custom \"{}\"", "a".repeat(4094)),
        );
        assert!(compile_zone(&zone(vec![input])).is_err());
        for target in [r"host\065label.example.test.", r"host\-label.example.test."] {
            let expected =
                RData::parse(RecordType::CNAME, [target].into_iter(), Some(&origin)).unwrap();
            let parsed = compile_zone(&zone(vec![record(DnsRecordType::Cname, target)])).unwrap();
            let actual = parsed
                .records
                .values()
                .next()
                .unwrap()
                .records_without_rrsigs()
                .next()
                .unwrap()
                .data();
            assert_eq!(actual, &expected);
        }
    }

    #[test]
    fn invalid_input_fails_with_record_field_paths() {
        for (kind, value) in [
            (DnsRecordType::A, "192.0.2.1 extra"),
            (DnsRecordType::A, "host 60 IN A 192.0.2.1"),
            (DnsRecordType::A, "192.0.2.1\nother IN A 192.0.2.2"),
            (DnsRecordType::A, "(192.0.2.1 other IN A 192.0.2.2)"),
            (DnsRecordType::A, "$ORIGIN other.test."),
            (DnsRecordType::A, "192.0.2.1 ; ignored"),
            (DnsRecordType::A, "\"unclosed"),
            (DnsRecordType::A, "("),
            (DnsRecordType::A, ")"),
            (DnsRecordType::Aaaa, "192.0.2.1"),
            (DnsRecordType::Mx, "65536 target"),
            (DnsRecordType::Hinfo, "\"cpu\" \"os\" extra"),
            (DnsRecordType::Svcb, "1 target port=443 port=444"),
            (DnsRecordType::Cname, r"host\;label.example.test."),
            (DnsRecordType::Cname, r"host\)label.example.test."),
        ] {
            let input = DnsConfigRaw {
                domain: None,
                zone: Some(vec![zone(vec![record(kind, value)])].into()),
            };
            let error = compile_dns(&input).unwrap_err().to_string();
            assert!(error.contains("dns.zone[0].records[0].value"), "{error}");
        }
        for kind in [DnsRecordType::Unspecified as i32, 65535] {
            let mut input = record(DnsRecordType::A, "192.0.2.1");
            input.r#type = kind;
            assert!(compile_zone(&zone(vec![input])).is_err());
        }
        for data in [
            None,
            Some(Data::Txt(DnsTxtData {
                segments: vec!["x".into()],
            })),
        ] {
            let mut input = record(DnsRecordType::A, "192.0.2.1");
            input.data = data;
            assert!(compile_zone(&zone(vec![input])).is_err());
        }
        assert!(compile_zone(&zone(vec![record(DnsRecordType::Txt, "\"x\"")])).is_err());
        let mut outside = record(DnsRecordType::A, "192.0.2.1");
        outside.name = "other.invalid.".into();
        assert!(
            compile_zone(&zone(vec![outside]))
                .unwrap_err()
                .to_string()
                .contains(".name")
        );
        let zones = DnsConfigRaw {
            domain: None,
            zone: Some(vec![zone(vec![]), zone(vec![])].into()),
        };
        assert!(
            compile_dns(&zones)
                .unwrap_err()
                .to_string()
                .contains("dns.zone[1].origin")
        );
    }
}
