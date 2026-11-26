use super::socket_protector::physical_dns_servers;
use super::{ASYNC_RUNTIME, INSTANCE_MANAGER};
use async_trait::async_trait;
use easytier::common::config::ConfigLoader;
use easytier_core::config::dns::{DnsZone, compile_dns, parse_origin};
use easytier_core::gateway::magic_dns::{
    MagicDnsQuery, MagicDnsQueryResolver, MagicDnsQueryResult, MagicDnsResolverRegistration,
    MagicDnsRouteSource, dns_domain,
};
use hickory_proto::op::{Edns, Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{LowerName, Name, RData, Record, RecordSet, RecordType, RrKey};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable, BinEncoder};
use once_cell::sync::Lazy;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use uuid::Uuid;

pub const MAGIC_DNS_FAKE_IP: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 101);
const MAX_CNAME_CHAIN_DEPTH: usize = 8;
// RFC 9715 IPv4/UDP unfragmented payload budget so packet-plane replies fit both
// 1380-byte (:vpn) and 1500-byte (L3 TUN) MTUs cleanly.
const MAX_PACKET_PLANE_EDNS_UDP_PAYLOAD: u16 = 1232;
const UPSTREAM_RECV_BUF_SIZE: usize = 4096;
const UPSTREAM_FORWARD_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalDnsState {
    pub running: bool,
    pub server_ip: String,
    pub zones: Vec<String>,
    pub record_count: usize,
    pub query_count: u64,
    pub hit_count: u64,
}

#[derive(Clone, Debug)]
struct ZoneData {
    origin: LowerName,
    records: BTreeMap<RrKey, RecordSet>,
    owner_names: BTreeSet<LowerName>,
    soa: Record,
}

#[derive(Clone, Debug, Default)]
struct DnsCatalog {
    zones: BTreeMap<LowerName, ZoneData>,
    zone_strings: Vec<String>,
    record_count: usize,
}

static DNS_CATALOG: Lazy<RwLock<Arc<DnsCatalog>>> =
    Lazy::new(|| RwLock::new(Arc::new(DnsCatalog::default())));
static QUERY_COUNT: AtomicU64 = AtomicU64::new(0);
static HIT_COUNT: AtomicU64 = AtomicU64::new(0);
static CUSTOM_UPSTREAM_SERVERS: Lazy<RwLock<Vec<SocketAddr>>> =
    Lazy::new(|| RwLock::new(Vec::new()));
static PACKET_REGISTRATIONS: Lazy<Mutex<HashMap<Uuid, MagicDnsResolverRegistration>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static REFRESH_LOCK: Lazy<tokio::sync::Mutex<()>> = Lazy::new(|| tokio::sync::Mutex::new(()));

fn parse_dns_server_addr(raw: &str) -> Option<SocketAddr> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(sa) = trimmed.parse::<SocketAddr>() {
        return Some(sa);
    }
    if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        return Some(SocketAddr::new(ip, 53));
    }
    None
}

pub fn set_custom_dns_servers(servers: Vec<String>) {
    let parsed: Vec<SocketAddr> = servers
        .iter()
        .filter_map(|s| parse_dns_server_addr(s))
        .collect();
    if let Ok(mut guard) = CUSTOM_UPSTREAM_SERVERS.write() {
        *guard = parsed;
    }
}

pub fn local_dns_state() -> LocalDnsState {
    let catalog = DNS_CATALOG.read().map(|g| g.clone()).unwrap_or_default();
    let has_registrations = PACKET_REGISTRATIONS
        .lock()
        .ok()
        .is_some_and(|g| !g.is_empty());
    LocalDnsState {
        running: has_registrations && !catalog.zones.is_empty(),
        server_ip: MAGIC_DNS_FAKE_IP.to_string(),
        zones: catalog.zone_strings.clone(),
        record_count: catalog.record_count,
        query_count: QUERY_COUNT.load(Ordering::Relaxed),
        hit_count: HIT_COUNT.load(Ordering::Relaxed),
    }
}

fn default_soa_record(origin: &LowerName) -> Record {
    let origin_name = Name::from(origin);
    let mname = Name::from_str(&format!("ns.{origin}")).unwrap_or_else(|_| origin_name.clone());
    let rname =
        Name::from_str(&format!("hostmaster.{origin}")).unwrap_or_else(|_| origin_name.clone());
    let soa = SOA::new(mname, rname, 2023101001, 7200, 3600, 1209600, 60);
    Record::from_rdata(origin_name, 60, RData::SOA(soa))
}

fn sanitize_hostname_label(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let cleaned: String = trimmed
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '.' {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    let cleaned = cleaned.trim_matches(|c| c == '-' || c == '.');
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.to_string())
    }
}

fn build_auto_host_name(hostname: &str, origin: &LowerName) -> Option<Name> {
    let raw_fqdn = format!("{hostname}.{origin}");
    if let Ok(mut name) = Name::from_str(&raw_fqdn) {
        name.set_fqdn(true);
        let lower = name.to_lowercase();
        if Name::from(origin).zone_of(&lower) {
            return Some(lower);
        }
    }
    let sanitized = sanitize_hostname_label(hostname)?;
    let fallback_fqdn = format!("{sanitized}.{origin}");
    let mut name = Name::from_str(&fallback_fqdn).ok()?;
    name.set_fqdn(true);
    let lower = name.to_lowercase();
    Name::from(origin).zone_of(&lower).then_some(lower)
}

#[derive(Default)]
struct ZoneContribution {
    auto_domain: Option<LowerName>,
    auto_hosts: Vec<(String, Ipv4Addr)>,
    configured_zones: BTreeMap<LowerName, DnsZone>,
}

fn build_catalog_from_contributions(contributions: Vec<ZoneContribution>) -> DnsCatalog {
    let mut origins: BTreeSet<LowerName> = BTreeSet::new();
    let mut configured_merged: BTreeMap<LowerName, BTreeMap<RrKey, RecordSet>> = BTreeMap::new();
    let mut auto_by_origin: BTreeMap<LowerName, Vec<(String, Ipv4Addr)>> = BTreeMap::new();

    for contrib in contributions {
        if let Some(domain) = contrib.auto_domain {
            origins.insert(domain.clone());
            auto_by_origin
                .entry(domain)
                .or_default()
                .extend(contrib.auto_hosts);
        }
        for (origin, zone) in contrib.configured_zones {
            origins.insert(origin.clone());
            let target = configured_merged.entry(origin).or_default();
            for (key, incoming) in zone.records {
                let cname_conflict = if key.record_type == RecordType::CNAME {
                    target.keys().any(|existing| {
                        existing.name == key.name && existing.record_type != RecordType::CNAME
                    })
                } else {
                    target.contains_key(&RrKey::new(key.name.clone(), RecordType::CNAME))
                };
                if cname_conflict {
                    continue;
                }
                match target.get_mut(&key) {
                    None => {
                        target.insert(key, incoming);
                    }
                    Some(current) => {
                        if matches!(
                            key.record_type,
                            RecordType::CNAME | RecordType::ANAME | RecordType::SOA
                        ) {
                            continue;
                        }
                        for rec in incoming.records_without_rrsigs() {
                            current.insert(rec.clone(), 0);
                        }
                    }
                }
            }
        }
    }

    let mut zones: BTreeMap<LowerName, ZoneData> = BTreeMap::new();
    let mut total_records = 0usize;

    for origin in origins {
        let mut records: BTreeMap<RrKey, RecordSet> =
            configured_merged.remove(&origin).unwrap_or_default();

        // Merge automatic MagicDNS A records (respecting configured CNAME & A TTLs).
        if let Some(hosts) = auto_by_origin.remove(&origin) {
            for (hostname, ipv4) in hosts {
                let Some(fqdn) = build_auto_host_name(&hostname, &origin) else {
                    continue;
                };
                let owner = LowerName::new(&fqdn);
                if records.contains_key(&RrKey::new(owner.clone(), RecordType::CNAME)) {
                    continue;
                }
                let key = RrKey::new(owner, RecordType::A);
                let ttl = records.get(&key).map(|set| set.ttl()).unwrap_or(1);
                let rec = Record::from_rdata(fqdn.clone(), ttl, RData::A(A(ipv4)));
                let set = records
                    .entry(key)
                    .or_insert_with(|| RecordSet::new(fqdn, RecordType::A, 0));
                set.insert(rec, 0);
            }
        }

        // Ensure SOA exists for authoritative NXDOMAIN / NODATA responses.
        let soa_key = RrKey::new(origin.clone(), RecordType::SOA);
        let soa = if let Some(existing_soa) = records
            .get(&soa_key)
            .and_then(|set| set.records_without_rrsigs().next())
            .cloned()
        {
            existing_soa
        } else {
            let synthesized = default_soa_record(&origin);
            let mut set = RecordSet::new(Name::from(&origin), RecordType::SOA, 0);
            set.insert(synthesized.clone(), 0);
            records.insert(soa_key, set);
            synthesized
        };

        let mut owner_names = BTreeSet::new();
        for (key, set) in &records {
            owner_names.insert(key.name.clone());
            total_records += set.records_without_rrsigs().count();
        }

        zones.insert(
            origin.clone(),
            ZoneData {
                origin,
                records,
                owner_names,
                soa,
            },
        );
    }

    let zone_strings = zones
        .keys()
        .map(|origin| origin.to_string().trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    DnsCatalog {
        zones,
        zone_strings,
        record_count: total_records,
    }
}

impl DnsCatalog {
    fn find_zone(&self, qname: &LowerName) -> Option<&ZoneData> {
        let mut candidate = qname.clone();
        loop {
            if let Some(zone) = self.zones.get(&candidate) {
                return Some(zone);
            }
            if candidate.is_root() {
                return None;
            }
            candidate = candidate.base_name();
        }
    }

    fn is_empty_non_terminal(zone: &ZoneData, qname: &LowerName) -> bool {
        let q_name = Name::from(qname);
        zone.owner_names
            .iter()
            .any(|owner| owner != qname && q_name.zone_of(&Name::from(owner)))
    }

    fn lookup_owner_in_zone(
        zone: &ZoneData,
        lookup_owner: &LowerName,
        reply_owner: Option<&Name>,
        qtype: RecordType,
    ) -> Option<ZoneLookupOutcome> {
        let has_any = zone.owner_names.contains(lookup_owner);
        if !has_any {
            return None;
        }
        let rewrite = |set: &RecordSet| -> Vec<Record> {
            set.records_without_rrsigs()
                .map(|rec| {
                    let mut cloned = rec.clone();
                    if let Some(name) = reply_owner {
                        cloned.set_name(name.clone());
                    }
                    cloned
                })
                .collect()
        };

        if qtype == RecordType::ANY {
            let mut all = Vec::new();
            for (k, set) in &zone.records {
                if &k.name == lookup_owner {
                    all.extend(rewrite(set));
                }
            }
            return Some(ZoneLookupOutcome::Records(all));
        }

        if let Some(set) = zone.records.get(&RrKey::new(lookup_owner.clone(), qtype)) {
            return Some(ZoneLookupOutcome::Records(rewrite(set)));
        }

        if let Some(cname_set) = zone
            .records
            .get(&RrKey::new(lookup_owner.clone(), RecordType::CNAME))
        {
            return Some(ZoneLookupOutcome::Cname(rewrite(cname_set)));
        }

        Some(ZoneLookupOutcome::NoData)
    }

    fn resolve_within_catalog(
        &self,
        qname: &LowerName,
        qtype: RecordType,
    ) -> Option<AuthoritativeAnswer> {
        let zone = self.find_zone(qname)?;
        let initial = self.lookup_single(zone, qname, qtype);
        match initial {
            SingleLookup::Records(records) => Some(AuthoritativeAnswer {
                rcode: ResponseCode::NoError,
                answers: records,
                authority: Vec::new(),
            }),
            SingleLookup::NoData => Some(AuthoritativeAnswer {
                rcode: ResponseCode::NoError,
                answers: Vec::new(),
                authority: vec![zone.soa.clone()],
            }),
            SingleLookup::NxDomain => Some(AuthoritativeAnswer {
                rcode: ResponseCode::NXDomain,
                answers: Vec::new(),
                authority: vec![zone.soa.clone()],
            }),
            SingleLookup::Cname(first_cnames) => {
                if qtype == RecordType::CNAME {
                    return Some(AuthoritativeAnswer {
                        rcode: ResponseCode::NoError,
                        answers: first_cnames,
                        authority: Vec::new(),
                    });
                }
                let mut answers = first_cnames.clone();
                let mut visited: HashSet<LowerName> = HashSet::from([qname.clone()]);
                let mut current_records = first_cnames;
                for _ in 0..MAX_CNAME_CHAIN_DEPTH {
                    let Some(target_name) = current_records
                        .first()
                        .and_then(|rec| rec.data().as_cname())
                        .map(|cname| LowerName::from(&cname.0))
                    else {
                        break;
                    };
                    if !visited.insert(target_name.clone()) {
                        break;
                    }
                    let Some(next_zone) = self.find_zone(&target_name) else {
                        break;
                    };
                    match self.lookup_single(next_zone, &target_name, qtype) {
                        SingleLookup::Records(recs) => {
                            answers.extend(recs);
                            break;
                        }
                        SingleLookup::Cname(next_cnames) => {
                            answers.extend(next_cnames.clone());
                            current_records = next_cnames;
                        }
                        SingleLookup::NoData | SingleLookup::NxDomain => {
                            break;
                        }
                    }
                }
                Some(AuthoritativeAnswer {
                    rcode: ResponseCode::NoError,
                    answers,
                    authority: Vec::new(),
                })
            }
        }
    }

    fn lookup_single(&self, zone: &ZoneData, qname: &LowerName, qtype: RecordType) -> SingleLookup {
        if let Some(exact) = Self::lookup_owner_in_zone(zone, qname, None, qtype) {
            return match exact {
                ZoneLookupOutcome::Records(r) => SingleLookup::Records(r),
                ZoneLookupOutcome::Cname(c) => SingleLookup::Cname(c),
                ZoneLookupOutcome::NoData => SingleLookup::NoData,
            };
        }

        if Self::is_empty_non_terminal(zone, qname) {
            return SingleLookup::NoData;
        }

        // RFC 4592 wildcard synthesis: walk closest encloser labels inside `zone.origin`.
        let reply_name = Name::from(qname);
        let origin_name = Name::from(&zone.origin);
        let mut parent = qname.base_name();
        while origin_name.zone_of(&Name::from(&parent)) {
            if let Ok(wild_name) = Name::from_str(&format!("*.{parent}")) {
                let wild_lower = LowerName::new(&wild_name);
                if let Some(hit) =
                    Self::lookup_owner_in_zone(zone, &wild_lower, Some(&reply_name), qtype)
                {
                    return match hit {
                        ZoneLookupOutcome::Records(r) => SingleLookup::Records(r),
                        ZoneLookupOutcome::Cname(c) => SingleLookup::Cname(c),
                        ZoneLookupOutcome::NoData => SingleLookup::NoData,
                    };
                }
            }
            if parent == zone.origin || parent.is_root() {
                break;
            }
            parent = parent.base_name();
        }

        SingleLookup::NxDomain
    }
}

enum ZoneLookupOutcome {
    Records(Vec<Record>),
    Cname(Vec<Record>),
    NoData,
}

enum SingleLookup {
    Records(Vec<Record>),
    Cname(Vec<Record>),
    NoData,
    NxDomain,
}

struct AuthoritativeAnswer {
    rcode: ResponseCode,
    answers: Vec<Record>,
    authority: Vec<Record>,
}

fn encode_dns_response(request: &Message, answer: AuthoritativeAnswer) -> Option<Vec<u8>> {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_authoritative(true);
    response.set_recursion_desired(request.recursion_desired());
    response.set_recursion_available(false);
    response.set_response_code(answer.rcode);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    for rec in answer.answers {
        response.add_answer(rec);
    }
    for rec in answer.authority {
        response.add_name_server(rec);
    }
    let max_size = if let Some(req_edns) = request.extensions() {
        let mut resp_edns = Edns::new();
        let advertised = req_edns
            .max_payload()
            .clamp(512, MAX_PACKET_PLANE_EDNS_UDP_PAYLOAD);
        resp_edns.set_max_payload(advertised);
        response.set_edns(resp_edns);
        advertised
    } else {
        512
    };

    let mut out = Vec::with_capacity(512);
    let mut encoder = BinEncoder::new(&mut out);
    encoder.set_max_size(max_size);
    if response.emit(&mut encoder).is_ok() {
        return Some(out);
    }

    // Retry with TC=1 and empty answer/authority if response exceeded max UDP payload.
    let mut truncated = Message::new();
    truncated.set_id(request.id());
    truncated.set_message_type(MessageType::Response);
    truncated.set_op_code(request.op_code());
    truncated.set_authoritative(true);
    truncated.set_truncated(true);
    truncated.set_recursion_desired(request.recursion_desired());
    truncated.set_response_code(answer.rcode);
    for query in request.queries() {
        truncated.add_query(query.clone());
    }
    truncated.to_vec().ok()
}

fn encode_error_response(request: &Message, rcode: ResponseCode) -> Option<Vec<u8>> {
    let mut response = Message::new();
    response.set_id(request.id());
    response.set_message_type(MessageType::Response);
    response.set_op_code(request.op_code());
    response.set_recursion_desired(request.recursion_desired());
    response.set_response_code(rcode);
    for query in request.queries() {
        response.add_query(query.clone());
    }
    response.to_vec().ok()
}

/// Resolves a raw DNS wire query against the current authoritative catalog.
/// Returns `Ok(Some(bytes))` if handled authoritatively, `Ok(None)` if outside local zones.
pub fn resolve_authoritative_query(payload: &[u8]) -> Option<Vec<u8>> {
    QUERY_COUNT.fetch_add(1, Ordering::Relaxed);
    let request = Message::from_bytes(payload).ok()?;
    if request.op_code() != OpCode::Query {
        return encode_error_response(&request, ResponseCode::NotImp);
    }
    let query = request.queries().first()?;
    let qname = LowerName::new(query.name());
    let qtype = query.query_type();

    let catalog = DNS_CATALOG.read().ok()?.clone();
    let answer = catalog.resolve_within_catalog(&qname, qtype)?;
    HIT_COUNT.fetch_add(1, Ordering::Relaxed);
    encode_dns_response(&request, answer)
}

async fn forward_dns_upstream(payload: &[u8]) -> Option<Vec<u8>> {
    let mut servers: Vec<SocketAddr> = CUSTOM_UPSTREAM_SERVERS
        .read()
        .map(|g| g.clone())
        .unwrap_or_default();
    if servers.is_empty() {
        servers = physical_dns_servers();
    }
    if servers.is_empty() {
        servers.push(SocketAddr::from(([223, 5, 5, 5], 53)));
        servers.push(SocketAddr::from(([180, 184, 1, 1], 53)));
    }
    for upstream in servers.into_iter().take(3) {
        let bind_addr: SocketAddr = if upstream.is_ipv6() {
            SocketAddr::from(([0u16; 8], 0))
        } else {
            SocketAddr::from(([0, 0, 0, 0], 0))
        };
        let Ok(sock) = UdpSocket::bind(bind_addr).await else {
            continue;
        };
        #[cfg(unix)]
        if !upstream.ip().is_loopback() {
            use std::os::fd::AsRawFd;
            if super::socket_protector::protect_raw_fd_if_enabled(sock.as_raw_fd()).is_err() {
                continue;
            }
        }
        if sock.send_to(payload, upstream).await.is_err() {
            continue;
        }
        let mut buf = vec![0u8; UPSTREAM_RECV_BUF_SIZE];
        if let Ok(Ok((len, _))) =
            tokio::time::timeout(UPSTREAM_FORWARD_TIMEOUT, sock.recv_from(&mut buf)).await
            && len >= 12
        {
            buf.truncate(len);
            return Some(buf);
        }
    }
    None
}

fn encode_servfail_for_payload(payload: &[u8]) -> Option<Vec<u8>> {
    Message::from_bytes(payload)
        .ok()
        .and_then(|msg| encode_error_response(&msg, ResponseCode::ServFail))
}

struct LocalPacketPlaneDnsResolver;

#[async_trait]
impl MagicDnsQueryResolver for LocalPacketPlaneDnsResolver {
    async fn resolve(&self, query: MagicDnsQuery) -> MagicDnsQueryResult {
        if let Some(local_resp) = resolve_authoritative_query(&query.payload) {
            return MagicDnsQueryResult::Response(Some(local_resp));
        }
        let Some(overload_response) = encode_servfail_for_payload(&query.payload) else {
            return MagicDnsQueryResult::Response(None);
        };
        MagicDnsQueryResult::Forward {
            response: Box::pin(async move { forward_dns_upstream(&query.payload).await }),
            overload_response,
        }
    }

    fn overload_response(&self, query: &MagicDnsQuery) -> Option<Vec<u8>> {
        encode_servfail_for_payload(&query.payload)
    }
}

pub async fn unregister_instance_packet_dns(instance_id: Uuid) {
    let reg = PACKET_REGISTRATIONS
        .lock()
        .ok()
        .and_then(|mut guard| guard.remove(&instance_id));
    if let Some(reg) = reg {
        reg.close().await;
    }
}

pub async fn clear_all_packet_dns() {
    let regs: Vec<MagicDnsResolverRegistration> = PACKET_REGISTRATIONS
        .lock()
        .ok()
        .map(|mut guard| guard.drain().map(|(_, v)| v).collect())
        .unwrap_or_default();
    for reg in regs {
        reg.close().await;
    }
}

/// Rebuilds the in-memory authoritative DNS catalog from all running EasyTier instances
/// and keeps the packet-plane resolver (`100.100.100.101`) synchronized.
/// Returns `true` if the set of authoritative zone origins changed.
pub async fn refresh_all_async() -> bool {
    let _guard = REFRESH_LOCK.lock().await;
    let instance_ids = INSTANCE_MANAGER.instance_ids();

    let mut contributions = Vec::new();
    let mut active_dns_instances: Vec<Uuid> = Vec::new();

    for id in instance_ids {
        let Some(cfg) = INSTANCE_MANAGER.config(id) else {
            continue;
        };
        let magic_dns_on = cfg.get_flags().accept_dns;
        let dns_cfg = cfg.get_dns();
        let configured_zones = dns_cfg
            .as_ref()
            .and_then(|d| compile_dns(d).ok())
            .unwrap_or_default();
        let has_custom_zones = !configured_zones.is_empty();

        if !magic_dns_on && !has_custom_zones {
            continue;
        }
        active_dns_instances.push(id);

        let mut contrib = ZoneContribution {
            auto_domain: None,
            auto_hosts: Vec::new(),
            configured_zones,
        };

        if magic_dns_on && let Ok(domain) = dns_domain(&cfg).or_else(|_| parse_origin("et.net")) {
            if let Some(instance) = INSTANCE_MANAGER.instance(id) {
                let snapshot = instance.packet_plane().snapshot().await;
                for route in snapshot.routes {
                    if route.hostname.trim().is_empty() {
                        continue;
                    }
                    if let Some(ip) = route
                        .ipv4_addr
                        .and_then(|inet| inet.address)
                        .map(Ipv4Addr::from)
                    {
                        contrib.auto_hosts.push((route.hostname, ip));
                    }
                }
            }
            contrib.auto_domain = Some(domain);
        }
        contributions.push(contrib);
    }

    let active_dns_id_set: HashSet<Uuid> = active_dns_instances.iter().copied().collect();
    let stale_ids: Vec<Uuid> = PACKET_REGISTRATIONS
        .lock()
        .ok()
        .map(|guard| {
            guard
                .keys()
                .filter(|id| !active_dns_id_set.contains(id))
                .copied()
                .collect()
        })
        .unwrap_or_default();
    for id in stale_ids {
        unregister_instance_packet_dns(id).await;
    }

    let new_catalog = Arc::new(build_catalog_from_contributions(contributions));
    let old_zones = DNS_CATALOG
        .read()
        .map(|g| g.zone_strings.clone())
        .unwrap_or_default();

    if let Ok(mut guard) = DNS_CATALOG.write() {
        *guard = new_catalog.clone();
    }

    if new_catalog.zones.is_empty() {
        clear_all_packet_dns().await;
    } else {
        // Register the packet-plane resolver (100.100.100.101) for each DNS-active instance
        // (shared by both ProxyHub L3 TUN and standalone :vpn modes).
        for id in active_dns_instances {
            let already = PACKET_REGISTRATIONS
                .lock()
                .ok()
                .is_some_and(|g| g.contains_key(&id));
            if already {
                continue;
            }
            if let Some(instance) = INSTANCE_MANAGER.instance(id) {
                let reg = instance
                    .packet_plane()
                    .register_magic_dns_resolver(
                        MAGIC_DNS_FAKE_IP,
                        Arc::new(LocalPacketPlaneDnsResolver),
                    )
                    .await;
                if let Ok(mut guard) = PACKET_REGISTRATIONS.lock() {
                    guard.insert(id, reg);
                }
            }
        }
    }

    old_zones != new_catalog.zone_strings
}

pub fn refresh_all_sync() -> bool {
    ASYNC_RUNTIME.block_on(refresh_all_async())
}

pub fn stop_all_sync() {
    ASYNC_RUNTIME.block_on(async {
        let _guard = REFRESH_LOCK.lock().await;
        clear_all_packet_dns().await;
        if let Ok(mut guard) = DNS_CATALOG.write() {
            *guard = Arc::new(DnsCatalog::default());
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use easytier::proto::core_config::{DnsRecordRaw, DnsRecordType};
    use easytier_core::config::toml::{DnsConfig, DnsZoneConfig};
    use hickory_proto::op::Query;

    fn make_query(name: &str, rtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(0x1234);
        msg.set_recursion_desired(true);
        msg.add_query(Query::query(Name::from_str(name).unwrap(), rtype));
        msg.to_vec().unwrap()
    }

    #[test]
    fn authoritative_magic_dns_and_custom_zones_resolution() {
        let dns_cfg = DnsConfig {
            domain: Some("mesh.lan".into()),
            zone: Some(
                vec![DnsZoneConfig {
                    origin: "svc.lan".into(),
                    ttl: Some(60),
                    records: Some(
                        vec![
                            DnsRecordRaw {
                                name: "web".into(),
                                r#type: DnsRecordType::Cname as i32,
                                ttl: None,
                                value: Some("nas.mesh.lan.".into()),
                            },
                            DnsRecordRaw {
                                name: "*.app".into(),
                                r#type: DnsRecordType::A as i32,
                                ttl: Some(30),
                                value: Some("10.53.176.9".into()),
                            },
                            DnsRecordRaw {
                                name: "meta".into(),
                                r#type: DnsRecordType::Txt as i32,
                                ttl: Some(120),
                                value: Some("\"v=1\" \"role=nas\"".into()),
                            },
                        ]
                        .into(),
                    ),
                }]
                .into(),
            ),
        };
        let compiled = compile_dns(&dns_cfg).unwrap();
        let catalog = build_catalog_from_contributions(vec![ZoneContribution {
            auto_domain: Some(parse_origin("mesh.lan").unwrap()),
            auto_hosts: vec![
                ("nas".into(), Ipv4Addr::new(10, 53, 176, 2)),
                ("FrankHans-Mac-mini".into(), Ipv4Addr::new(10, 53, 176, 1)),
            ],
            configured_zones: compiled,
        }]);

        assert_eq!(catalog.zone_strings, vec!["mesh.lan", "svc.lan"]);

        // 1. MagicDNS auto host A record
        {
            let mut guard = DNS_CATALOG.write().unwrap();
            *guard = Arc::new(catalog);
        }
        let resp = Message::from_bytes(
            &resolve_authoritative_query(&make_query("nas.mesh.lan.", RecordType::A)).unwrap(),
        )
        .unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NoError);
        assert!(resp.authoritative());
        assert_eq!(resp.answers().len(), 1);
        assert_eq!(
            resp.answers()[0].data(),
            &RData::A(A(Ipv4Addr::new(10, 53, 176, 2)))
        );

        // 2. Cross-zone CNAME chain (web.svc.lan -> nas.mesh.lan -> 10.53.176.2)
        let cname_resp = Message::from_bytes(
            &resolve_authoritative_query(&make_query("web.svc.lan.", RecordType::A)).unwrap(),
        )
        .unwrap();
        assert_eq!(cname_resp.response_code(), ResponseCode::NoError);
        assert_eq!(cname_resp.answers().len(), 2);
        assert_eq!(cname_resp.answers()[0].record_type(), RecordType::CNAME);
        assert_eq!(
            cname_resp.answers()[1].data(),
            &RData::A(A(Ipv4Addr::new(10, 53, 176, 2)))
        );

        // 3. Wildcard synthesis (foo.app.svc.lan -> 10.53.176.9)
        let wild_resp = Message::from_bytes(
            &resolve_authoritative_query(&make_query("foo.app.svc.lan.", RecordType::A)).unwrap(),
        )
        .unwrap();
        assert_eq!(wild_resp.response_code(), ResponseCode::NoError);
        assert_eq!(wild_resp.answers().len(), 1);
        assert_eq!(
            wild_resp.answers()[0].name().to_string(),
            "foo.app.svc.lan."
        );
        assert_eq!(
            wild_resp.answers()[0].data(),
            &RData::A(A(Ipv4Addr::new(10, 53, 176, 9)))
        );

        // 4. TXT record
        let txt_resp = Message::from_bytes(
            &resolve_authoritative_query(&make_query("meta.svc.lan.", RecordType::TXT)).unwrap(),
        )
        .unwrap();
        assert_eq!(txt_resp.response_code(), ResponseCode::NoError);
        assert_eq!(txt_resp.answers().len(), 1);

        // 5. NODATA (AAAA for A-only record -> NoError + SOA)
        let nodata = Message::from_bytes(
            &resolve_authoritative_query(&make_query("nas.mesh.lan.", RecordType::AAAA)).unwrap(),
        )
        .unwrap();
        assert_eq!(nodata.response_code(), ResponseCode::NoError);
        assert!(nodata.answers().is_empty());
        assert_eq!(nodata.name_servers().len(), 1);

        // 6. NXDOMAIN
        let nx = Message::from_bytes(
            &resolve_authoritative_query(&make_query("missing.mesh.lan.", RecordType::A)).unwrap(),
        )
        .unwrap();
        assert_eq!(nx.response_code(), ResponseCode::NXDomain);
        assert_eq!(nx.name_servers().len(), 1);

        // 7. Non-local domain returns None
        assert!(resolve_authoritative_query(&make_query("example.com.", RecordType::A)).is_none());
    }
}
