# Local Magic DNS records

Enable Magic DNS and configure static records in the same TOML file:

```toml
[flags]
accept_dns = true

[dns]
domain = "et.net."

[[dns.zone]]
origin = "et.net."
ttl = 60
records = [
    { name = "nas", type = "A", value = "10.0.0.8" },
    { name = "nas", type = "AAAA", value = "fd00::8" },
    { name = "files", type = "CNAME", value = "nas" },
    { name = "info", type = "TXT", value = '"local records"' },
]

[[dns.zone]]
origin = "example.test."
records = [
    { name = "service", type = "A", ttl = 120, value = "10.0.0.9" },
    { name = "@", type = "MX", value = "10 mail" },
    { name = "_sip._tcp", type = "SRV", value = "10 5 5060 sip" },
]
```

`dns.domain` controls the automatically generated node names, defaults to
`"et.net."`, and supersedes the deprecated `flags.tld_dns_zone`. Automatically
generated records are not part of the editable static `records` array.

## Record semantics

Each record object represents one resource record. `name` and `type` are required.
The DNS class is always IN. The `value` contains only the type's RDATA, without
an owner, TTL, class or type prefix. For example, MX uses `"10 mail"` and SRV uses
`"10 5 5060 sip"`. Quoting and escaping inside these compound values follow the
DNS library's presentation syntax. Zone directives, comments, additional records
and unused trailing tokens are rejected.

Supported types are A, AAAA, ANAME, CAA, CERT, CNAME, CSYNC, HINFO, HTTPS, MX,
NAPTR, NS, OPENPGPKEY, PTR, SOA, SRV, SSHFP, SVCB, TLSA and TXT. This input
support does not add DNSSEC or ANAME resolution.

`origin` must be a non-root DNS name. A trailing dot is optional on the zone
origin. Origins must be unique within one instance's configuration after
normalization. Record names without a trailing dot are relative to the origin;
`@` names the origin itself. Absolute owner names must belong to the zone.
Underscores and wildcard owner names retain their DNS meaning.

Domain-name fields inside RDATA follow the same relative/absolute rules, including
`@` for the origin. Absolute targets may point outside the zone. `"."` is accepted
where the record type permits a root target. SOA's mailbox field uses DNS name
syntax, not `user@example.com`. Text fields such as TXT segments, CAA properties
and NAPTR regular expressions are not expanded as domain names.

The optional `ttl` fields use seconds. A record without a TTL inherits its zone's
TTL, and a zone without a TTL defaults to zero. Explicit zero is preserved.
Records with the same owner and type form one RRset and must have the same
effective TTL. Multiple values are allowed except for the library's single-value
types such as CNAME, ANAME and SOA. Duplicate RDATA and CNAME conflicts are errors.
SOA records must use the zone origin. A CNAME at the origin is rejected because
every authoritative zone needs its own SOA.

Input order, relative names and omitted TTLs are preserved when saving the
configuration. DNS answers do not promise RRset value order. Runtime comparison
uses parsed data, so rearranging an RRset or changing domain-name case does not
change its meaning.

## TXT records

TXT uses the same `value` field as other record types:

```toml
[[dns.zone.records]]
name = "info"
type = "TXT"
value = '"quote\" slash\\ ;" "" "tail"'
```

Each quoted string becomes one UTF-8 DNS character-string of at most 255 bytes.
There must be at least one string; an empty string is allowed. Strings are
ordered and are never split or combined automatically. To configure two TXT
records, add two record objects.

The example uses a TOML literal string to preserve DNS quotes and escapes.
DNS presentation escaping still applies inside `value`, as it does for HINFO
and NAPTR. JSON and TOML basic strings also apply their own escaping rules.

## Configuration and management

The file and management API share `core_config.DnsConfigRaw`, including the
record enum and the `value` field. Management JSON uses the same field names
and transparent collection arrays:

```json
{
  "dns": {
    "zone": [{
      "origin": "example.test.",
      "ttl": 60,
      "records": [
        {"name": "nas", "type": "A", "value": "192.0.2.1"},
        {"name": "info", "type": "TXT", "value": "\"first\" \"second\""}
      ]
    }]
  }
}
```

An omitted collection and an explicit empty array remain distinct in the input.
The collection wrappers are `RepeatedDnsZoneConfigRaw` and `RepeatedDnsRecordRaw`;
their protobuf `items` fields are transparent in file/management JSON.

File input, management configuration generation and native DNS startup use the
same core compiler. Validation happens before a candidate configuration is
accepted and reports paths such as `dns.zone[0].records[1].value`. Compound
RDATA errors identify `value`, rather than separate MX/SRV subfields. Existing
management error responses carry these paths and the parser's explanation.

`ConfigRpc.PatchConfig` and `easytier-cli dns set --file dns.toml` patch a running
instance. An omitted `dns` or child field preserves its saved value. A supplied
zone array replaces that instance's static zones; `zone: []` or `dns clear`
clears them while retaining its default domain and automatic node records.
`dns show` and `ConfigRpc.GetConfig` read saved configuration.

Successful saving does not confirm publication. The existing 500 ms loop sends
the complete contribution to the elected server asynchronously. Concurrent full
edits can overwrite each other. Records do not have IDs or individual CRUD
operations; this model adds neither configuration CAS nor a publication ACK
state machine.

Web keeps the original desired configuration when a connected core does not
advertise DNS configuration support. For that heartbeat, startup, patch planning,
readback comparison and runtime caches omit the unsupported `dns` field. Other
configuration still converges, and an applied revision means its supported fields
were applied. Once a core advertises support, the retained DNS configuration
participates in strict comparison and reconciliation again. This does not infer
capabilities from an offline device or add a frontend notice.

## Runtime boundary

All connected local instances contribute, including Web-managed and standalone
instances. The elected server aggregates equal normalized origins into one zone.
Different origins remain separate authoritative zones, selected by the longest
matching suffix. There is no fallback to a parent zone after a negative answer.
For example, `db.dev` in `corp.test` is hidden while a `dev.corp.test` zone
exists, even if the child only contains `api`. To add names without creating this
boundary, put them in the same origin.

Conflicts are resolved per name and RRset, so unrelated records and route
updates still take effect:

- A, AAAA and PTR values are combined across instances and deduplicated by
  canonical RDATA. Automatic A records participate in the same address set.
- Other types keep one instance's complete RRset. Identical sets are deduplicated;
  differing sets use the lowest normalized instance UUID. Multi-valued sets
  within one configuration remain supported. This is a conservative merge
  policy, not a claim that DNS forbids those types from having multiple values:
  combining TXT can create two SPF policies, MX can mix Null MX with mail servers,
  service records can change selection, and certificate records can broaden trust.
- A CNAME cannot coexist with other types at its name. Manual contributions take
  precedence over automatic node records, then the lowest instance UUID wins.
  ANAME remains a singleton RRset and can coexist with other non-CNAME types;
  this does not add ANAME address substitution.
- Compatible sources use their minimum TTL for every record in the effective
  RRset. Suppressed sources do not change it. Thus a static A merged with an
  automatic A has TTL 1; saved TTLs remain unchanged.
- One explicit SOA wins by UUID, independent of its serial. A default SOA is
  generated only when no instance supplies one. Its original serial and timers
  are preserved, including negative-cache settings; serials are not incremented.
  NS records do not choose an instance or introduce delegation machinery.

Disconnect withdraws the connection's contribution and recomputes winners.
Clearing static zones leaves its node records intact. Election rebuilds the state
from republished contributions, so availability and winners can change while
members reconnect. DNS caches can retain old answers until their TTL expires.
The established empty default route zones remain authoritative after withdrawal.
Static-only zones are removed when their last contributor leaves. Records are
not distributed to other machines.

The system resolver match list includes all contributed default and static
origins, after the elected instance's default search domain. A name missing from
its selected zone does not fall back to system DNS. Queries outside local zones
retain the existing forwarding behavior.

Use `easytier-cli --instance-id <uuid> dns status` or
`ConfigRpc.GetDnsStatus` with the existing instance selector to inspect a current
server snapshot. `saved_config_matches_contribution` compares the saved DNS
configuration with that server's accepted contribution; it is false while a
new save is awaiting publication or no contribution has been observed. It does
not mean every saved record won conflict resolution. Each contributed RRset
shows requested values, actual selected authority, records at that name and
suppression, merge or TTL notices. Zone apex records include the selected SOA.
Only names and zones contributed by the selected instance are enumerated.

These are published authority records, not final recursive query results:
CNAME chains, wildcard matching, ANAME behavior and client caches still affect
queries. A child-zone notice explains when a record is present in the parent
authority but unreachable through that parent. DNS being disabled, an unavailable
server or an election gap is reported as unavailable, not as synchronous save
failure. This query does not change `GetConfig` or Web's saved-config readback.

This does not change Magic DNS activation, the fixed DNS address, TUN
requirements, platform DNS setup or node record RPC. Systems without automatic
DNS setup must continue to configure their resolver manually.
