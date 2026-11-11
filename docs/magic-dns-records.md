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
support does not add DNSSEC, ANAME resolution or change automatic SOA behavior.

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
SOA records must use the zone origin.

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

The full management operation replaces the complete configuration candidate.
`PatchConfig` also accepts `InstanceConfigPatch.dns`: omitted DNS members are
unchanged, a present `zone` array replaces all static zones, and `zone = []`
clears them while preserving the domain. An empty DNS patch changes nothing.
Record lists are replaced with their zone; records have no IDs or individual
CRUD operations. Invalid DNS is rejected before saving that DNS change.
Concurrent edits can overwrite each other. This does not add configuration
CAS or DNS publication acknowledgements.

Use `easytier-cli dns show` to read the instance's saved DNS configuration.
`easytier-cli dns set --file dns.toml` sends a DNS-only TOML patch using the
same syntax as above, without `[flags]` or other unrelated settings. For
example, `[dns]` followed by `domain = "mesh.test."` changes only the domain.
`easytier-cli dns clear` clears static zones and preserves the domain. Writes
require one instance; use `--instance-id` or `--instance-name` when necessary.
The CLI reads the configuration back before reporting success. This checks
saved configuration, not DNS answers; restart the instance to publish changes.
As with other patches, the instance's backing file is updated when configured.
For instances without a backing file, export the updated configuration and use
it on restart.

EasyTier Web keeps the desired DNS configuration in its saved configuration.
Cores advertise DNS patch support in their heartbeat. On older cores, Web
skips DNS patching and DNS readback comparisons, while continuing to apply
and verify other fields. Editing or restarting such a configuration retains
the saved DNS fields; initial startup requests still include DNS, which cores
that do not recognize the field ignore. After upgrading to a supporting core,
Web reconciles saved DNS again. An applied revision on an older core covers
only supported fields; on a supporting core it includes saved DNS, never DNS
publication. Offline editing reads the saved configuration without inferring
core capabilities. This adds no DNS form or runtime status to the Web UI.

## Runtime boundary

Static records come from the local configuration of the EasyTier instance that
wins the local Magic DNS server election. They coexist with automatically
generated node records and survive route updates. Configuration changes take
effect when the instance restarts. If the elected instance has no `[dns]`
configuration, no static records are served, even when another local instance
has some. Records are not distributed to other machines.

Only the elected instance's configured zones are added to the system resolver
match list, after the default zone. Configured zones are authoritative: a name
missing from a configured zone does not fall back to system DNS. Queries outside
those zones retain the existing forwarding behavior.

This does not change Magic DNS activation, the fixed DNS address, TUN
requirements, platform DNS setup or node record RPC. Systems without automatic
DNS setup must continue to configure their resolver manually.
