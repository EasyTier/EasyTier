# Local Magic DNS records

Configure records through a TOML file. Enable Magic DNS as before and add
static records using DNS zone file syntax:

```toml
[flags]
accept_dns = true

[[dns.zone]]
origin = "et.net."
ttl = 60
records = [
    "nas IN A 10.0.0.8",
    "nas IN AAAA fd00::8",
    "files IN CNAME nas",
    'info IN TXT "local records"',
]

[[dns.zone]]
origin = "example.test."
records = ["service 120 IN A 10.0.0.9"]
```

`origin` must be a non-root DNS name. Record names are relative to it;
absolute names must belong to that zone.
`ttl` supplies the default TTL in seconds, or zero when omitted. Individual
records may specify their own TTL. Zone file directives such as `$INCLUDE` are
not accepted.

Static records come from the local configuration of the EasyTier instance that
wins the local Magic DNS server election. They coexist with automatically
generated node records and survive route updates. Configuration changes take
effect when the instance restarts. If the elected instance has no `[dns]`
configuration, no static records are served, even when another local instance
has some. Records are not distributed to other machines.

Only the elected instance's configured zones are added to the system resolver
match list, after the default zone. Zones configured by other local instances
are neither served nor used for system name resolution.

Configured zones are authoritative: a name missing from a configured zone does
not fall back to system DNS. Queries outside those zones retain the existing
system DNS forwarding behavior. This does not change Magic DNS activation,
the fixed DNS address, TUN requirements, or platform DNS setup. Systems without
automatic DNS setup must continue to configure their resolver manually.

## Migration and configuration definitions

The file and management API share `core_config.DnsConfigRaw`. `NetworkConfig.dns`
uses field 77. These DNS inputs were not released as a public string contract.
The local `UpdateDnsRecordRequest` is unchanged: static records stay local to the
server instance and are never carried over RPC.

Optional arrays use reusable messages: `common.RepeatedString` for record strings and
`core_config.RepeatedDnsZoneConfigRaw` for zones. An absent wrapper means the array was
omitted; a present wrapper with no items means an explicit empty array. TOML still
uses `[[dns.zone]]`, `zone = []`, and `records = []`. The collection wrappers use
ordinary Serde with `serde(transparent)`. Both `DnsConfigRaw` and
`DnsZoneConfigRaw` use pbjson and delegate their collection fields to these
transparent wrappers. TOML and DNS management JSON both use `zone`, with no
field renaming:

```json
{"dns":{"zone":[{"origin":"example.test.","ttl":0,"records":["nas IN A 192.0.2.1"]}]}}
```

The protobuf field numbers, field types and wrapper nesting define the binary
contract. The DNS root uses zone at tag 2; each zone uses origin 1, ttl 2 and
records 3; collection wrappers use items at tag 1. This leaves the root's tag 1
available for activation in dns-policy. A future configuration generator can rename
helper messages while preserving this layout. Existing TOML and JSON field names
remain part of their respective formats.

`ConfigLoader::get_dns` and `set_dns` now use this Raw message directly. Native
DNS input is parsed directly into runtime records. Defaults, collection unwrapping,
domain normalization and record validation stay in the native DNS parser. Management
projections and browser form merging preserve the Raw collection presence.

When replacing the legacy DNS runtime, replace the interim
`ConfigLoader::get_dns`/`set_dns` methods and their internal call sites as needed.
dns-policy removes the legacy `magic_dns.proto` along with the old DNS server;
its node RPC and zone distribution protocol replace this local transport. This
interim feature does not extend that transport.

The existing `accept_dns` switch and this interim runtime's authoritative-zone
behavior remain in use for now. On migration, the full DNS implementation and
the shared definition own activation and fallthrough defaults; these temporary
behaviors are not additional compatibility requirements for that implementation.
