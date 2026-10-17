# Local Magic DNS records

Enable Magic DNS as before and add static records using DNS zone file syntax:

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

`origin` must be a non-root DNS domain. Record names are relative to it;
absolute names must belong to that zone.
`ttl` supplies the default TTL in seconds, or zero when omitted. Individual
records may specify their own TTL. Zone file directives such as `$INCLUDE` are
not accepted.

Records from local EasyTier instances are combined by the elected local Magic
DNS server. They coexist with automatically generated node records, survive
route updates, and are removed when their instance disconnects. Configuration
changes take effect when the instance restarts. Records are not distributed to
other machines.

Configured zones are authoritative: a name missing from a configured zone does
not fall back to system DNS. Queries outside those zones retain the existing
system DNS forwarding behavior. This does not change Magic DNS activation,
the fixed DNS address, TUN requirements, or platform DNS setup. Systems without
automatic DNS setup must continue to configure their resolver manually.

## Migration to dns-policy

The management API uses the same `optional string dns = 73` as dns-policy:
the string contains the TOML contents of `[dns]`, without the outer header.
No DNS types or fields are added to `common.proto`.

The Rust `toml::DnsConfig` and `DnsZoneConfig` are temporary record-only models.
Replace them with dns-policy's Raw/Parsed configuration when merging that
implementation. Remove the interim `ConfigLoader::get_dns`/`set_dns` methods in
favor of its `DnsConfigLoaderExt`; retain the dns-policy serialization paths.
The local `UpdateDnsRecordRequest.dns` field belongs to the old
`magic_dns.proto`, which dns-policy removes along with the old DNS server.
Its node RPC and zone distribution protocol replace this local transport.

The existing `accept_dns` switch and this interim runtime's authoritative-zone
behavior remain in use for now. On migration, dns-policy owns activation and
fallthrough defaults; these temporary behaviors are not additional compatibility
requirements for that implementation.
