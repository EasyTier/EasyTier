# Raw peer JSON

Run `easytier-cli peer --all-json` to output the complete `list_peer` and
`list_route` RPC responses as a single JSON document:

```json
{
  "peers": { "peer_infos": [], "my_info": null },
  "routes": { "routes": [] }
}
```

Fields follow the Rust response types' Serde representation. Each peer retains
all returned connections, tunnel addresses, statistics, and authentication
metadata. Routes are returned separately without joining or filtering peers.
`remote_addr` and `resolved_remote_addr` remain separate fields.

The flag forces JSON output and cannot be combined with peer subcommands.
Existing instance selectors apply. When multiple instances are selected, the
output is an array of objects containing `instance_id`, `instance_name`, and
`result` (the object shown above). The two RPC responses are separate snapshots.
Only connections known to the queried core are included; this does not query
every remote node for its own connections.

For Node.js, execute the command with `execFile` and parse stdout with
`JSON.parse`. No table headings or human-readable unit conversions are added.
