# Inspect credential users from the CLI

On a node that stores the issued credentials, list their currently authenticated
direct peers:

```sh
easytier-cli credential peers

# Select one network instance and return machine-readable output.
easytier-cli --instance-name my-network --output json credential peers
```

The table associates each credential ID with peer IDs, virtual IPv4/IPv6
addresses, and hostnames. A reusable credential can have multiple peers;
multiple tunnels to the same peer appear only once. Existing `credential list`
output is unchanged.

JSON output has this shape for one instance:

```json
{
  "credentials": [
    {
      "credential_id": "user-123",
      "peers": [
        {
          "peer_id": 42,
          "ipv4": "10.144.144.2",
          "ipv6": null,
          "hostname": "laptop"
        }
      ]
    }
  ]
}
```

Without an explicit instance selector, the command follows the other CLI query
commands: it queries running instances, wrapping multiple results with their
instance IDs and names.

## Scope

The association uses the remote public key of an authenticated live credential
connection, matched against the credential's SHA-256 public-key fingerprint.
It never uses a route advertisement alone as proof of credential identity.
Credential secrets and connection keys are not printed.

This is a per-node snapshot, not a network-wide login history. An empty `peers`
array (shown as `no direct peers` in the table) does not mean a credential is
unused elsewhere: its users may only be connected to another node or reachable
through a relay. Older cores without credential fingerprints cannot be matched.
Missing route addresses are returned as `null` (shown as `-`); a peer may connect
before its route or DHCP address is available. Addresses and connection state
can change between the RPC snapshots.
