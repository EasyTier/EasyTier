# Diagnose duplicate instance IDs

Each distinct node in a network should have its own `instance_id`. When copying
an EasyTier configuration to another node, assign the copy a new UUID.

`easytier-cli peer` and `easytier-cli route` check the queried node and its route
snapshot for different peer IDs advertising the same non-nil instance UUID. A
collision produces a warning on **stderr**, for example:

```text
Warning [local peer 1]: duplicate instance_id detected: 00112233-4455-6677-8899-aabbccddeeff advertised by peer IDs [2, 9]. Check for copied configs or overlapping restarts; distinct nodes need unique instance_id values.
```

The same check runs in table, JSON, and verbose modes:

```sh
easytier-cli peer
easytier-cli --instance-name my-network route
easytier-cli --output json route > routes.json
```

Normal stdout and JSON schemas are unchanged. Multi-instance queries check each
network independently and label warnings with the queried instance name and
UUID. Reusing an instance UUID in separate networks does not by itself trigger
a warning. Multiple connections or repeated records for the same peer ID do not
trigger one either. Missing, malformed, and nil UUIDs are ignored.

## Interpreting the warning

This is a diagnostic of the current route snapshot, not proof of two physical
machines sharing a configuration. An overlapping restart or a stale route during
convergence may temporarily advertise two peer IDs for one UUID. Check the
reported peers and any copied configurations before changing their IDs.

If distinct nodes share the UUID, assign a fresh UUID to the copied node's
configuration and restart that node. Subsequent queries stop warning once the
conflicting route advertisements disappear. The CLI does not reject connections,
rewrite configurations, or change routing behavior; this check is not proactive
background logging in `easytier-core`.

## Validation

Run the CLI unit tests with `cargo test -p easytier --bin easytier-cli`.
`bash script/test-cli-duplicate-instance-id.sh` builds both binaries and exercises
local loopback nodes without a TUN device. Set `SKIP_BUILD=1` to reuse existing
binaries; `CORE_BIN` and `CLI_BIN` can override their paths. The script verifies
local/remote collisions, all output modes, instance isolation, JSON columns,
and recovery after disconnect or changing the copied UUID.
