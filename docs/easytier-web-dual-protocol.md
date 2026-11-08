# TCP and UDP config-server listeners

Run one config server on the same TCP and UDP port:

```sh
easytier-web --config-server-protocol both --config-server-port 20000
```

The equivalent environment settings are `ET_CONFIG_SERVER_PROTOCOL=both` and
`ET_CONFIG_SERVER_PORT=20000`. Allow both TCP and UDP through the firewall; Docker
bridge deployments need both `-p 20000:20000/tcp` and `-p 20000:20000/udp`.

Clients choose a concrete protocol and keep the existing username or token path:

```sh
easytier-core --config-server udp://example.com:20000/admin
easytier-core --config-server tcp://example.com:20000/admin
```

Both listeners share authentication, device identity, sessions and configuration
management. Account isolation continues to apply. Clients do not automatically
switch protocols. `both` is only a server option, never a URL scheme.

The default remains UDP. Explicit `udp`, `tcp` and `ws` modes retain their
existing behavior. In `both` mode each protocol must bind at least one address
family; unavailable IPv6 does not prevent IPv4 operation. If either protocol
cannot bind at all, startup fails instead of silently providing only one protocol.
`both` requires a non-zero port; port `0` would assign independent ephemeral
ports to each listener and is rejected. Single-protocol modes retain their
existing port `0` behavior.

The console offers a command for each protocol. `/api/v1/console-info` preserves
`config_server_protocol` as a concrete scheme (`udp` in `both` mode) for older
frontends, and adds `config_server_protocols` (`["udp", "tcp"]` in `both` mode).
New frontends fall back to the singular field when using older servers.

Gateway mode accepts either a TCP or UDP `--gateway-peer-url` with `both`.
It continues to advertise the single configured Gateway URL.
