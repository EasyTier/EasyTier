# EasyTier Core on Cloudflare Workers

This package runs the EasyTier peer and relay core inside a Cloudflare
Durable Object. Cloudflare upgrades each incoming WebSocket, then transfers
the endpoint to the WASI guest as an EasyTier message tunnel. Standard
EasyTier clients connect directly with `wss://`; no relay-specific client is
required.

This integration is experimental. Its WASI composition selects the
instance-level `InboundOnly` connectivity mode: the guest accepts a
Host-registered WebSocket listener and participates in EasyTier routing, but
does not bind native sockets, dial outbound peers, perform STUN, or run hole
punching.

## Architecture

One named Durable Object owns one long-lived EasyTier instance:

```text
EasyTier client
    │ WSS (one EasyTier packet per binary message)
    ▼
Cloudflare Worker
    │ routes every request to one named object
    ▼
Durable Object
    ├── Cloudflare WebSocket endpoints
    ├── bounded host message/operation queues
    ├── serialized JSPI export pump
    └── easytier-core.wasm
            └── normal server tunnel admission and peer routing
```

The Durable Object uses the standard WebSocket API rather than WebSocket
hibernation. The Wasm memory, Tokio executor, and EasyTier peer graph are
in-memory state and cannot be reconstructed from a hibernated socket
attachment alone.

## Build and validate

From this directory:

```sh
pnpm install
pnpm build:wasm
pnpm test
pnpm exec tsc --noEmit
pnpm exec wrangler deploy --dry-run
```

`build:wasm` compiles `easytier-core` for `wasm32-wasip1` with the
`wasm-host-websocket` Adapter and runs `wasm-opt`. The Cargo feature compiles
the Adapter; it does not change normal `CoreInstance` behavior. The resulting
generated Wasm file is intentionally ignored by Git.

The deployment requires a Workers runtime with WebAssembly JSPI support. The
`/runtime-capabilities` endpoint reports whether both
`WebAssembly.Suspending` and `WebAssembly.promising` are available.

## Browser client

The same host ABI also has an outbound-only browser profile. It dials EasyTier
`ws://` or `wss://` peers with the browser WebSocket API and keeps the smoltcp
TCP data plane inside Wasm; it does not attempt native DNS, socket listeners,
STUN, hole punching, TUN, or host packet forwarding.

Build the browser Wasm and the smoke page with:

```sh
pnpm build:browser-wasm
pnpm build:browser-smoke
```

Serve this directory over localhost or HTTPS and open `browser/index.html` to
exercise raw EasyTier TCP through a WebSocket relay. Browsers must provide
WebAssembly JSPI.

## Configure

`wrangler.jsonc` contains a non-production test network so local development
works without additional files. Replace its identity before a real
deployment. Never use the checked-in `cf-wasi-test` secret for a private
network.

For a production secret, keep the checked-in fallback only for development
and install an overriding secret binding:

```sh
pnpm exec wrangler secret put EASYTIER_CONFIG_SECRET
```

The secret value is the complete EasyTier TOML configuration. The Worker
composition requires:

- `listeners = []`;
- no `[[peer]]` entries;
- `no_tun = false` (the host supplies a packet sink, not an OS TUN device);
- `disable_p2p = true`;
- `enable_encryption` to match connecting clients.

`EASYTIER_OBJECT_NAME` selects the singleton Durable Object. Change it when
deploying a new network identity or when intentionally replacing an
unrecoverable in-memory instance. Changing it creates a new object; existing
WebSockets on the old object are not migrated.

## Run

Local development:

```sh
pnpm exec wrangler dev --local
```

Deploy to an authenticated account:

```sh
pnpm deploy
```

For an expendable preview account, Wrangler also supports:

```sh
pnpm build:wasm
pnpm exec wrangler deploy --temporary
```

Connect a normal EasyTier client:

```sh
easytier-core \
  --network-name <network-name> \
  --network-secret <network-secret> \
  --peers wss://<worker-domain>/ \
  --no-listener \
  --bind-device false
```

`GET /health` initializes the object and returns the core state, host
WebSocket ABI version, active connection count, queued byte count, and pending
operation count.

## Resource and protocol invariants

- Every WebSocket binary message is exactly one EasyTier tunnel payload.
- Text messages are rejected; a remote close becomes tunnel EOF.
- A connection handle is transferred to the guest only after admission is
  scheduled successfully. Before transfer, failure cleanup remains host-owned.
- Guest exports are called through one serialized JSPI queue, preventing
  reentrant Wasm execution.
- The object accepts at most 256 sockets.
- A message is limited to 1 MiB; per-connection receive queues are limited to
  64 messages and 2 MiB; total queued or completed-but-untaken receive data is
  limited to 16 MiB.
- Outbound buffered data is capped at 4 MiB when the runtime exposes
  `bufferedAmount`.

The Worker is a relay node, not a TUN endpoint. It has no host network
interface and discards packets addressed to the Worker itself.
