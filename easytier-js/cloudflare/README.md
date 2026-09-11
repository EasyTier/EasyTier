# `@easytier/cloudflare`

Run an inbound EasyTier relay in a Cloudflare Durable Object. The package
includes the matching EasyTier WebAssembly artifact and owns WebSocket
admission, Guest lifecycle, and request routing.

## Install

```sh
pnpm add @easytier/cloudflare
pnpm add --save-dev wrangler
```

## Create the Worker

```ts
import { createEasyTierCloudflare } from "@easytier/cloudflare";

const easytier = createEasyTierCloudflare<Env>({
  namespace: (env) => env.EASYTIER_CORE,
  config: (env) => ({
    networkName: "office",
    networkSecret: env.EASYTIER_NETWORK_SECRET,
    instanceName: "edge-relay",
    encryption: true,
  }),
});

export class EasyTierCoreObject extends easytier.DurableObject {}
export default easytier;
```

`Env` is generated from `wrangler.jsonc` by `wrangler types`; applications do
not need to maintain a parallel binding interface by hand.

## Configure Wrangler

```jsonc
{
  "$schema": "node_modules/wrangler/config-schema.json",
  "name": "easytier-relay",
  "main": "src/worker.ts",
  "compatibility_date": "2026-09-05",
  "compatibility_flags": ["nodejs_compat"],
  "secrets": {
    "required": ["EASYTIER_NETWORK_SECRET"]
  },
  "durable_objects": {
    "bindings": [
      {
        "name": "EASYTIER_CORE",
        "class_name": "EasyTierCoreObject"
      }
    ]
  },
  "migrations": [
    {
      "tag": "v1",
      "new_sqlite_classes": ["EasyTierCoreObject"]
    }
  ]
}
```

Generate the environment type after changing the configuration:

```sh
pnpm wrangler types
```

For local development, put the secret in an untracked `.dev.vars` file:

```dotenv
EASYTIER_NETWORK_SECRET=replace-with-a-local-secret
```

Then start the Worker and check the EasyTier Instance:

```sh
pnpm wrangler dev --local
curl http://127.0.0.1:8787/health
```

The health response contains only the public Instance state and connection
count:

```json
{"ok":true,"state":"running","connections":0}
```

Set the production secret interactively before the first deployment:

```sh
pnpm wrangler secret put EASYTIER_NETWORK_SECRET
pnpm wrangler deploy
```

`createEasyTierCloudflare()` returns both the Durable Object base class and a
fetch handler. The one-line named subclass gives Wrangler a concrete class and
type to bind. Pass a custom `objectName` string or callback to route independent
EasyTier networks to different named objects; the default is `primary`.

The Cloudflare Adapter is an inbound-only relay. Its public Interface does not
expose TOML, WebAssembly, Host Tunnel handles, JSPI scheduling, or the socket
admission sequence. `GET /health` returns only the Instance state and active
connection count. Other non-WebSocket paths return `404`.

The Durable Object intentionally uses the standard WebSocket API rather than
hibernation. EasyTier's Wasm memory, Tokio executor, and peer graph are
in-memory state and cannot be reconstructed from socket attachments alone.

For local development in the EasyTier repository:

```sh
cd easytier-js
pnpm install
pnpm --filter @easytier/web-example build:packages
pnpm --filter @easytier/web-example dev:cloudflare
```

See the complete Browser-to-Cloudflare walkthrough in
[`easytier-js/examples/web`](https://github.com/EasyTier/EasyTier/tree/main/easytier-js/examples/web).
