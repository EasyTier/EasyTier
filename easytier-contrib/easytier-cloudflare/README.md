# `@easytier/cloudflare`

Run an inbound EasyTier relay in a Cloudflare Durable Object. The package
includes the matching EasyTier WebAssembly artifact and owns WebSocket
admission, Guest lifecycle, and request routing.

```sh
pnpm add @easytier/cloudflare
```

```ts
import { createEasyTierCloudflare } from "@easytier/cloudflare";

interface Env {
  EASYTIER_CORE: DurableObjectNamespace;
  EASYTIER_NETWORK_SECRET: string;
}

const easytier = createEasyTierCloudflare<Env>({
  namespace: (env) => env.EASYTIER_CORE,
  config: (env) => ({
    networkName: "office",
    networkSecret: env.EASYTIER_NETWORK_SECRET,
    instanceName: "edge-relay",
    encryption: true,
  }),
});

export const EasyTierCoreObject = easytier.DurableObject;
export default easytier;
```

The Worker project still declares the deployment resource in `wrangler.jsonc`:

```jsonc
{
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

`createEasyTierCloudflare()` returns both the Durable Object class and a fetch
handler. Pass a custom `objectName` string or callback to route independent
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
pnpm build:wasm
pnpm test
pnpm check
pnpm exec wrangler dev --local
```
