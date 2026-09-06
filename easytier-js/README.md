# EasyTier JavaScript

The EasyTier JavaScript packages run the same EasyTier WASM core across web
runtimes while keeping application-facing APIs small:

- [`@easytier/browser`](./browser) provides a browser TCP client.
- [`@easytier/cloudflare`](./cloudflare) provides a Cloudflare Durable Object
  relay.
- [`@easytier/runtime`](./runtime) contains their shared runtime and adapter
  implementation. Most applications should use one of the two public host
  packages instead of depending on it directly.

A complete browser and Cloudflare Worker walkthrough is available in
[`examples/web`](./examples/web).

From the repository root, install dependencies and run the package checks with:

```sh
pnpm install
pnpm --filter @easytier/browser check
pnpm --filter @easytier/cloudflare check
```
