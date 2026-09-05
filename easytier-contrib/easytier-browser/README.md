# `@easytier/browser`

Run an outbound EasyTier instance and its TCP data plane directly in a browser.
The package embeds the matching EasyTier WebAssembly artifact in its JavaScript
entry point; applications do not configure a bundler loader, compile Rust, load
WASI, or work with Guest handles.

```sh
pnpm add @easytier/browser
```

```ts
import { createEasyTier } from "@easytier/browser";

const easytier = await createEasyTier({
  networkName: "office",
  networkSecret: "secret",
  ipv4: "10.144.0.10/24",
  peers: "wss://relay.example.com/",
  encryption: true,
});

const stream = await easytier.connectTcp("10.144.0.20:8080", {
  timeout: 10_000,
});
await stream.write(new TextEncoder().encode("hello"));
const response = await stream.read();
await stream.close();
await easytier.close();
```

`createEasyTier()` resolves after the EasyTier Instance is running. The Browser
Adapter supports `ws://` and `wss://` peers and an overlay IPv4 TCP data plane.
It does not expose native listeners, TUN, STUN, or hole punching. The browser
must support WebAssembly JSPI.
