import { readFile } from "node:fs/promises";

import { EasyTierRuntime } from "../src/core-runtime";
import {
  compileModule,
  connectWithRetry,
  deadline,
  probeHttpMarker,
  SMOKE_RETRY_MILLISECONDS,
} from "./smoke-shared";

const relayUrl = process.env.EASYTIER_BROWSER_RELAY ?? "ws://127.0.0.1:11011/";
const networkName = process.env.EASYTIER_BROWSER_NETWORK ?? "browser-smoke";
const networkSecret = process.env.EASYTIER_BROWSER_SECRET ?? "browser-smoke-test";
const ipv4 = process.env.EASYTIER_BROWSER_IPV4 ?? "10.144.144.2";
const moduleBytes = await readFile(
  process.env.EASYTIER_BROWSER_WASM ??
    new URL("./easytier_core.wasm", import.meta.url),
);
const module = compileModule(moduleBytes as unknown as BufferSource);
const config = `
instance_id = "${process.env.EASYTIER_BROWSER_INSTANCE_ID ?? crypto.randomUUID()}"
instance_name = "browser-node-smoke"
ipv4 = "${ipv4}/24"
listeners = []

[network_identity]
network_name = "${networkName}"
network_secret = "${networkSecret}"

[[peer]]
uri = "${relayUrl}"

[flags]
no_tun = true
use_smoltcp = true
disable_p2p = true
enable_encryption = true
bind_device = false
`;

let peerAdded = false;
const runtime = new EasyTierRuntime(module, config, (url) => new WebSocket(url), (event) => {
  console.log(JSON.stringify({ event: "easytier_core_event", ...event }));
  if (event.kind === "peer_added") {
    peerAdded = true;
  }
});
await runtime.ready;

const timeoutAt = deadline();
while (Date.now() < timeoutAt) {
  const health = await runtime.health();
  if (peerAdded) {
    const target = process.env.EASYTIER_BROWSER_TCP_TARGET;
    if (target !== undefined) {
      const separator = target.lastIndexOf(":");
      if (separator < 1) {
        throw new Error(`invalid EASYTIER_BROWSER_TCP_TARGET: ${target}`);
      }
      const host = target.slice(0, separator);
      const port = Number(target.slice(separator + 1));
      const stream = await connectWithRetry(
        () => runtime.connectTcp(host, port, 1_000),
        timeoutAt,
      );
      await probeHttpMarker(stream, host, "browser-data-plane-ok");
      console.log(
        JSON.stringify({ event: "browser_smoke_data_plane", target }),
      );
    }
    console.log(JSON.stringify({ event: "browser_smoke_connected", health }));
    process.exit(0);
  }
  await new Promise((resolve) => setTimeout(resolve, SMOKE_RETRY_MILLISECONDS));
}

throw new Error(`EasyTier did not connect to ${relayUrl}`);
