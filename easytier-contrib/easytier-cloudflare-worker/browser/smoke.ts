import { EasyTierRuntime } from "../src/core-runtime";
import {
  compileModule,
  connectWithRetry,
  deadline,
  probeHttpMarker,
  waitForPeer,
} from "./smoke-shared";

interface BrowserLocation {
  search: string;
}

interface StatusElement {
  dataset: Record<string, string | undefined>;
  textContent: string | null;
}

interface BrowserDocument {
  querySelector(selector: string): StatusElement | null;
}

const browser = globalThis as unknown as {
  document: BrowserDocument;
  location: BrowserLocation;
};
const status = browser.document.querySelector("#status");
if (status === null) {
  throw new Error("browser smoke status element is missing");
}

function setStatus(state: string, message: string): void {
  status!.dataset.state = state;
  status!.textContent = message;
  console.log(JSON.stringify({ event: "browser_smoke_status", state, message }));
}

async function run(): Promise<void> {
  const query = new URLSearchParams(browser.location.search);
  const relayUrl = query.get("relay") ?? "ws://127.0.0.1:11011/";
  const target = query.get("target") ?? "100.64.0.1:18080";
  const separator = target.lastIndexOf(":");
  if (separator < 1) {
    throw new Error(`invalid target: ${target}`);
  }
  const host = target.slice(0, separator);
  const port = Number(target.slice(separator + 1));
  const response = await fetch("./generated/easytier_core.wasm");
  if (!response.ok) {
    throw new Error(`failed to load WASM: HTTP ${response.status}`);
  }
  const module = compileModule(await response.arrayBuffer());
  const config = `
instance_id = "${crypto.randomUUID()}"
instance_name = "browser-chromium-smoke"
ipv4 = "10.144.144.2/24"
listeners = []

[network_identity]
network_name = "browser-smoke"
network_secret = "browser-smoke-test"

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
  const runtime = new EasyTierRuntime(
    module,
    config,
    (url) => new WebSocket(url),
    (event) => {
      console.log(JSON.stringify({ event: "easytier_core_event", ...event }));
      if (event.kind === "peer_added") {
        peerAdded = true;
      }
    },
  );
  await runtime.ready;
  setStatus("joining", `joining ${relayUrl}`);

  const timeoutAt = deadline();
  await waitForPeer(
    () => peerAdded,
    timeoutAt,
    `EasyTier did not connect to ${relayUrl}`,
  );
  const stream = await connectWithRetry(
    () => runtime.connectTcp(host, port, 1_000),
    timeoutAt,
  );
  await probeHttpMarker(stream, host, "browser-data-plane-ok");
  setStatus("connected", `connected to ${target} through EasyTier`);
}

setStatus("starting", "starting browser EasyTier runtime");
void run().catch((error: unknown) => {
  setStatus("failed", String(error));
});
