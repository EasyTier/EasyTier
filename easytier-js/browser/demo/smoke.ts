import { createEasyTier } from "../src/index";
import {
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
  let peerAdded = false;
  const runtime = await createEasyTier(
    {
      networkName: "browser-smoke",
      networkSecret: "browser-smoke-test",
      instanceName: "browser-chromium-smoke",
      ipv4: "10.144.144.2/24",
      peers: relayUrl,
      encryption: true,
    },
    {
      onEvent: (event) => {
        console.log(JSON.stringify({ event: "easytier_core_event", ...event }));
        if (event.kind === "peer_added") {
          peerAdded = true;
        }
      },
    },
  );
  setStatus("joining", `joining ${relayUrl}`);

  const timeoutAt = deadline();
  await waitForPeer(
    () => peerAdded,
    timeoutAt,
    `EasyTier did not connect to ${relayUrl}`,
  );
  const stream = await connectWithRetry(
    () => runtime.connectTcp(`${host}:${port}`, { timeout: 1_000 }),
    timeoutAt,
  );
  await probeHttpMarker(stream, host, "browser-data-plane-ok");
  setStatus("connected", `connected to ${target} through EasyTier`);
}

setStatus("starting", "starting browser EasyTier runtime");
void run().catch((error: unknown) => {
  setStatus("failed", String(error));
});
