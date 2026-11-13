import {
  createEasyTier,
  type EasyTierInstance,
} from "@easytier/browser";

const form = requireElement<HTMLFormElement>("connection-form");
const connectButton = requireElement<HTMLButtonElement>("connect");
const disconnectButton = requireElement<HTMLButtonElement>("disconnect");
const status = requireElement<HTMLOutputElement>("status");
const events = requireElement<HTMLPreElement>("events");

let instance: EasyTierInstance | undefined;

form.addEventListener("submit", (event) => {
  event.preventDefault();
  void connect();
});

disconnectButton.addEventListener("click", () => {
  void disconnect();
});

async function connect(): Promise<void> {
  if (instance !== undefined) {
    return;
  }

  const fields = new FormData(form);
  connectButton.disabled = true;
  events.textContent = "";
  setStatus("Starting EasyTier…");

  let peerConnected = false;
  try {
    instance = await createEasyTier(
      {
        networkName: requiredField(fields, "network"),
        networkSecret: requiredField(fields, "secret"),
        instanceName: "easytier-web-example",
        ipv4: requiredField(fields, "ipv4"),
        peers: requiredField(fields, "relay"),
      },
      {
        onEvent(event) {
          appendEvent(event.kind, event.message);
          if (event.kind === "peer_added") {
            peerConnected = true;
            setStatus("Connected to the EasyTier relay");
          }
        },
      },
    );
    disconnectButton.disabled = false;
    if (!peerConnected) {
      setStatus("EasyTier is running; waiting for the relay…");
    }
  } catch (error) {
    instance = undefined;
    connectButton.disabled = false;
    setStatus(`Connection failed: ${String(error)}`);
  }
}

async function disconnect(): Promise<void> {
  const current = instance;
  if (current === undefined) {
    return;
  }

  instance = undefined;
  disconnectButton.disabled = true;
  try {
    await current.close();
    setStatus("Disconnected");
  } catch (error) {
    setStatus(`Disconnect failed: ${String(error)}`);
  } finally {
    connectButton.disabled = false;
  }
}

function appendEvent(kind: string, message: string): void {
  events.textContent += `${kind}: ${message}\n`;
  events.scrollTop = events.scrollHeight;
}

function requiredField(fields: FormData, name: string): string {
  const value = fields.get(name);
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${name} is required`);
  }
  return value;
}

function requireElement<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (element === null) {
    throw new Error(`missing element: ${id}`);
  }
  return element as T;
}

function setStatus(message: string): void {
  status.value = message;
}
