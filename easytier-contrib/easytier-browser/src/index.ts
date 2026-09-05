import {
  createEasyTierRuntime,
  type RuntimeWebSocket,
} from "@easytier/runtime/adapter";
import type {
  EasyTierEvent,
  EasyTierInstance,
  EasyTierIpv4SocketAddress,
  EasyTierNetworkConfig,
  EasyTierOperationOptions,
  EasyTierState,
  EasyTierStatus,
  EasyTierTcpListener,
  EasyTierTcpReadResult,
  EasyTierTcpStream,
} from "@easytier/runtime";

export type {
  EasyTierEvent,
  EasyTierInstance,
  EasyTierIpv4SocketAddress,
  EasyTierNetworkConfig,
  EasyTierOperationOptions,
  EasyTierState,
  EasyTierStatus,
  EasyTierTcpListener,
  EasyTierTcpReadResult,
  EasyTierTcpStream,
};

export interface BrowserEasyTierConfig extends EasyTierNetworkConfig {
  ipv4: string;
  peers: string | readonly string[];
}

export interface BrowserEasyTierOptions {
  onEvent?: (event: EasyTierEvent) => void;
}

const coreUrl = new URL("./generated/easytier_core.wasm", import.meta.url);

export async function createEasyTier(
  config: BrowserEasyTierConfig,
  options: BrowserEasyTierOptions = {},
): Promise<EasyTierInstance> {
  return createEasyTierRuntime({
    module: loadCoreModule,
    config: {
      profile: "browser",
      instanceId: crypto.randomUUID(),
      instanceName: config.instanceName ?? "easytier-browser",
      networkName: config.networkName,
      networkSecret: config.networkSecret,
      encryption: config.encryption ?? true,
      ipv4: config.ipv4,
      peers:
        typeof config.peers === "string" ? [config.peers] : [...config.peers],
    },
    connectWebSocket: (url) =>
      new WebSocket(url) as unknown as RuntimeWebSocket,
    onEvent: options.onEvent,
  });
}

async function loadCoreModule(): Promise<WebAssembly.Module> {
  const response = await fetch(coreUrl);
  if (!response.ok) {
    throw new Error(
      `failed to load the EasyTier browser artifact: HTTP ${response.status}`,
    );
  }
  return WebAssembly.compile(await response.arrayBuffer());
}
