import {
  createEasyTierRuntime,
  type RuntimeWebSocket,
} from "@easytier/runtime/adapter";
import type {
  EasyTierEvent,
  EasyTierInstance,
  EasyTierNetworkConfig,
} from "@easytier/runtime";

export interface BrowserEasyTierConfig extends EasyTierNetworkConfig {
  ipv4: string;
  peers: string | readonly string[];
}

export interface BrowserEasyTierOptions {
  onEvent?: (event: EasyTierEvent) => void;
}

export async function createEasyTierWithArtifact(
  artifact: BufferSource,
  config: BrowserEasyTierConfig,
  options: BrowserEasyTierOptions = {},
): Promise<EasyTierInstance> {
  return createEasyTierRuntime({
    module: () => WebAssembly.compile(artifact),
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
