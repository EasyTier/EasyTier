import coreBytes from "./generated/easytier_core.wasm";
import { createEasyTierWithArtifact } from "./create.js";
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
import type {
  BrowserEasyTierConfig,
  BrowserEasyTierOptions,
} from "./create.js";

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
export type { BrowserEasyTierConfig, BrowserEasyTierOptions };

export async function createEasyTier(
  config: BrowserEasyTierConfig,
  options: BrowserEasyTierOptions = {},
): Promise<EasyTierInstance> {
  return createEasyTierWithArtifact(coreBytes, config, options);
}
