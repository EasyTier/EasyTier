import coreModule from "./generated/easytier_core.wasm";

import { createCloudflareApplication } from "./app.js";
import type {
  CloudflareEasyTierOptions,
  EasyTierCloudflareApplication,
} from "./types.js";

export type {
  CloudflareEasyTierConfig,
  CloudflareEasyTierOptions,
  EasyTierCloudflareApplication,
} from "./types.js";

export function createEasyTierCloudflare<Env>(
  options: CloudflareEasyTierOptions<Env>,
): EasyTierCloudflareApplication<Env> {
  return createCloudflareApplication(coreModule, options);
}
