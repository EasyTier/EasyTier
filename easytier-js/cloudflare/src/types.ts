import type { DurableObject } from "cloudflare:workers";
import type { EasyTierNetworkConfig } from "@easytier/runtime";

export type CloudflareEasyTierConfig = EasyTierNetworkConfig;

export interface EasyTierDurableObjectNamespace {
  getByName(name: string): {
    fetch(request: Request): Promise<Response>;
  };
}

export interface CloudflareEasyTierOptions<Env> {
  namespace(env: Env): EasyTierDurableObjectNamespace;
  config(env: Env):
    | CloudflareEasyTierConfig
    | Promise<CloudflareEasyTierConfig>;
  objectName?: string | ((request: Request, env: Env) => string);
}

export type EasyTierDurableObjectClass<Env> = typeof DurableObject<Env>;

export interface EasyTierCloudflareApplication<Env> {
  readonly DurableObject: EasyTierDurableObjectClass<Env>;
  fetch(
    request: Request,
    env: Env,
    context: ExecutionContext,
  ): Promise<Response>;
}
