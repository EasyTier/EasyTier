import type { EasyTierNetworkConfig } from "@easytier/runtime";

export type CloudflareEasyTierConfig = EasyTierNetworkConfig;

export interface CloudflareEasyTierOptions<Env> {
  namespace(env: Env): DurableObjectNamespace;
  config(env: Env):
    | CloudflareEasyTierConfig
    | Promise<CloudflareEasyTierConfig>;
  objectName?: string | ((request: Request, env: Env) => string);
}

export interface EasyTierDurableObject {
  fetch(request: Request): Promise<Response>;
}

export interface EasyTierDurableObjectClass<Env> {
  new (ctx: DurableObjectState, env: Env): EasyTierDurableObject;
}

export interface EasyTierCloudflareApplication<Env> {
  readonly DurableObject: EasyTierDurableObjectClass<Env>;
  fetch(
    request: Request,
    env: Env,
    context: ExecutionContext,
  ): Promise<Response>;
}
