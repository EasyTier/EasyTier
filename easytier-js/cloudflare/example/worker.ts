import { createEasyTierCloudflare } from "../src/index";

const easytier = createEasyTierCloudflare<Env>({
  namespace: (env) => env.EASYTIER_CORE,
  objectName: (request, env) =>
    env.EASYTIER_OBJECT_NAME ?? new URL(request.url).hostname,
  config: (env) => ({
    networkName: env.EASYTIER_NETWORK_NAME,
    networkSecret: env.EASYTIER_NETWORK_SECRET,
    instanceName: "cloudflare-worker",
    encryption: env.EASYTIER_ENABLE_ENCRYPTION !== "false",
  }),
});

export class EasyTierCoreObject extends easytier.DurableObject {}
export default easytier;
