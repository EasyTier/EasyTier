import { createEasyTierCloudflare } from "@easytier/cloudflare";

const easytier = createEasyTierCloudflare<Env>({
  namespace: (env) => env.EASYTIER_CORE,
  config: (env) => ({
    networkName: env.EASYTIER_NETWORK_NAME,
    networkSecret: env.EASYTIER_NETWORK_SECRET,
    instanceName: "easytier-web-example-relay",
    encryption: true,
  }),
});

export class EasyTierCoreObject extends easytier.DurableObject {}
export default easytier;
