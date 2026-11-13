interface Env {
  EASYTIER_CORE: DurableObjectNamespace<
    import("./worker").EasyTierCoreObject
  >;
  EASYTIER_NETWORK_NAME: string;
  EASYTIER_NETWORK_SECRET: string;
  EASYTIER_ENABLE_ENCRYPTION?: string;
  EASYTIER_OBJECT_NAME?: string;
}
