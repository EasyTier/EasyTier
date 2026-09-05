interface Env {
  EASYTIER_CONFIG: string;
  EASYTIER_CONFIG_SECRET?: string;
  EASYTIER_CORE: DurableObjectNamespace<
    import("./index").EasyTierCoreObject
  >;
  EASYTIER_OBJECT_NAME: string;
}

declare module "*.wasm" {
  const module: WebAssembly.Module;
  export default module;
}
