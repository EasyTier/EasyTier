declare module "*.wasm" {
  const bytes: Uint8Array<ArrayBuffer>;
  export default bytes;
}
