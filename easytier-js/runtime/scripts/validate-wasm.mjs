import { readFile } from "node:fs/promises";
import path from "node:path";

const [profile, artifactArgument] = process.argv.slice(2);
if (profile !== "browser" && profile !== "cloudflare") {
  throw new Error(
    "usage: validate-wasm.mjs <browser|cloudflare> <artifact-file>",
  );
}
if (artifactArgument === undefined) {
  throw new Error("Wasm artifact file is required");
}

const artifact = path.resolve(process.cwd(), artifactArgument);
const module = new WebAssembly.Module(await readFile(artifact));
const imports = new Set(
  WebAssembly.Module.imports(module)
    .filter((entry) => entry.module === "easytier_host")
    .map((entry) => entry.name),
);
const exports = new Set(
  WebAssembly.Module.exports(module).map((entry) => entry.name),
);

requireSymbol(exports, "easytier_host_tunnel_abi_version", "export");
requireSymbol(exports, "easytier_instance_accept_tunnel", "export");
if (profile === "browser") {
  requireSymbol(imports, "start_tunnel_connect", "import");
  requireSymbol(exports, "easytier_data_plane_tcp_connect_submit", "export");
} else {
  rejectSymbol(imports, "start_tunnel_connect", "import");
  rejectSymbol(exports, "easytier_data_plane_tcp_connect_submit", "export");
}

function requireSymbol(symbols, name, kind) {
  if (!symbols.has(name)) {
    throw new Error(`${profile} artifact is missing ${kind} ${name}`);
  }
}

function rejectSymbol(symbols, name, kind) {
  if (symbols.has(name)) {
    throw new Error(`${profile} artifact unexpectedly contains ${kind} ${name}`);
  }
}
