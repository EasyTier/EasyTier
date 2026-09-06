import { mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const packageDirectory = path.dirname(
  path.dirname(fileURLToPath(import.meta.url)),
);
const repositoryRoot = path.resolve(packageDirectory, "../..");
const [profile, outputArgument] = process.argv.slice(2);
if (profile !== "browser" && profile !== "cloudflare") {
  throw new Error(
    "usage: build-wasm.mjs <browser|cloudflare> <output-file>",
  );
}
if (outputArgument === undefined) {
  throw new Error("Wasm output file is required");
}
const browserBuild = profile === "browser";
const executableSuffix = process.platform === "win32" ? ".cmd" : "";
const wasmOptExecutable = path.join(
  packageDirectory,
  "node_modules",
  ".bin",
  `wasm-opt${executableSuffix}`,
);
const artifact = path.join(
  repositoryRoot,
  "target/wasm32-wasip1/release/easytier_core.wasm",
);
const output = path.resolve(process.cwd(), outputArgument);
const outputDirectory = path.dirname(output);

await new Promise((resolve, reject) => {
  const cargo = spawn(
    "cargo",
    [
      "build",
      "-p",
      "easytier-core",
      "--release",
      "--target",
      "wasm32-wasip1",
      "--no-default-features",
      "--features",
      browserBuild
        ? "wasm-host-tunnel-outbound,aes-gcm,proxy-smoltcp-stack"
        : "wasm-host-tunnel,aes-gcm",
    ],
    {
      cwd: repositoryRoot,
      env: {
        ...process.env,
        CARGO_PROFILE_RELEASE_OPT_LEVEL: "z",
      },
      stdio: "inherit",
    },
  );
  cargo.once("error", reject);
  cargo.once("exit", (code, signal) => {
    if (code === 0) {
      resolve();
      return;
    }
    reject(
      new Error(
        `cargo build failed (${signal === null ? `exit ${code}` : signal})`,
      ),
    );
  });
});

await mkdir(outputDirectory, { recursive: true });
await new Promise((resolve, reject) => {
  const wasmOpt = spawn(
    wasmOptExecutable,
    [
      artifact,
      "-Oz",
      "--enable-bulk-memory",
      "--enable-nontrapping-float-to-int",
      "--strip-debug",
      "--strip-producers",
      "-o",
      output,
    ],
    {
      cwd: packageDirectory,
      stdio: "inherit",
    },
  );
  wasmOpt.once("error", reject);
  wasmOpt.once("exit", (code, signal) => {
    if (code === 0) {
      resolve();
      return;
    }
    reject(
      new Error(
        `wasm-opt failed (${signal === null ? `exit ${code}` : signal})`,
      ),
    );
  });
});
console.log(
  `optimized ${path.relative(process.cwd(), output)} (${profile})`,
);
