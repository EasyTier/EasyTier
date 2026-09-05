import { mkdir } from "node:fs/promises";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const packageDirectory = path.dirname(
  path.dirname(fileURLToPath(import.meta.url)),
);
const repositoryRoot = path.resolve(packageDirectory, "../..");
const artifact = path.join(
  repositoryRoot,
  "target/wasm32-wasip1/release/easytier_core.wasm",
);
const outputDirectory = path.join(packageDirectory, "src/generated");
const output = path.join(outputDirectory, "easytier_core.wasm");

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
      "wasm-host-websocket,aes-gcm",
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
    "wasm-opt",
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
console.log(`optimized ${path.relative(packageDirectory, output)}`);
