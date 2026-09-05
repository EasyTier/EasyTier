import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("Cloudflare Worker WASM build profile", () => {
  it("includes the cipher used by secure peer sessions", async () => {
    const buildScript = await readFile(
      new URL("../scripts/build-wasm.mjs", import.meta.url),
      "utf8",
    );

    expect(buildScript).toMatch(
      /"--features",\s*"wasm-host-websocket,aes-gcm"/,
    );
  });
});
