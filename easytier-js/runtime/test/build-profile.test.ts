import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("Cloudflare Worker WASM build profile", () => {
  it("keeps separate worker and browser capability sets", async () => {
    const buildScript = await readFile(
      new URL("../scripts/build-wasm.mjs", import.meta.url),
      "utf8",
    );

    expect(buildScript).toContain('"wasm-host-tunnel,aes-gcm"');
    expect(buildScript).toContain(
      '"wasm-host-tunnel-outbound,aes-gcm,proxy-smoltcp-stack"',
    );
  });
});
