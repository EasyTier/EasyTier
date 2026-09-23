import { afterEach, describe, expect, it, vi } from "vitest";

const { createRuntime } = vi.hoisted(() => ({
  createRuntime: vi.fn(),
}));

vi.mock("@easytier/runtime/adapter", () => ({
  createEasyTierRuntime: createRuntime,
}));

import { createEasyTierWithArtifact } from "../src/create";

const EMPTY_WASM_MODULE = new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]);

describe("createEasyTier", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    createRuntime.mockReset();
  });

  it("starts the browser profile from typed configuration", async () => {
    const instance = { close: vi.fn() };
    let loadedModule: WebAssembly.Module | undefined;
    createRuntime.mockImplementation(async (options) => {
      loadedModule = await options.module();
      return instance;
    });
    class MockWebSocket {
      constructor(readonly url: string) {}
    }
    vi.stubGlobal("WebSocket", MockWebSocket);

    await expect(
      createEasyTierWithArtifact(
        EMPTY_WASM_MODULE,
        {
          networkName: "office",
          networkSecret: "secret",
          instanceName: "dashboard",
          ipv4: "10.144.0.10/24",
          peers: "wss://relay.example.com/",
        },
        { onEvent: vi.fn() },
      ),
    ).resolves.toBe(instance);

    expect(createRuntime).toHaveBeenCalledOnce();
    const options = createRuntime.mock.calls[0]?.[0];
    expect(options.config).toMatchObject({
      profile: "browser",
      instanceName: "dashboard",
      networkName: "office",
      networkSecret: "secret",
      encryption: true,
      ipv4: "10.144.0.10/24",
      peers: ["wss://relay.example.com/"],
    });
    expect(loadedModule).toBeInstanceOf(WebAssembly.Module);
    expect(options.connectWebSocket("wss://peer.example/").url).toBe(
      "wss://peer.example/",
    );
  });

  it("fails before starting when the embedded artifact is invalid", async () => {
    createRuntime.mockImplementation(async (options) => {
      await options.module();
    });

    await expect(
      createEasyTierWithArtifact(
        new Uint8Array([1, 2, 3]),
        {
          networkName: "office",
          networkSecret: "secret",
          ipv4: "10.144.0.10/24",
          peers: ["wss://relay.example.com/"],
        },
      ),
    ).rejects.toThrow();
    expect(createRuntime).toHaveBeenCalledOnce();
  });
});
