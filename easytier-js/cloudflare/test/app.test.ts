import { beforeEach, describe, expect, it, vi } from "vitest";

const { createRuntime } = vi.hoisted(() => ({
  createRuntime: vi.fn(),
}));

vi.mock("cloudflare:workers", () => ({
  DurableObject: class<Env> {
    protected readonly ctx: DurableObjectState;
    protected readonly env: Env;

    constructor(ctx: DurableObjectState, env: Env) {
      this.ctx = ctx;
      this.env = env;
    }
  },
}));

vi.mock("@easytier/runtime/adapter", () => ({
  createEasyTierRuntime: createRuntime,
}));

import { createCloudflareApplication } from "../src/app";

interface TestEnv {
  namespace: DurableObjectNamespace;
  secret: string;
}

describe("createEasyTierCloudflare", () => {
  beforeEach(() => {
    createRuntime.mockReset();
    createRuntime.mockResolvedValue({
      status: vi.fn().mockResolvedValue({
        state: "running",
        connections: 2,
      }),
    });
  });

  it("routes requests through the configured named Durable Object", async () => {
    const fetch = vi.fn().mockResolvedValue(new Response("ok"));
    const getByName = vi.fn().mockReturnValue({ fetch });
    const namespace = { getByName } as unknown as DurableObjectNamespace;
    const application = createCloudflareApplication(
      {} as WebAssembly.Module,
      {
        namespace: (env: TestEnv) => env.namespace,
        objectName: (request) => new URL(request.url).hostname,
        config: (env) => ({
          networkName: "office",
          networkSecret: env.secret,
        }),
      },
    );
    const request = new Request("https://relay.example.com/health");

    await expect(
      application.fetch(
        request,
        { namespace, secret: "secret" },
        {} as ExecutionContext,
      ),
    ).resolves.toHaveProperty("status", 200);
    expect(getByName).toHaveBeenCalledWith("relay.example.com");
    expect(fetch).toHaveBeenCalledWith(request);
  });

  it("persists the hidden EasyTier instance identity across restarts", async () => {
    const values = new Map<string, unknown>();
    const storage = {
      get: vi.fn(async (key: string) => values.get(key)),
      put: vi.fn(async (key: string, value: unknown) => {
        values.set(key, value);
      }),
    };
    const application = createCloudflareApplication(
      {} as WebAssembly.Module,
      {
        namespace: (env: TestEnv) => env.namespace,
        config: (env) => ({
          networkName: "office",
          networkSecret: env.secret,
          encryption: false,
        }),
      },
    );
    const state = { storage } as unknown as DurableObjectState;
    const env = {
      namespace: {} as DurableObjectNamespace,
      secret: "do-not-log-this",
    };
    class TestEasyTierCoreObject extends application.DurableObject {}

    const first = new TestEasyTierCoreObject(state, env);
    const firstResponse = await first.fetch!(
      new Request("https://relay.example.com/health"),
    );
    expect(await firstResponse.json()).toEqual({
      ok: true,
      state: "running",
      connections: 2,
    });

    const second = new TestEasyTierCoreObject(state, env);
    await second.fetch!(new Request("https://relay.example.com/health"));

    expect(createRuntime).toHaveBeenCalledTimes(2);
    const firstConfig = createRuntime.mock.calls[0]?.[0].config;
    const secondConfig = createRuntime.mock.calls[1]?.[0].config;
    expect(firstConfig).toMatchObject({
      profile: "cloudflare",
      networkName: "office",
      networkSecret: "do-not-log-this",
      encryption: false,
    });
    expect(secondConfig.instanceId).toBe(firstConfig.instanceId);
    expect(storage.put).toHaveBeenCalledTimes(1);
  });
});
