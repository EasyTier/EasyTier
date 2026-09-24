import { afterEach, describe, expect, it, vi } from "vitest";

import { EasyTierRuntime } from "../src/runtime";

interface RuntimeHarness {
  armNextDrive(): void;
  serial: Promise<void>;
}

interface AttachHarness {
  attachTunnel(
    tunnelHandle: bigint,
    metadata: {
      version: 1;
      local_url: string;
      remote_url: string;
    },
  ): Promise<void>;
  serial: Promise<void>;
}

describe("EasyTierRuntime timer ownership", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("installs only the latest queued deadline timer", async () => {
    vi.useFakeTimers();
    const runtime = Object.create(
      EasyTierRuntime.prototype,
    ) as RuntimeHarness;
    Object.assign(runtime, {
      call: async (name: string) =>
        name === "nextDeadlineMillis" ? 1000n : 0,
      instanceHandle: 1n,
      lastError: undefined,
      serial: Promise.resolve(),
      timer: undefined,
      timerGeneration: 0,
      timerDueAt: undefined,
      armRequest: 0,
    });

    runtime.armNextDrive();
    runtime.armNextDrive();
    await runtime.serial;

    expect(vi.getTimerCount()).toBe(1);
  });

  it("does not postpone an earlier deadline when re-armed", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    let pumpCount = 0;
    const clock = {
      advanceMillis: vi.fn(),
      syncWallTime: vi.fn(),
    };
    const runtime = Object.create(
      EasyTierRuntime.prototype,
    ) as RuntimeHarness;
    Object.assign(runtime, {
      call: async (name: string) =>
        name === "nextDeadlineMillis" ? 1000n : 0,
      instanceHandle: 1n,
      lastError: undefined,
      serial: Promise.resolve(),
      timer: undefined,
      timerGeneration: 0,
      timerDueAt: undefined,
      armRequest: 0,
      clock,
      queuePump: () => {
        pumpCount += 1;
      },
    });

    runtime.armNextDrive();
    await runtime.serial;
    await vi.advanceTimersByTimeAsync(100);
    runtime.armNextDrive();
    await runtime.serial;

    await vi.advanceTimersByTimeAsync(899);
    expect(pumpCount).toBe(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(pumpCount).toBe(1);
    expect(clock.syncWallTime).toHaveBeenCalledOnce();
    expect(clock.advanceMillis).not.toHaveBeenCalled();
  });
});

describe("EasyTierRuntime host tunnel ownership", () => {
  it("commits guest ownership before driving admission", async () => {
    const events: string[] = [];
    const runtime = Object.create(
      EasyTierRuntime.prototype,
    ) as AttachHarness;
    Object.assign(runtime, {
      ready: Promise.resolve(),
      serial: Promise.resolve(),
      instanceHandle: 1n,
      copyIntoGuest: async () => 64,
      call: async (name: string) => {
        events.push(name);
        return 0;
      },
      host: {
        transferToGuest: () => events.push("transferToGuest"),
        abort: () => events.push("abort"),
      },
      driveUntilIdle: async () => {
        events.push("driveUntilIdle");
      },
      armNextDrive: () => events.push("armNextDrive"),
    });

    await runtime.attachTunnel(2n, {
      version: 1,
      local_url: "wss://relay.example/",
      remote_url: "wss://client.example/",
    });

    expect(events).toEqual([
      "acceptTunnel",
      "transferToGuest",
      "bufferFree",
      "driveUntilIdle",
      "armNextDrive",
    ]);
  });

  it("aborts guest-owned socket when admission drive fails", async () => {
    const events: string[] = [];
    const runtime = Object.create(
      EasyTierRuntime.prototype,
    ) as AttachHarness;
    Object.assign(runtime, {
      ready: Promise.resolve(),
      serial: Promise.resolve(),
      instanceHandle: 1n,
      copyIntoGuest: async () => 64,
      call: async () => 0,
      host: {
        transferToGuest: () => events.push("transferToGuest"),
        abort: () => events.push("abort"),
      },
      driveUntilIdle: async () => {
        throw new Error("drive failed");
      },
      armNextDrive: () => {},
    });

    await expect(
      runtime.attachTunnel(2n, {
        version: 1,
        local_url: "wss://relay.example/",
        remote_url: "wss://client.example/",
      }),
    ).rejects.toThrow("drive failed");
    expect(events).toEqual(["transferToGuest", "abort"]);
  });
});

describe("EasyTierRuntime data plane", () => {
  it("exposes TCP listener creation after runtime initialization", async () => {
    const listener = {} as Awaited<ReturnType<EasyTierRuntime["bindTcp"]>>;
    const bindTcp = vi.fn().mockResolvedValue(listener);
    const runtime = Object.create(
      EasyTierRuntime.prototype,
    ) as EasyTierRuntime;
    Object.assign(runtime, {
      ready: Promise.resolve(),
      dataPlane: { bindTcp },
    });

    await expect(runtime.bindTcp(22, 500)).resolves.toBe(listener);
    expect(bindTcp).toHaveBeenCalledWith(22, 500);
  });

  it("stops and drops the guest exactly once before releasing host resources", async () => {
    const calls: string[] = [];
    let driveCount = 0;
    const dataPlane = {
      drainCompletions: vi.fn().mockResolvedValue(undefined),
      shutdown: vi.fn(),
    };
    const host = { shutdown: vi.fn() };
    const clock = {
      interrupt: vi.fn(),
      advanceMillis: vi.fn(),
    };
    const runtime = Object.create(
      EasyTierRuntime.prototype,
    ) as EasyTierRuntime;
    Object.assign(runtime, {
      ready: Promise.resolve(),
      serial: Promise.resolve(),
      instanceHandle: 7n,
      dataPlane,
      host,
      clock,
      stopping: false,
      stopPromise: undefined,
      armRequest: 0,
      timer: undefined,
      timerGeneration: 0,
      timerDueAt: undefined,
      completionRequested: false,
      pumpQueued: false,
      call: async (name: string) => {
        calls.push(name);
        switch (name) {
          case "instanceStop":
          case "instanceDrop":
            return 0;
          case "instanceDrive":
            driveCount += 1;
            return driveCount === 1 ? 3 : 4;
          case "nextDeadlineMillis":
            return 0n;
          default:
            throw new Error(`unexpected call: ${name}`);
        }
      },
    });

    const stopping = runtime.stop();
    expect(runtime.stop()).toBe(stopping);
    await stopping;

    expect(calls).toEqual([
      "instanceStop",
      "instanceDrive",
      "nextDeadlineMillis",
      "instanceDrive",
      "instanceDrop",
    ]);
    expect(dataPlane.drainCompletions).toHaveBeenCalledTimes(2);
    expect(dataPlane.shutdown).toHaveBeenCalledOnce();
    expect(host.shutdown).toHaveBeenCalledOnce();
    expect(clock.interrupt).toHaveBeenCalledTimes(2);
  });
});
