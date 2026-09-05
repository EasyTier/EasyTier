import { afterEach, describe, expect, it, vi } from "vitest";

import { EasyTierRuntime } from "../src/core-runtime";

interface RuntimeHarness {
  armNextDrive(): void;
  serial: Promise<void>;
}

interface AttachHarness {
  attachWebSocket(
    websocketHandle: bigint,
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

describe("EasyTierRuntime WebSocket ownership", () => {
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

    await runtime.attachWebSocket(2n, {
      version: 1,
      local_url: "wss://relay.example/",
      remote_url: "wss://client.example/",
    });

    expect(events).toEqual([
      "acceptWebSocket",
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
      runtime.attachWebSocket(2n, {
        version: 1,
        local_url: "wss://relay.example/",
        remote_url: "wss://client.example/",
      }),
    ).rejects.toThrow("drive failed");
    expect(events).toEqual(["transferToGuest", "abort"]);
  });
});
