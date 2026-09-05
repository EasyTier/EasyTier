import { describe, expect, it } from "vitest";

import { WebSocketHost } from "../src/websocket-host";

type HostCall = (...parameters: Array<number | bigint>) => number;

class MockWebSocket {
  readonly sent: Uint8Array[] = [];
  readonly closes: Array<{ code?: number; reason?: string }> = [];
  bufferedAmount = 0;

  send(message: Uint8Array): void {
    this.sent.push(message.slice());
  }

  close(code?: number, reason?: string): void {
    this.closes.push({ code, reason });
  }
}

function call(
  host: WebSocketHost,
  name: string,
  ...parameters: Array<number | bigint>
): number {
  const imported = host.imports[name];
  if (typeof imported !== "function") {
    throw new Error(`missing host import ${name}`);
  }
  return (imported as HostCall)(...parameters);
}

function fixture(): {
  host: WebSocketHost;
  memory: WebAssembly.Memory;
  socket: MockWebSocket;
  handle: bigint;
} {
  const host = new WebSocketHost();
  const memory = new WebAssembly.Memory({ initial: 1 });
  host.bindMemory(memory);
  const socket = new MockWebSocket();
  const handle = host.register(socket as unknown as WebSocket);
  host.transferToGuest(handle);
  return { host, memory, socket, handle };
}

describe("WebSocketHost", () => {
  it("preserves binary message boundaries", () => {
    const { host, memory, handle } = fixture();
    host.receive(handle, new Uint8Array([1, 2, 3]).buffer);
    host.receive(handle, new Uint8Array([8, 9]).buffer);

    expect(call(host, "start_websocket_receive", handle, 10n, 64)).toBe(
      0,
    );
    expect(call(host, "take_websocket_receive", 10n, 100, 64)).toBe(3);
    expect(new Uint8Array(memory.buffer, 100, 3)).toEqual(
      new Uint8Array([1, 2, 3]),
    );

    expect(call(host, "start_websocket_receive", handle, 11n, 64)).toBe(
      0,
    );
    expect(call(host, "take_websocket_receive", 11n, 200, 64)).toBe(2);
    expect(new Uint8Array(memory.buffer, 200, 2)).toEqual(
      new Uint8Array([8, 9]),
    );
  });

  it("accounts for a ready receive until its probed message is taken", () => {
    const { host, memory, handle } = fixture();
    expect(call(host, "start_websocket_receive", handle, 12n, 64)).toBe(
      0,
    );

    host.receive(handle, new Uint8Array([1, 2, 3]).buffer);
    expect(host.health()).toEqual({
      connections: 1,
      queuedBytes: 3,
      pendingOperations: 1,
    });
    expect(call(host, "take_websocket_receive", 12n, 0, 0)).toBe(3);
    expect(host.health().queuedBytes).toBe(3);

    expect(call(host, "take_websocket_receive", 12n, 500, 3)).toBe(3);
    expect(new Uint8Array(memory.buffer, 500, 3)).toEqual(
      new Uint8Array([1, 2, 3]),
    );
    expect(host.health()).toEqual({
      connections: 1,
      queuedBytes: 0,
      pendingOperations: 0,
    });

    expect(call(host, "start_websocket_receive", handle, 13n, 64)).toBe(
      0,
    );
    host.receive(handle, new Uint8Array([4, 5]).buffer);
    expect(call(host, "cancel_operation", 13n)).toBe(0);
    expect(host.health().queuedBytes).toBe(0);

    expect(call(host, "start_websocket_receive", handle, 14n, 64)).toBe(
      0,
    );
    host.receive(handle, new ArrayBuffer(0));
    expect(call(host, "take_websocket_receive", 14n, 0, 0)).toBe(0);
    expect(call(host, "take_websocket_receive", 14n, 1, 0)).toBe(0);
    expect(host.health().pendingOperations).toBe(0);
  });

  it("copies outbound data before returning from submit", () => {
    const { host, memory, socket, handle } = fixture();
    const source = new Uint8Array(memory.buffer, 300, 3);
    source.set([4, 5, 6]);

    expect(call(host, "start_websocket_send", handle, 20n, 300, 3)).toBe(
      0,
    );
    source.fill(9);
    expect(call(host, "take_websocket_send", 20n)).toBe(0);
    expect(socket.sent).toEqual([new Uint8Array([4, 5, 6])]);
  });

  it("counts a ready receive against the per-connection byte limit", () => {
    const { host, socket, handle } = fixture();
    const megabyte = 1024 * 1024;
    expect(
      call(
        host,
        "start_websocket_receive",
        handle,
        21n,
        megabyte,
      ),
    ).toBe(0);

    host.receive(handle, new ArrayBuffer(megabyte));
    host.receive(handle, new ArrayBuffer(megabyte));
    expect(host.health().queuedBytes).toBe(2 * megabyte);

    host.receive(handle, new ArrayBuffer(1));
    expect(socket.closes).toContainEqual({
      code: 1009,
      reason: "receive queue limit",
    });
    expect(host.health().queuedBytes).toBe(2 * megabyte);

    expect(call(host, "close", handle)).toBe(0);
    expect(host.health().queuedBytes).toBe(0);
  });

  it("reports text and remote close as terminal receive statuses", () => {
    const { host, handle } = fixture();
    host.receive(handle, "not a packet");
    expect(call(host, "start_websocket_receive", handle, 30n, 64)).toBe(
      0,
    );
    expect(call(host, "take_websocket_receive", 30n, 400, 64)).toBe(
      -11,
    );

    expect(call(host, "start_websocket_receive", handle, 31n, 64)).toBe(
      0,
    );
    host.remoteClose(handle);
    expect(call(host, "take_websocket_receive", 31n, 400, 64)).toBe(
      -10,
    );
  });

  it("closes resources and cancellation idempotently", () => {
    const { host, socket, handle } = fixture();
    expect(call(host, "start_websocket_receive", handle, 40n, 64)).toBe(
      0,
    );
    expect(call(host, "cancel_operation", 40n)).toBe(0);
    expect(call(host, "cancel_operation", 40n)).toBe(0);
    expect(call(host, "close", handle)).toBe(0);
    expect(call(host, "close", handle)).toBe(0);

    expect(socket.closes).toHaveLength(1);
    expect(host.health()).toEqual({
      connections: 0,
      queuedBytes: 0,
      pendingOperations: 0,
    });
  });
});
