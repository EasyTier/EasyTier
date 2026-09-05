import { describe, expect, it, vi } from "vitest";

import { WebSocketHost } from "../src/websocket-host";

type HostCall = (...parameters: Array<number | bigint>) => number | bigint;

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
): number | bigint {
  const imported = host.imports[name];
  if (typeof imported !== "function") {
    throw new Error(`missing host import ${name}`);
  }
  return (imported as HostCall)(...parameters);
}

class MockOutboundWebSocket extends MockWebSocket {
  binaryType: "blob" | "arraybuffer" = "blob";
  private readonly listeners = new Map<
    string,
    Array<(event: { data?: string | ArrayBuffer }) => void>
  >();

  addEventListener(
    type: string,
    listener: (event: { data?: string | ArrayBuffer }) => void,
  ): void {
    const listeners = this.listeners.get(type) ?? [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  emit(type: string, data?: string | ArrayBuffer): void {
    for (const listener of this.listeners.get(type) ?? []) {
      listener({ data });
    }
  }
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

function encodeTcpPortLease(
  memory: WebAssembly.Memory,
  pointer: number,
  port: number,
  purpose = 6,
): number {
  const options = new Uint8Array(memory.buffer, pointer, 48);
  options.fill(0);
  options[0] = 2;
  options[1] = 4;
  const view = new DataView(memory.buffer, pointer, options.byteLength);
  view.setUint16(18, port, false);
  options[42] = purpose;
  return options.byteLength;
}

describe("WebSocketHost", () => {
  it("isolates application event handler failures from the guest", () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => {});
    const host = new WebSocketHost(undefined, () => {
      throw new Error("application callback failed");
    });
    const memory = new WebAssembly.Memory({ initial: 1 });
    host.bindMemory(memory);
    const kind = new TextEncoder().encode("peer_added");
    const message = new TextEncoder().encode("connected");
    new Uint8Array(memory.buffer, 64, kind.byteLength).set(kind);
    new Uint8Array(memory.buffer, 128, message.byteLength).set(message);

    expect(
      call(
        host,
        "emit_event",
        2n,
        64,
        kind.byteLength,
        128,
        message.byteLength,
      ),
    ).toBe(0);
    expect(log).toHaveBeenCalledWith(
      expect.stringContaining("easytier_event_handler_failed"),
    );
    log.mockRestore();
  });

  it("releases every socket and pending operation on shutdown", () => {
    const { host, socket, handle } = fixture();
    expect(
      call(host, "start_tunnel_receive", handle, 99n, 1024),
    ).toBe(0);
    expect(host.health()).toEqual({
      connections: 1,
      queuedBytes: 0,
      pendingOperations: 1,
    });

    host.shutdown();
    host.shutdown();

    expect(host.health()).toEqual({
      connections: 0,
      queuedBytes: 0,
      pendingOperations: 0,
    });
    expect(socket.closes).toEqual([
      { code: 1000, reason: "EasyTier runtime stopped" },
    ]);
  });

  it("opens outbound WebSockets as guest-owned tunnel handles", () => {
    const sockets: MockOutboundWebSocket[] = [];
    const urls: string[] = [];
    const host = new WebSocketHost((url) => {
      urls.push(url);
      const socket = new MockOutboundWebSocket();
      sockets.push(socket);
      return socket as unknown as WebSocket;
    });
    const memory = new WebAssembly.Memory({ initial: 1 });
    host.bindMemory(memory);
    let wakes = 0;
    host.setWakeGuest(() => {
      wakes += 1;
    });
    const encoded = new TextEncoder().encode("wss://relay.example/");
    new Uint8Array(memory.buffer, 64, encoded.byteLength).set(encoded);

    expect(
      call(
        host,
        "start_tunnel_connect",
        1n,
        64,
        encoded.byteLength,
      ),
    ).toBe(0);
    expect(call(host, "take_tunnel_connect", 1n)).toBe(-1n);
    expect(urls).toEqual(["wss://relay.example/"]);
    const socket = sockets[0];
    expect(socket).toBeDefined();
    if (socket === undefined) {
      throw new Error("outbound WebSocket was not created");
    }
    expect(socket.binaryType).toBe("arraybuffer");

    socket.emit("open");
    expect(wakes).toBe(1);
    const handle = call(host, "take_tunnel_connect", 1n);
    expect(typeof handle).toBe("bigint");
    expect(handle).toBeGreaterThan(0n);
    expect(host.health()).toEqual({
      connections: 1,
      queuedBytes: 0,
      pendingOperations: 0,
    });
  });

  it("reports outbound WebSocket failure before ownership transfer", () => {
    const socket = new MockOutboundWebSocket();
    const host = new WebSocketHost(
      () => socket as unknown as WebSocket,
    );
    const memory = new WebAssembly.Memory({ initial: 1 });
    host.bindMemory(memory);
    const encoded = new TextEncoder().encode("ws://relay.example/");
    new Uint8Array(memory.buffer, 32, encoded.byteLength).set(encoded);

    expect(
      call(
        host,
        "start_tunnel_connect",
        2n,
        32,
        encoded.byteLength,
      ),
    ).toBe(0);
    socket.emit("error");
    expect(call(host, "take_tunnel_connect", 2n)).toBe(-10n);
    expect(host.health().connections).toBe(0);
  });

  it("rejects outbound WebSocket requests when no factory is installed", () => {
    const host = new WebSocketHost();
    const memory = new WebAssembly.Memory({ initial: 1 });
    host.bindMemory(memory);
    const encoded = new TextEncoder().encode("ws://relay.example/");
    new Uint8Array(memory.buffer, 16, encoded.byteLength).set(encoded);

    expect(
      call(
        host,
        "start_tunnel_connect",
        3n,
        16,
        encoded.byteLength,
      ),
    ).toBe(-4);
  });

  it("leases browser-local TCP ports for the smoltcp data plane", () => {
    const host = new WebSocketHost(() => {
      throw new Error("unexpected WebSocket connection");
    });
    const memory = new WebAssembly.Memory({ initial: 1 });
    host.bindMemory(memory);
    const optionsLength = encodeTcpPortLease(memory, 128, 55_000);

    expect(call(host, "start_tcp_bind", 4n, 128, optionsLength)).toBe(0);
    expect(call(host, "start_tcp_bind", 4n, 128, optionsLength)).toBe(-3);
    expect(call(host, "take_tcp_bind", 4n, 256, 35)).toBe(0);

    const result = new Uint8Array(memory.buffer, 256, 35);
    const resultView = new DataView(
      result.buffer,
      result.byteOffset,
      result.byteLength,
    );
    const handle = resultView.getBigUint64(0, false);
    expect(handle).toBeGreaterThan(0n);
    expect(result[8]).toBe(4);
    expect(resultView.getUint16(25, false)).toBe(55_000);

    expect(call(host, "start_tcp_bind", 5n, 128, optionsLength)).toBe(-3);
    expect(call(host, "close", handle)).toBe(0);
    expect(call(host, "start_tcp_bind", 6n, 128, optionsLength)).toBe(0);
    expect(call(host, "cancel_operation", 6n)).toBe(0);
  });

  it("rejects host TCP listeners other than browser port leases", () => {
    const host = new WebSocketHost(() => {
      throw new Error("unexpected WebSocket connection");
    });
    const memory = new WebAssembly.Memory({ initial: 1 });
    host.bindMemory(memory);

    const optionsLength = encodeTcpPortLease(memory, 128, 0, 4);
    expect(call(host, "start_tcp_bind", 7n, 128, optionsLength)).toBe(-4);

    const inboundOnlyHost = new WebSocketHost();
    inboundOnlyHost.bindMemory(memory);
    encodeTcpPortLease(memory, 128, 0);
    expect(
      call(inboundOnlyHost, "start_tcp_bind", 8n, 128, optionsLength),
    ).toBe(-4);
  });

  it("preserves binary message boundaries", () => {
    const { host, memory, handle } = fixture();
    host.receive(handle, new Uint8Array([1, 2, 3]).buffer);
    host.receive(handle, new Uint8Array([8, 9]).buffer);

    expect(call(host, "start_tunnel_receive", handle, 10n, 64)).toBe(
      0,
    );
    expect(call(host, "take_tunnel_receive", 10n, 100, 64)).toBe(3);
    expect(new Uint8Array(memory.buffer, 100, 3)).toEqual(
      new Uint8Array([1, 2, 3]),
    );

    expect(call(host, "start_tunnel_receive", handle, 11n, 64)).toBe(
      0,
    );
    expect(call(host, "take_tunnel_receive", 11n, 200, 64)).toBe(2);
    expect(new Uint8Array(memory.buffer, 200, 2)).toEqual(
      new Uint8Array([8, 9]),
    );
  });

  it("accounts for a ready receive until its probed message is taken", () => {
    const { host, memory, handle } = fixture();
    expect(call(host, "start_tunnel_receive", handle, 12n, 64)).toBe(
      0,
    );

    host.receive(handle, new Uint8Array([1, 2, 3]).buffer);
    expect(host.health()).toEqual({
      connections: 1,
      queuedBytes: 3,
      pendingOperations: 1,
    });
    expect(call(host, "take_tunnel_receive", 12n, 0, 0)).toBe(3);
    expect(host.health().queuedBytes).toBe(3);

    expect(call(host, "take_tunnel_receive", 12n, 500, 3)).toBe(3);
    expect(new Uint8Array(memory.buffer, 500, 3)).toEqual(
      new Uint8Array([1, 2, 3]),
    );
    expect(host.health()).toEqual({
      connections: 1,
      queuedBytes: 0,
      pendingOperations: 0,
    });

    expect(call(host, "start_tunnel_receive", handle, 13n, 64)).toBe(
      0,
    );
    host.receive(handle, new Uint8Array([4, 5]).buffer);
    expect(call(host, "cancel_operation", 13n)).toBe(0);
    expect(host.health().queuedBytes).toBe(0);

    expect(call(host, "start_tunnel_receive", handle, 14n, 64)).toBe(
      0,
    );
    host.receive(handle, new ArrayBuffer(0));
    expect(call(host, "take_tunnel_receive", 14n, 0, 0)).toBe(0);
    expect(call(host, "take_tunnel_receive", 14n, 1, 0)).toBe(0);
    expect(host.health().pendingOperations).toBe(0);
  });

  it("copies outbound data before returning from submit", () => {
    const { host, memory, socket, handle } = fixture();
    const source = new Uint8Array(memory.buffer, 300, 3);
    source.set([4, 5, 6]);

    expect(call(host, "start_tunnel_send", handle, 20n, 300, 3)).toBe(
      0,
    );
    source.fill(9);
    expect(call(host, "take_tunnel_send", 20n)).toBe(0);
    expect(socket.sent).toEqual([new Uint8Array([4, 5, 6])]);
  });

  it("counts a ready receive against the per-connection byte limit", () => {
    const { host, socket, handle } = fixture();
    const megabyte = 1024 * 1024;
    expect(
      call(
        host,
        "start_tunnel_receive",
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

  it("rejects text before exposing the tunnel payload ABI", () => {
    const { host, socket, handle } = fixture();
    host.receive(handle, "not a packet");
    expect(socket.closes).toContainEqual({
      code: 1003,
      reason: "binary tunnel payload required",
    });
    expect(call(host, "start_tunnel_receive", handle, 30n, 64)).toBe(0);
    expect(call(host, "take_tunnel_receive", 30n, 400, 64)).toBe(-3);
  });

  it("reports remote close as tunnel EOF", () => {
    const { host, handle } = fixture();
    expect(call(host, "start_tunnel_receive", handle, 31n, 64)).toBe(0);
    host.remoteClose(handle);
    expect(call(host, "take_tunnel_receive", 31n, 400, 64)).toBe(
      -10,
    );
  });

  it("closes resources and cancellation idempotently", () => {
    const { host, socket, handle } = fixture();
    expect(call(host, "start_tunnel_receive", handle, 40n, 64)).toBe(
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
