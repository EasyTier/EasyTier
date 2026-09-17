import { describe, expect, it } from "vitest";

import {
  EasyTierDataPlane,
  type DataPlaneBindings,
  type DataPlaneExportName,
  type DataPlaneValue,
} from "../src/data-plane";

const CONNECT_OPERATION = 101n;
const READ_OPERATION = 102n;
const WRITE_OPERATION = 103n;
const BIND_OPERATION = 104n;
const ACCEPT_OPERATION = 105n;
const SHUTDOWN_OPERATION = 106n;
const STREAM_RESOURCE = 501n;
const ACCEPTED_STREAM_RESOURCE = 502n;
const LISTENER_RESOURCE = 601n;

class DataPlaneFixture implements DataPlaneBindings {
  readonly instanceHandle = 17n;
  readonly memory = new WebAssembly.Memory({ initial: 1 });
  readonly closedResources: bigint[] = [];
  readonly boundPorts: number[] = [];
  readonly acceptedListeners: bigint[] = [];
  readonly shutdownResources: bigint[] = [];
  readonly submittedAddresses: Uint8Array[] = [];
  readonly submittedTimeouts: bigint[] = [];
  readonly writes: Uint8Array[] = [];
  onDrive: () => Promise<void> = async () => {};

  private nextPointer = 1024;
  private readonly completions: Array<{
    operation: bigint;
    kind: number;
    status: number;
  }> = [];

  async call(
    name: DataPlaneExportName,
    parameters: DataPlaneValue[],
  ): Promise<DataPlaneValue> {
    switch (name) {
      case "dataPlaneAbiVersion":
        return 4;
      case "dataPlaneCapabilities":
        return 2n;
      case "dataPlaneTcpConnectSubmit": {
        const addressPointer = Number(parameters[1]);
        this.submittedAddresses.push(this.readGuest(addressPointer, 27));
        this.submittedTimeouts.push(BigInt(parameters[2]!));
        this.writeU64(Number(parameters[3]), CONNECT_OPERATION);
        this.completions.push({
          operation: CONNECT_OPERATION,
          kind: 1,
          status: 0,
        });
        return 0;
      }
      case "dataPlaneTcpBindSubmit":
        this.boundPorts.push(Number(parameters[1]));
        this.submittedTimeouts.push(BigInt(parameters[2]!));
        this.writeU64(Number(parameters[3]), BIND_OPERATION);
        this.completions.push({
          operation: BIND_OPERATION,
          kind: 2,
          status: 0,
        });
        return 0;
      case "dataPlaneTcpAcceptSubmit":
        this.acceptedListeners.push(BigInt(parameters[1]!));
        this.submittedTimeouts.push(BigInt(parameters[2]!));
        this.writeU64(Number(parameters[3]), ACCEPT_OPERATION);
        this.completions.push({
          operation: ACCEPT_OPERATION,
          kind: 3,
          status: 0,
        });
        return 0;
      case "dataPlaneTcpReadSubmit":
        expect(parameters[1]).toBe(STREAM_RESOURCE);
        this.writeU64(Number(parameters[3]), READ_OPERATION);
        this.completions.push({
          operation: READ_OPERATION,
          kind: 4,
          status: 0,
        });
        return 0;
      case "dataPlaneTcpWriteSubmit": {
        expect(parameters[1]).toBe(STREAM_RESOURCE);
        const length = Number(parameters[3]);
        this.writes.push(this.readGuest(Number(parameters[2]), length));
        this.writeU64(Number(parameters[4]), WRITE_OPERATION);
        this.completions.push({
          operation: WRITE_OPERATION,
          kind: 5,
          status: 0,
        });
        return 0;
      }
      case "dataPlaneTcpShutdownWriteSubmit":
        this.shutdownResources.push(BigInt(parameters[1]!));
        this.writeU64(Number(parameters[2]), SHUTDOWN_OPERATION);
        this.completions.push({
          operation: SHUTDOWN_OPERATION,
          kind: 9,
          status: 0,
        });
        return 0;
      case "dataPlaneCompletionDrain": {
        const output = Number(parameters[1]);
        const capacity = Number(parameters[2]);
        const count = Math.min(capacity, this.completions.length);
        const view = new DataView(this.memory.buffer);
        for (let index = 0; index < count; index += 1) {
          const completion = this.completions[index];
          if (completion === undefined) {
            throw new Error("completion queue changed while draining");
          }
          const offset = output + index * 12;
          view.setBigUint64(offset, completion.operation, false);
          view.setUint16(offset + 8, completion.kind, false);
          view.setUint16(offset + 10, completion.status, false);
        }
        this.completions.splice(0, count);
        return count;
      }
      case "dataPlaneTcpConnectResultTake":
        expect(parameters[1]).toBe(CONNECT_OPERATION);
        this.writeU64(Number(parameters[2]), STREAM_RESOURCE);
        this.writeSocketAddress(Number(parameters[2]) + 8, "10.1.2.4", 40000);
        this.writeSocketAddress(Number(parameters[2]) + 35, "10.1.2.3", 8080);
        return 0;
      case "dataPlaneTcpBindResultTake":
        expect(parameters[1]).toBe(BIND_OPERATION);
        this.writeU64(Number(parameters[2]), LISTENER_RESOURCE);
        this.writeSocketAddress(Number(parameters[2]) + 8, "10.1.2.4", 32123);
        return 0;
      case "dataPlaneTcpAcceptResultTake":
        expect(parameters[1]).toBe(ACCEPT_OPERATION);
        this.writeU64(Number(parameters[2]), ACCEPTED_STREAM_RESOURCE);
        this.writeSocketAddress(Number(parameters[2]) + 8, "10.1.2.4", 32123);
        this.writeSocketAddress(Number(parameters[2]) + 35, "10.1.2.5", 44000);
        return 0;
      case "dataPlaneResultSize":
        expect(parameters[1]).toBe(READ_OPERATION);
        return 5;
      case "dataPlaneTcpReadResultTake": {
        expect(parameters[1]).toBe(READ_OPERATION);
        const data = new TextEncoder().encode("hello");
        new Uint8Array(
          this.memory.buffer,
          Number(parameters[2]),
          data.byteLength,
        ).set(data);
        new Uint8Array(this.memory.buffer, Number(parameters[4]), 1)[0] = 1;
        return data.byteLength;
      }
      case "dataPlaneTcpWriteResultTake":
        expect(parameters[1]).toBe(WRITE_OPERATION);
        return this.writes.at(-1)?.byteLength ?? 0;
      case "dataPlaneTcpShutdownWriteResultTake":
        expect(parameters[1]).toBe(SHUTDOWN_OPERATION);
        return 0;
      case "dataPlaneResourceClose":
        this.closedResources.push(BigInt(parameters[1]!));
        return 0;
      case "dataPlaneOperationFree":
        return 0;
    }
  }

  async allocate(length: number): Promise<number> {
    const pointer = this.nextPointer;
    this.nextPointer += Math.max(length, 1) + 8;
    return pointer;
  }

  async free(_pointer: number): Promise<void> {}

  async copyIntoGuest(bytes: Uint8Array): Promise<number> {
    const pointer = await this.allocate(bytes.byteLength);
    new Uint8Array(this.memory.buffer, pointer, bytes.byteLength).set(bytes);
    return pointer;
  }

  readGuest(pointer: number, length: number): Uint8Array {
    return new Uint8Array(this.memory.buffer, pointer, length).slice();
  }

  async instanceError(context: string): Promise<string> {
    return `${context} failed`;
  }

  runExclusive<T>(operation: () => Promise<T>): Promise<T> {
    return operation();
  }

  drive(): Promise<void> {
    return this.onDrive();
  }

  private writeU64(pointer: number, value: bigint): void {
    new DataView(this.memory.buffer).setBigUint64(pointer, value, false);
  }

  private writeSocketAddress(
    pointer: number,
    ipv4: string,
    port: number,
  ): void {
    const bytes = new Uint8Array(this.memory.buffer, pointer, 27);
    bytes.fill(0);
    bytes[0] = 4;
    bytes.set(ipv4.split(".").map(Number), 1);
    new DataView(this.memory.buffer).setUint16(pointer + 17, port, false);
  }
}

describe("EasyTierDataPlane", () => {
  it("connects, exchanges bytes, and closes an IPv4 TCP stream", async () => {
    const bindings = new DataPlaneFixture();
    const dataPlane = new EasyTierDataPlane(bindings);
    bindings.onDrive = () => dataPlane.drainCompletions();
    await dataPlane.initialize();

    const stream = await dataPlane.connectTcp("10.1.2.3", 8080, 250);
    expect(bindings.submittedTimeouts).toEqual([250n]);
    const address = bindings.submittedAddresses[0];
    expect(address?.subarray(0, 5)).toEqual(
      new Uint8Array([4, 10, 1, 2, 3]),
    );
    expect(
      new DataView(
        address!.buffer,
        address!.byteOffset,
        address!.byteLength,
      ).getUint16(17, false),
    ).toBe(8080);
    expect(stream.localAddress).toEqual({ ipv4: "10.1.2.4", port: 40000 });
    expect(stream.peerAddress).toEqual({ ipv4: "10.1.2.3", port: 8080 });

    expect(await stream.write(new TextEncoder().encode("request"))).toBe(7);
    expect(bindings.writes).toEqual([new TextEncoder().encode("request")]);
    await expect(stream.read()).resolves.toEqual({
      data: new TextEncoder().encode("hello"),
      eof: true,
    });

    await stream.shutdownWrite();
    await stream.shutdownWrite();
    expect(bindings.shutdownResources).toEqual([STREAM_RESOURCE]);
    await expect(stream.write(new Uint8Array([1]))).rejects.toThrow(
      "TCP stream write side is shut down",
    );
    await expect(stream.read()).resolves.toEqual({
      data: new TextEncoder().encode("hello"),
      eof: true,
    });

    await stream.close();
    await stream.close();
    expect(bindings.closedResources).toEqual([STREAM_RESOURCE]);
    expect(() => stream.read()).toThrow("TCP stream is closed");
  });

  it("binds a TCP listener and accepts streams with endpoint metadata", async () => {
    const bindings = new DataPlaneFixture();
    const dataPlane = new EasyTierDataPlane(bindings);
    bindings.onDrive = () => dataPlane.drainCompletions();
    await dataPlane.initialize();

    const listener = await dataPlane.bindTcp(0, 500);
    expect(listener.localAddress).toEqual({
      ipv4: "10.1.2.4",
      port: 32123,
    });
    expect(bindings.boundPorts).toEqual([0]);

    const stream = await listener.accept(750);
    expect(bindings.acceptedListeners).toEqual([LISTENER_RESOURCE]);
    expect(bindings.submittedTimeouts).toEqual([500n, 750n]);
    expect(stream.localAddress).toEqual({
      ipv4: "10.1.2.4",
      port: 32123,
    });
    expect(stream.peerAddress).toEqual({
      ipv4: "10.1.2.5",
      port: 44000,
    });

    await stream.close();
    await listener.close();
    await listener.close();
    expect(bindings.closedResources).toEqual([
      ACCEPTED_STREAM_RESOURCE,
      LISTENER_RESOURCE,
    ]);
    expect(() => listener.accept()).toThrow("TCP listener is closed");
  });

  it("rejects invalid browser TCP endpoints before guest submission", async () => {
    const bindings = new DataPlaneFixture();
    const dataPlane = new EasyTierDataPlane(bindings);
    await dataPlane.initialize();

    expect(() => dataPlane.connectTcp("example.com", 443)).toThrow(
      "invalid IPv4 address",
    );
    expect(() => dataPlane.connectTcp("10.0.0.1", 0)).toThrow(
      "TCP port must be between 1 and 65535",
    );
    expect(() => dataPlane.bindTcp(-1)).toThrow(
      "TCP local port must be between 0 and 65535",
    );
  });

  it("invalidates existing resources when the runtime stops", async () => {
    const bindings = new DataPlaneFixture();
    const dataPlane = new EasyTierDataPlane(bindings);
    bindings.onDrive = () => dataPlane.drainCompletions();
    await dataPlane.initialize();
    const listener = await dataPlane.bindTcp(22);

    dataPlane.shutdown();

    await expect(listener.accept()).rejects.toThrow(
      "EasyTier runtime is stopped",
    );
    await expect(listener.close()).rejects.toThrow(
      "EasyTier runtime is stopped",
    );
  });
});
