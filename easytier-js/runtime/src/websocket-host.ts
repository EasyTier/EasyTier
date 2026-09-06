const HOST_PENDING = -1;
const HOST_INVALID = -3;
const HOST_UNSUPPORTED = -4;
const HOST_TUNNEL_CLOSED = -10;

const PACKET_SINK_HANDLE = 1n;
const EVENT_SINK_HANDLE = 2n;
const FIRST_WEBSOCKET_HANDLE = 3n;
const MAX_CONNECTIONS = 256;
const MAX_MESSAGE_BYTES = 1024 * 1024;
const MAX_QUEUED_MESSAGES = 64;
const MAX_QUEUED_BYTES_PER_CONNECTION = 2 * 1024 * 1024;
const MAX_QUEUED_BYTES_PER_OBJECT = 16 * 1024 * 1024;
const MAX_BUFFERED_SEND_BYTES = 4 * 1024 * 1024;
const MAX_URL_BYTES = 16 * 1024;

type IncomingMessage =
  | { kind: "binary"; bytes: Uint8Array }
  | { kind: "error"; status: number };

type ReceiveOperation =
  | {
      kind: "receive";
      handle: bigint;
      capacity: number;
      state: "pending";
    }
  | {
      kind: "receive";
      handle: bigint;
      capacity: number;
      state: "ready";
      message: IncomingMessage;
    };

interface SendOperation {
  kind: "send";
  handle: bigint;
  state: "ready";
  status: number;
}

type ConnectOperation = {
  kind: "connect";
  handle: bigint;
  state: "pending" | "ready";
  result: bigint;
};

type TcpPortLeaseOperation = {
  kind: "tcp-port-lease";
  handle: bigint;
  port: number;
  state: "ready";
};

type HostOperation =
  | ReceiveOperation
  | SendOperation
  | ConnectOperation
  | TcpPortLeaseOperation;

interface WebSocketState {
  socket: RuntimeWebSocket;
  incoming: IncomingMessage[];
  queuedBytes: number;
  pendingReceive: bigint | undefined;
  remoteClosed: boolean;
  guestOwned: boolean;
}

export interface RuntimeWebSocketEvent {
  data?: string | ArrayBuffer;
}

export interface RuntimeWebSocket {
  binaryType: string;
  readonly bufferedAmount?: number;
  send(message: Uint8Array): void;
  close(code?: number, reason?: string): void;
  addEventListener(
    type: "open" | "message" | "close" | "error",
    listener: (event: RuntimeWebSocketEvent) => void,
  ): void;
  accept?(): void;
}

export interface WebSocketHostHealth {
  connections: number;
  queuedBytes: number;
  pendingOperations: number;
}

export interface EasyTierCoreEvent {
  kind: string;
  message: string;
}

export class WebSocketHost {
  private readonly sockets = new Map<bigint, WebSocketState>();
  private readonly tcpPortLeases = new Map<bigint, number>();
  private readonly operations = new Map<bigint, HostOperation>();
  private nextHandle = FIRST_WEBSOCKET_HANDLE;
  private nextTcpPort = 49_152;
  private totalQueuedBytes = 0;
  private wakeGuest: () => void = () => {};
  private wasmMemory: WebAssembly.Memory | undefined;

  constructor(
    private readonly outboundFactory?: (url: string) => RuntimeWebSocket,
    private readonly onEvent: (event: EasyTierCoreEvent) => void = (event) => {
      console.log(JSON.stringify({ event: "easytier_core_event", ...event }));
    },
  ) {}

  readonly imports: WebAssembly.Imports["easytier_host"] = {
    emit_event: (
      handle: bigint,
      kind: number,
      kindLength: number,
      message: number,
      messageLength: number,
    ) => this.emitEvent(handle, kind, kindLength, message, messageLength),
    start_tunnel_receive: (
      handle: bigint,
      operation: bigint,
      capacity: number,
    ) => this.startReceive(handle, operation, capacity),
    take_tunnel_receive: (
      operation: bigint,
      destination: number,
      capacity: number,
    ) => this.takeReceive(operation, destination, capacity),
    start_tunnel_send: (
      handle: bigint,
      operation: bigint,
      source: number,
      length: number,
    ) => this.startSend(handle, operation, source, length),
    take_tunnel_send: (operation: bigint) => this.takeSend(operation),
    start_tunnel_connect: (
      operation: bigint,
      url: number,
      urlLength: number,
    ) => this.startConnect(operation, url, urlLength),
    take_tunnel_connect: (operation: bigint) =>
      this.takeConnect(operation),
    cancel_operation: (operation: bigint) => this.cancelOperation(operation),
    close: (handle: bigint) => this.closeHandle(handle),
    try_packet_write: (
      handle: bigint,
      _packet: number,
      _packetLength: number,
    ) => (handle === PACKET_SINK_HANDLE ? 0 : HOST_INVALID),
    start_packet_write_ready: () => HOST_UNSUPPORTED,
    take_packet_write_ready: () => HOST_UNSUPPORTED,
    start_read: () => HOST_UNSUPPORTED,
    take_read: () => HOST_UNSUPPORTED,
    start_write: () => HOST_UNSUPPORTED,
    take_write: () => HOST_UNSUPPORTED,
    start_udp_recv: () => HOST_UNSUPPORTED,
    take_udp_recv: () => HOST_UNSUPPORTED,
    try_udp_send: () => HOST_UNSUPPORTED,
    start_udp_send_ready: () => HOST_UNSUPPORTED,
    take_udp_send_ready: () => HOST_UNSUPPORTED,
    start_tcp_connect: () => HOST_UNSUPPORTED,
    take_tcp_connect: () => HOST_UNSUPPORTED,
    start_udp_bind: () => HOST_UNSUPPORTED,
    take_udp_bind: () => HOST_UNSUPPORTED,
    start_tcp_bind: (
      operation: bigint,
      options: number,
      optionsLength: number,
    ) => this.startTcpBind(operation, options, optionsLength),
    take_tcp_bind: (
      operation: bigint,
      destination: number,
      capacity: number,
    ) => this.takeTcpBind(operation, destination, capacity),
    start_tcp_accept: () => HOST_UNSUPPORTED,
    take_tcp_accept: () => HOST_UNSUPPORTED,
    start_dns_resolve: () => HOST_UNSUPPORTED,
    take_dns_resolve: () => HOST_UNSUPPORTED,
    start_dns_txt: () => HOST_UNSUPPORTED,
    take_dns_txt: () => HOST_UNSUPPORTED,
    start_dns_srv: () => HOST_UNSUPPORTED,
    take_dns_srv: () => HOST_UNSUPPORTED,
    start_local_addr_for_remote: () => HOST_UNSUPPORTED,
    take_local_addr_for_remote: () => HOST_UNSUPPORTED,
  };

  bindMemory(memory: WebAssembly.Memory): void {
    this.wasmMemory = memory;
  }

  setWakeGuest(wakeGuest: () => void): void {
    this.wakeGuest = wakeGuest;
  }

  canAccept(): boolean {
    return this.sockets.size < MAX_CONNECTIONS;
  }

  register(socket: RuntimeWebSocket): bigint {
    if (!this.canAccept()) {
      throw new Error("WebSocket connection limit reached");
    }
    const handle = this.allocateHandle();
    this.sockets.set(handle, {
      socket,
      incoming: [],
      queuedBytes: 0,
      pendingReceive: undefined,
      remoteClosed: false,
      guestOwned: false,
    });
    return handle;
  }

  transferToGuest(handle: bigint): void {
    const state = this.requireSocket(handle);
    state.guestOwned = true;
  }

  reject(handle: bigint): void {
    const state = this.sockets.get(handle);
    if (state === undefined || state.guestOwned) {
      return;
    }
    this.releaseSocket(handle, state, 1011, "EasyTier attach failed");
  }

  abort(handle: bigint, reason: string): void {
    const state = this.sockets.get(handle);
    if (state === undefined) {
      return;
    }
    this.releaseSocket(handle, state, 1011, reason);
  }

  receive(handle: bigint, data: string | ArrayBuffer): void {
    const state = this.sockets.get(handle);
    if (state === undefined || state.remoteClosed) {
      return;
    }
    if (typeof data === "string") {
      this.terminateWithError(
        handle,
        state,
        1003,
        "binary tunnel payload required",
      );
      return;
    }
    if (data.byteLength > MAX_MESSAGE_BYTES) {
      this.terminateWithError(handle, state, 1009, "message too large");
      return;
    }
    const bytes = new Uint8Array(data).slice();
    this.enqueue(handle, state, { kind: "binary", bytes }, bytes.byteLength);
  }

  remoteClose(handle: bigint): void {
    const state = this.sockets.get(handle);
    if (state === undefined || state.remoteClosed) {
      return;
    }
    state.remoteClosed = true;
    if (state.pendingReceive !== undefined && state.incoming.length === 0) {
      this.completeReceive(state.pendingReceive, {
        kind: "error",
        status: HOST_TUNNEL_CLOSED,
      });
    }
  }

  remoteError(handle: bigint): void {
    const state = this.sockets.get(handle);
    if (state === undefined || state.remoteClosed) {
      return;
    }
    this.terminateWithError(handle, state, 1011, "WebSocket error");
  }

  health(): WebSocketHostHealth {
    return {
      connections: this.sockets.size,
      queuedBytes: this.totalQueuedBytes,
      pendingOperations: this.operations.size,
    };
  }

  shutdown(reason = "EasyTier runtime stopped"): void {
    for (const [handle, state] of [...this.sockets]) {
      this.releaseSocket(handle, state, 1000, reason);
    }
    this.tcpPortLeases.clear();
    this.operations.clear();
    this.totalQueuedBytes = 0;
    this.wasmMemory = undefined;
    this.wakeGuest = () => {};
  }

  private emitEvent(
    handle: bigint,
    kindPointer: number,
    kindLength: number,
    messagePointer: number,
    messageLength: number,
  ): number {
    if (handle !== EVENT_SINK_HANDLE) {
      return HOST_INVALID;
    }
    const decoder = new TextDecoder();
    try {
      this.onEvent({
        kind: decoder.decode(this.memoryBytes(kindPointer, kindLength)),
        message: decoder.decode(this.memoryBytes(messagePointer, messageLength)),
      });
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "easytier_event_handler_failed",
          error: String(error),
        }),
      );
    }
    return 0;
  }

  private startConnect(
    operation: bigint,
    urlPointer: number,
    urlLength: number,
  ): number {
    if (this.outboundFactory === undefined) {
      return HOST_UNSUPPORTED;
    }
    if (
      urlLength <= 0 ||
      urlLength > MAX_URL_BYTES ||
      this.operations.has(operation) ||
      !this.canAccept()
    ) {
      return HOST_INVALID;
    }

    let requestedUrl: string;
    let socket: RuntimeWebSocket;
    try {
      requestedUrl = new TextDecoder("utf-8", {
        fatal: true,
        ignoreBOM: false,
      }).decode(
        this.memoryBytes(urlPointer, urlLength),
      );
      const parsed = new URL(requestedUrl);
      if (parsed.protocol !== "ws:" && parsed.protocol !== "wss:") {
        return HOST_INVALID;
      }
      socket = this.outboundFactory(requestedUrl);
    } catch {
      return HOST_INVALID;
    }

    socket.binaryType = "arraybuffer";
    const handle = this.register(socket);
    this.operations.set(operation, {
      kind: "connect",
      handle,
      state: "pending",
      result: BigInt(HOST_PENDING),
    });
    socket.addEventListener("open", () => {
      this.completeConnect(operation, handle);
    });
    socket.addEventListener("message", (event) => {
      if (typeof event.data === "string" || event.data instanceof ArrayBuffer) {
        this.receive(handle, event.data);
      } else {
        this.remoteError(handle);
      }
    });
    socket.addEventListener("close", () => {
      if (!this.failConnect(operation, handle, HOST_TUNNEL_CLOSED)) {
        this.remoteClose(handle);
      }
    });
    socket.addEventListener("error", () => {
      if (!this.failConnect(operation, handle, HOST_TUNNEL_CLOSED)) {
        this.remoteError(handle);
      }
    });
    return 0;
  }

  private takeConnect(operation: bigint): bigint {
    const pending = this.operations.get(operation);
    if (pending === undefined || pending.kind !== "connect") {
      return BigInt(HOST_INVALID);
    }
    if (pending.state === "pending") {
      return BigInt(HOST_PENDING);
    }
    this.operations.delete(operation);
    if (pending.result > 0n) {
      this.transferToGuest(pending.handle);
    }
    return pending.result;
  }

  private completeConnect(operation: bigint, handle: bigint): void {
    const pending = this.operations.get(operation);
    if (
      pending === undefined ||
      pending.kind !== "connect" ||
      pending.handle !== handle ||
      pending.state !== "pending"
    ) {
      return;
    }
    this.operations.set(operation, {
      ...pending,
      state: "ready",
      result: handle,
    });
    this.wakeGuest();
  }

  private failConnect(
    operation: bigint,
    handle: bigint,
    status: number,
  ): boolean {
    const pending = this.operations.get(operation);
    if (
      pending === undefined ||
      pending.kind !== "connect" ||
      pending.handle !== handle
    ) {
      return false;
    }
    const state = this.sockets.get(handle);
    if (state !== undefined) {
      this.sockets.delete(handle);
      this.totalQueuedBytes -= state.queuedBytes;
      try {
        state.socket.close(1011, "WebSocket connect failed");
      } catch {
        // The browser has already made the endpoint terminal.
      }
    }
    this.operations.set(operation, {
      ...pending,
      state: "ready",
      result: BigInt(status),
    });
    this.wakeGuest();
    return true;
  }

  private startReceive(
    handle: bigint,
    operation: bigint,
    capacity: number,
  ): number {
    if (
      capacity < 0 ||
      capacity > MAX_MESSAGE_BYTES ||
      this.operations.has(operation)
    ) {
      return HOST_INVALID;
    }
    const state = this.sockets.get(handle);
    if (state === undefined || state.pendingReceive !== undefined) {
      return HOST_INVALID;
    }
    const queued = state.incoming.shift();
    if (queued !== undefined) {
      this.operations.set(operation, {
        kind: "receive",
        handle,
        capacity,
        state: "ready",
        message: queued,
      });
      return 0;
    }
    if (state.remoteClosed) {
      this.operations.set(operation, {
        kind: "receive",
        handle,
        capacity,
        state: "ready",
        message: { kind: "error", status: HOST_TUNNEL_CLOSED },
      });
      return 0;
    }
    state.pendingReceive = operation;
    this.operations.set(operation, {
      kind: "receive",
      handle,
      capacity,
      state: "pending",
    });
    return 0;
  }

  private takeReceive(
    operation: bigint,
    destination: number,
    capacity: number,
  ): number {
    const pending = this.operations.get(operation);
    if (pending === undefined || pending.kind !== "receive") {
      return HOST_INVALID;
    }
    if (pending.state === "pending") {
      return HOST_PENDING;
    }
    const { message } = pending;
    if (message.kind === "error") {
      this.operations.delete(operation);
      return message.status;
    }
    if (message.bytes.byteLength > pending.capacity) {
      this.operations.delete(operation);
      this.removeQueuedBytesForHandle(pending.handle, message);
      return HOST_INVALID;
    }
    if (destination === 0 && capacity === 0) {
      return message.bytes.byteLength;
    }
    this.operations.delete(operation);
    this.removeQueuedBytesForHandle(pending.handle, message);
    if (message.bytes.byteLength > capacity) {
      return HOST_INVALID;
    }
    const destinationBytes = this.memoryBytes(destination, capacity);
    destinationBytes.set(message.bytes);
    return message.bytes.byteLength;
  }

  private startSend(
    handle: bigint,
    operation: bigint,
    source: number,
    length: number,
  ): number {
    if (
      length < 0 ||
      length > MAX_MESSAGE_BYTES ||
      this.operations.has(operation)
    ) {
      return HOST_INVALID;
    }
    const state = this.sockets.get(handle);
    if (state === undefined || state.remoteClosed) {
      return HOST_TUNNEL_CLOSED;
    }
    const bufferedAmount = Reflect.get(state.socket, "bufferedAmount");
    if (
      typeof bufferedAmount === "number" &&
      bufferedAmount + length > MAX_BUFFERED_SEND_BYTES
    ) {
      this.terminateWithError(handle, state, 1009, "send buffer limit");
      return HOST_INVALID;
    }
    const message = this.memoryBytes(source, length).slice();
    let status = 0;
    try {
      state.socket.send(message);
    } catch {
      status = HOST_TUNNEL_CLOSED;
    }
    this.operations.set(operation, {
      kind: "send",
      handle,
      state: "ready",
      status,
    });
    return 0;
  }

  private takeSend(operation: bigint): number {
    const pending = this.operations.get(operation);
    if (pending === undefined || pending.kind !== "send") {
      return HOST_INVALID;
    }
    this.operations.delete(operation);
    return pending.status;
  }

  private cancelOperation(operation: bigint): number {
    const pending = this.operations.get(operation);
    if (pending?.kind === "connect") {
      const state = this.sockets.get(pending.handle);
      if (state !== undefined) {
        this.releaseSocket(
          pending.handle,
          state,
          1000,
          "WebSocket connect cancelled",
        );
      }
    } else if (pending?.kind === "receive" && pending.state === "pending") {
      const state = this.sockets.get(pending.handle);
      if (state?.pendingReceive === operation) {
        state.pendingReceive = undefined;
      }
    } else if (pending?.kind === "receive") {
      this.removeQueuedBytesForHandle(pending.handle, pending.message);
    } else if (pending?.kind === "tcp-port-lease") {
      this.tcpPortLeases.delete(pending.handle);
    }
    this.operations.delete(operation);
    return 0;
  }

  private closeHandle(handle: bigint): number {
    if (handle === PACKET_SINK_HANDLE) {
      return 0;
    }
    if (this.tcpPortLeases.delete(handle)) {
      return 0;
    }
    const state = this.sockets.get(handle);
    if (state === undefined) {
      return 0;
    }
    this.releaseSocket(handle, state, 1000, "EasyTier tunnel closed");
    return 0;
  }

  private enqueue(
    handle: bigint,
    state: WebSocketState,
    message: IncomingMessage,
    byteLength: number,
  ): void {
    if (state.pendingReceive !== undefined) {
      if (!this.canQueueBytes(state, byteLength)) {
        this.terminateWithError(handle, state, 1009, "receive queue limit");
        return;
      }
      this.addQueuedBytes(state, byteLength);
      this.completeReceive(state.pendingReceive, message);
      return;
    }
    if (
      state.incoming.length >= MAX_QUEUED_MESSAGES ||
      !this.canQueueBytes(state, byteLength)
    ) {
      this.terminateWithError(handle, state, 1009, "receive queue limit");
      return;
    }
    state.incoming.push(message);
    this.addQueuedBytes(state, byteLength);
  }

  private completeReceive(
    operation: bigint,
    message: IncomingMessage,
  ): void {
    const pending = this.operations.get(operation);
    if (
      pending === undefined ||
      pending.kind !== "receive" ||
      pending.state !== "pending"
    ) {
      return;
    }
    const state = this.sockets.get(pending.handle);
    if (state?.pendingReceive === operation) {
      state.pendingReceive = undefined;
    }
    this.operations.set(operation, {
      ...pending,
      state: "ready",
      message,
    });
    this.wakeGuest();
  }

  private terminateWithError(
    handle: bigint,
    state: WebSocketState,
    closeCode: number,
    reason: string,
  ): void {
    state.remoteClosed = true;
    if (state.pendingReceive !== undefined) {
      this.completeReceive(state.pendingReceive, {
        kind: "error",
        status: HOST_INVALID,
      });
    } else {
      state.incoming.push({ kind: "error", status: HOST_INVALID });
    }
    try {
      state.socket.close(closeCode, reason);
    } catch {
      // The endpoint is already terminal; the tombstone remains for guest EOF.
    }
    if (!state.guestOwned) {
      this.releaseSocket(handle, state, closeCode, reason);
    }
  }

  private releaseSocket(
    handle: bigint,
    state: WebSocketState,
    closeCode: number,
    reason: string,
  ): void {
    this.sockets.delete(handle);
    this.totalQueuedBytes -= state.queuedBytes;
    for (const [operation, pending] of this.operations) {
      if (pending.handle === handle) {
        this.operations.delete(operation);
      }
    }
    try {
      state.socket.close(closeCode, reason);
    } catch {
      // Close is intentionally idempotent.
    }
  }

  private removeQueuedBytes(
    state: WebSocketState,
    message: IncomingMessage,
  ): void {
    if (message.kind !== "binary") {
      return;
    }
    state.queuedBytes -= message.bytes.byteLength;
    this.totalQueuedBytes -= message.bytes.byteLength;
  }

  private removeQueuedBytesForHandle(
    handle: bigint,
    message: IncomingMessage,
  ): void {
    const state = this.sockets.get(handle);
    if (state !== undefined) {
      this.removeQueuedBytes(state, message);
    }
  }

  private canQueueBytes(
    state: WebSocketState,
    byteLength: number,
  ): boolean {
    return (
      state.queuedBytes + byteLength <=
        MAX_QUEUED_BYTES_PER_CONNECTION &&
      this.totalQueuedBytes + byteLength <=
        MAX_QUEUED_BYTES_PER_OBJECT
    );
  }

  private addQueuedBytes(
    state: WebSocketState,
    byteLength: number,
  ): void {
    state.queuedBytes += byteLength;
    this.totalQueuedBytes += byteLength;
  }

  private allocateHandle(): bigint {
    while (
      this.sockets.has(this.nextHandle) ||
      this.tcpPortLeases.has(this.nextHandle)
    ) {
      this.nextHandle += 1n;
      if (this.nextHandle === 0n) {
        this.nextHandle = FIRST_WEBSOCKET_HANDLE;
      }
    }
    const handle = this.nextHandle;
    this.nextHandle += 1n;
    return handle;
  }

  private startTcpBind(
    operation: bigint,
    optionsPointer: number,
    optionsLength: number,
  ): number {
    if (this.outboundFactory === undefined) {
      return HOST_UNSUPPORTED;
    }
    if (this.operations.has(operation) || optionsLength < 48) {
      return HOST_INVALID;
    }
    let options: Uint8Array;
    try {
      options = this.memoryBytes(optionsPointer, optionsLength);
    } catch {
      return HOST_INVALID;
    }
    if (options.byteLength < 48 || options[0] !== 2) {
      return HOST_INVALID;
    }
    const netnsLength = new DataView(
      options.buffer,
      options.byteOffset,
      options.byteLength,
    ).getUint32(35, false);
    const purposeOffset = 42 + netnsLength;
    if (
      purposeOffset >= options.byteLength ||
      options[purposeOffset] !== 6 ||
      options[1] !== 4 ||
      options.subarray(2, 18).some((byte) => byte !== 0)
    ) {
      return HOST_UNSUPPORTED;
    }
    const requestedPort = new DataView(
      options.buffer,
      options.byteOffset,
      options.byteLength,
    ).getUint16(18, false);
    const port = this.allocateTcpPort(requestedPort);
    if (port === undefined) {
      return HOST_INVALID;
    }
    const handle = this.allocateHandle();
    this.tcpPortLeases.set(handle, port);
    this.operations.set(operation, {
      kind: "tcp-port-lease",
      handle,
      port,
      state: "ready",
    });
    return 0;
  }

  private takeTcpBind(
    operation: bigint,
    destination: number,
    capacity: number,
  ): number {
    const pending = this.operations.get(operation);
    if (
      pending === undefined ||
      pending.kind !== "tcp-port-lease" ||
      capacity < 35
    ) {
      return HOST_INVALID;
    }
    const encoded = this.memoryBytes(destination, capacity);
    encoded.subarray(0, 35).fill(0);
    const view = new DataView(encoded.buffer, encoded.byteOffset, 35);
    view.setBigUint64(0, pending.handle, false);
    encoded[8] = 4;
    view.setUint16(25, pending.port, false);
    this.operations.delete(operation);
    return 0;
  }

  private allocateTcpPort(requestedPort: number): number | undefined {
    const leasedPorts = new Set(this.tcpPortLeases.values());
    if (requestedPort !== 0) {
      return leasedPorts.has(requestedPort) ? undefined : requestedPort;
    }
    for (let attempts = 0; attempts < 16_384; attempts += 1) {
      const port = this.nextTcpPort;
      this.nextTcpPort = port === 65_535 ? 49_152 : port + 1;
      if (!leasedPorts.has(port)) {
        return port;
      }
    }
    return undefined;
  }

  private requireSocket(handle: bigint): WebSocketState {
    const state = this.sockets.get(handle);
    if (state === undefined) {
      throw new Error(`unknown WebSocket handle ${handle}`);
    }
    return state;
  }

  private memoryBytes(pointer: number, length: number): Uint8Array {
    if (this.wasmMemory === undefined) {
      throw new Error("Wasm memory is not bound");
    }
    return new Uint8Array(this.wasmMemory.buffer, pointer, length);
  }
}
