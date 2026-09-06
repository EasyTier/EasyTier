import { WasiClock } from "./wasi-clock.js";
import { WasiPreview1 } from "./wasi-preview1.js";
import {
  EasyTierDataPlane,
  type DataPlaneExportName,
  type EasyTierTcpListener,
  type EasyTierTcpStream,
} from "./data-plane.js";
import {
  WebSocketHost,
  type EasyTierCoreEvent,
  type RuntimeWebSocket,
  type WebSocketHostHealth,
} from "./websocket-host.js";

const CORE_CONFIG_VERSION = 14;
const HOST_TUNNEL_ABI_VERSION = 1;
const PACKET_SINK_HANDLE = 1n;
const EVENT_SINK_HANDLE = 2n;
const INSTANCE_RUNNING = 2;
const INSTANCE_STOPPED = 4;
const NO_DEADLINE = 0x7fff_ffff_ffff_ffffn;
const MAX_ZERO_DEADLINE_DRIVES = 64;
const MAX_START_DRIVES = 512;
const MAX_STOP_DRIVES = 512;

export interface HostTunnelMetadata {
  version: 1;
  local_url: string;
  remote_url: string;
  resolved_remote_url?: string;
}

type WasmValue = number | bigint;
type WasmCallable = (...parameters: WasmValue[]) => WasmValue;
type PromisingExport = (...parameters: WasmValue[]) => Promise<WasmValue>;

interface CoreExports {
  memory: WebAssembly.Memory;
  _start: WasmCallable;
  easytier_buffer_alloc: WasmCallable;
  easytier_buffer_free: WasmCallable;
  easytier_instance_create: WasmCallable;
  easytier_instance_start: WasmCallable;
  easytier_instance_stop: WasmCallable;
  easytier_instance_drive: WasmCallable;
  easytier_instance_notify_completions: WasmCallable;
  easytier_instance_state: WasmCallable;
  easytier_instance_next_deadline_millis: WasmCallable;
  easytier_instance_error_len: WasmCallable;
  easytier_instance_error_copy: WasmCallable;
  easytier_instance_drop: WasmCallable;
  easytier_host_tunnel_abi_version: WasmCallable;
  easytier_instance_accept_tunnel: WasmCallable;
  easytier_data_plane_abi_version?: WasmCallable;
  easytier_data_plane_capabilities?: WasmCallable;
  easytier_data_plane_tcp_connect_submit?: WasmCallable;
  easytier_data_plane_tcp_bind_submit?: WasmCallable;
  easytier_data_plane_tcp_accept_submit?: WasmCallable;
  easytier_data_plane_tcp_read_submit?: WasmCallable;
  easytier_data_plane_tcp_write_submit?: WasmCallable;
  easytier_data_plane_tcp_shutdown_write_submit?: WasmCallable;
  easytier_data_plane_completion_drain?: WasmCallable;
  easytier_data_plane_result_size?: WasmCallable;
  easytier_data_plane_tcp_connect_result_take?: WasmCallable;
  easytier_data_plane_tcp_bind_result_take?: WasmCallable;
  easytier_data_plane_tcp_accept_result_take?: WasmCallable;
  easytier_data_plane_tcp_read_result_take?: WasmCallable;
  easytier_data_plane_tcp_write_result_take?: WasmCallable;
  easytier_data_plane_tcp_shutdown_write_result_take?: WasmCallable;
  easytier_data_plane_operation_free?: WasmCallable;
  easytier_data_plane_resource_close?: WasmCallable;
}

interface PromisingCoreExports {
  start: PromisingExport;
  bufferAlloc: PromisingExport;
  bufferFree: PromisingExport;
  instanceCreate: PromisingExport;
  instanceStart: PromisingExport;
  instanceStop: PromisingExport;
  instanceDrive: PromisingExport;
  notifyCompletions: PromisingExport;
  instanceState: PromisingExport;
  nextDeadlineMillis: PromisingExport;
  errorLength: PromisingExport;
  errorCopy: PromisingExport;
  instanceDrop: PromisingExport;
  tunnelAbiVersion: PromisingExport;
  acceptTunnel: PromisingExport;
  dataPlaneAbiVersion?: PromisingExport;
  dataPlaneCapabilities?: PromisingExport;
  dataPlaneTcpConnectSubmit?: PromisingExport;
  dataPlaneTcpBindSubmit?: PromisingExport;
  dataPlaneTcpAcceptSubmit?: PromisingExport;
  dataPlaneTcpReadSubmit?: PromisingExport;
  dataPlaneTcpWriteSubmit?: PromisingExport;
  dataPlaneTcpShutdownWriteSubmit?: PromisingExport;
  dataPlaneCompletionDrain?: PromisingExport;
  dataPlaneResultSize?: PromisingExport;
  dataPlaneTcpConnectResultTake?: PromisingExport;
  dataPlaneTcpBindResultTake?: PromisingExport;
  dataPlaneTcpAcceptResultTake?: PromisingExport;
  dataPlaneTcpReadResultTake?: PromisingExport;
  dataPlaneTcpWriteResultTake?: PromisingExport;
  dataPlaneTcpShutdownWriteResultTake?: PromisingExport;
  dataPlaneOperationFree?: PromisingExport;
  dataPlaneResourceClose?: PromisingExport;
}

export interface CoreHealth extends WebSocketHostHealth {
  state: number;
  tunnelAbiVersion: number;
}

export class EasyTierRuntime {
  private readonly host: WebSocketHost;
  readonly ready: Promise<void>;

  private instanceHandle = 0n;
  private exports: PromisingCoreExports | undefined;
  private memory: WebAssembly.Memory | undefined;
  private clock: WasiClock | undefined;
  private serial = Promise.resolve();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private timerGeneration = 0;
  private timerDueAt: number | undefined;
  private armRequest = 0;
  private pumpQueued = false;
  private completionRequested = false;
  private lastError: unknown;
  private dataPlane: EasyTierDataPlane | undefined;
  private stopping = false;
  private stopPromise: Promise<void> | undefined;

  constructor(
    private readonly module: WebAssembly.Module,
    private readonly config: string,
    outboundWebSocketFactory?: (url: string) => RuntimeWebSocket,
    onEvent?: (event: EasyTierCoreEvent) => void,
  ) {
    this.host = new WebSocketHost(outboundWebSocketFactory, onEvent);
    this.ready = this.enqueue(() => this.initialize());
    this.host.setWakeGuest(() => this.requestHostCompletion());
  }

  canAcceptWebSocket(): boolean {
    return !this.stopping && this.host.canAccept();
  }

  async acceptWebSocket(
    socket: RuntimeWebSocket,
    metadata: HostTunnelMetadata,
  ): Promise<void> {
    await this.ready;
    this.requireRunning();
    if (!this.host.canAccept()) {
      throw new Error("WebSocket connection limit reached");
    }

    socket.binaryType = "arraybuffer";
    const handle = this.host.register(socket);
    socket.addEventListener("message", (event) => {
      if (event.data === undefined) {
        this.host.remoteError(handle);
        return;
      }
      this.host.receive(handle, event.data);
    });
    socket.addEventListener("close", () => {
      this.host.remoteClose(handle);
    });
    socket.addEventListener("error", () => {
      this.host.remoteError(handle);
    });

    try {
      socket.accept?.();
      await this.attachTunnel(handle, metadata);
    } catch (error) {
      this.host.reject(handle);
      throw error;
    }
  }

  async attachTunnel(
    tunnelHandle: bigint,
    metadata: HostTunnelMetadata,
  ): Promise<void> {
    await this.ready;
    this.requireRunning();
    await this.enqueue(async () => {
      this.requireRunning();
      const encoded = new TextEncoder().encode(JSON.stringify(metadata));
      const pointer = await this.copyIntoGuest(encoded);
      let transferred = false;
      try {
        try {
          const status = Number(
            await this.call("acceptTunnel", [
              this.instanceHandle,
              tunnelHandle,
              pointer,
              encoded.byteLength,
            ]),
          );
          if (status !== 0) {
            throw new Error(
              await this.instanceError(`Tunnel attach (${status})`),
            );
          }
          this.host.transferToGuest(tunnelHandle);
          transferred = true;
        } finally {
          await this.call("bufferFree", [pointer]);
        }
        await this.driveUntilIdle();
        this.armNextDrive();
      } catch (error) {
        if (transferred) {
          this.host.abort(tunnelHandle, "EasyTier admission failed");
        }
        throw error;
      }
    });
  }

  async health(): Promise<CoreHealth> {
    await this.ready;
    return this.enqueue(async () => ({
      state: Number(
        await this.call("instanceState", [this.instanceHandle]),
      ),
      tunnelAbiVersion: Number(await this.call("tunnelAbiVersion", [])),
      ...this.host.health(),
    }));
  }

  async connectTcp(
    ipv4: string,
    port: number,
    timeoutMilliseconds?: number,
  ): Promise<EasyTierTcpStream> {
    await this.ready;
    this.requireRunning();
    if (this.dataPlane === undefined) {
      throw new Error("this EasyTier guest does not include the data plane");
    }
    return this.dataPlane.connectTcp(ipv4, port, timeoutMilliseconds);
  }

  async bindTcp(
    localPort: number,
    timeoutMilliseconds?: number,
  ): Promise<EasyTierTcpListener> {
    await this.ready;
    this.requireRunning();
    if (this.dataPlane === undefined) {
      throw new Error("this EasyTier guest does not include the data plane");
    }
    return this.dataPlane.bindTcp(localPort, timeoutMilliseconds);
  }

  stop(): Promise<void> {
    if (this.stopPromise !== undefined) {
      return this.stopPromise;
    }
    this.stopping = true;
    this.armRequest += 1;
    this.cancelTimer();
    this.clock?.interrupt();
    const stop = this.ready.then(
      () => this.enqueue(() => this.stopInstance()),
      (error: unknown) => {
        this.releaseRuntimeResources();
        throw error;
      },
    );
    this.stopPromise = stop;
    return stop;
  }

  private async initialize(): Promise<void> {
    if (
      typeof WebAssembly.Suspending !== "function" ||
      typeof WebAssembly.promising !== "function"
    ) {
      throw new Error("WebAssembly JSPI support is required");
    }

    let instance: WebAssembly.Instance | undefined;
    const clock = new WasiClock(() => {
      if (instance === undefined) {
        throw new Error("Wasm instance is not initialized");
      }
      return (instance.exports as unknown as CoreExports).memory;
    });
    const wasi = new WasiPreview1(clock);

    instance = new WebAssembly.Instance(this.module, {
      wasi_snapshot_preview1: wasi.imports,
      easytier_host: this.host.imports,
    });
    const raw = instance.exports as unknown as CoreExports;
    this.memory = raw.memory;
    this.host.bindMemory(raw.memory);
    wasi.bindMemory(raw.memory);
    this.clock = clock;
    this.exports = this.wrapExports(raw);
    await this.call("start", []);

    const abiVersion = Number(await this.call("tunnelAbiVersion", []));
    if (abiVersion !== HOST_TUNNEL_ABI_VERSION) {
      throw new Error(
        `host tunnel ABI ${abiVersion} is unsupported; expected ${HOST_TUNNEL_ABI_VERSION}`,
      );
    }
    const createConfig = new TextEncoder().encode(
      JSON.stringify({
        version: CORE_CONFIG_VERSION,
        config: this.config,
        environment: {
          public_ipv4: null,
          interface_ipv4s: [],
          public_ipv6: null,
          interface_ipv6s: [],
          mapped_listeners: [],
          local_ips: [],
          protected_tcp_ports: [],
          preferred_ipv6_sources: [],
        },
      }),
    );
    const configPointer = await this.copyIntoGuest(createConfig);
    try {
      this.instanceHandle = BigInt(
        await this.call("instanceCreate", [
          configPointer,
          createConfig.byteLength,
          PACKET_SINK_HANDLE,
          EVENT_SINK_HANDLE,
        ]),
      );
    } finally {
      await this.call("bufferFree", [configPointer]);
    }
    if (this.instanceHandle === 0n) {
      throw new Error(await this.instanceError("core instance creation"));
    }
    if (this.exports.dataPlaneAbiVersion !== undefined) {
      this.dataPlane = new EasyTierDataPlane({
        instanceHandle: this.instanceHandle,
        call: (name, parameters) => this.call(name, parameters),
        allocate: async (length) => {
          const pointer = Number(await this.call("bufferAlloc", [length]));
          if (pointer === 0) {
            throw new Error("guest buffer allocation failed");
          }
          return pointer;
        },
        free: async (pointer) => {
          await this.call("bufferFree", [pointer]);
        },
        copyIntoGuest: (bytes) => this.copyIntoGuest(bytes),
        readGuest: (pointer, length) =>
          new Uint8Array(this.requireMemory().buffer, pointer, length).slice(),
        instanceError: (context) => this.instanceError(context),
        runExclusive: (operation) => this.enqueue(operation),
        drive: async () => {
          await this.driveUntilIdle();
          this.armNextDrive();
        },
      });
      await this.dataPlane.initialize();
    }
    const startStatus = Number(
      await this.call("instanceStart", [this.instanceHandle]),
    );
    if (startStatus !== 0) {
      throw new Error(await this.instanceError(`core start (${startStatus})`));
    }
    let lastState = 0;
    let lastDeadline = NO_DEADLINE;
    for (let attempt = 0; attempt < MAX_START_DRIVES; attempt += 1) {
      lastState = Number(
        await this.call("instanceDrive", [this.instanceHandle]),
      );
      if (lastState === INSTANCE_RUNNING) {
        this.armNextDrive();
        console.log(
          JSON.stringify({
            event: "easytier_core_started",
            tunnelAbiVersion: abiVersion,
            startupDrives: attempt + 1,
          }),
        );
        return;
      }
      if (lastState < 0) {
        throw new Error(
          await this.instanceError(`core drive (${lastState})`),
        );
      }
      lastDeadline = BigInt(
        await this.call("nextDeadlineMillis", [this.instanceHandle]),
      );
      if (lastDeadline > 0n && lastDeadline !== NO_DEADLINE) {
        const wait = Number(
          lastDeadline > 1000n ? 1000n : lastDeadline,
        );
        await new Promise((resolve) => setTimeout(resolve, wait));
        this.clock?.advanceMillis(wait);
      }
    }
    throw new Error(
      `core did not reach running state: state=${lastState}, deadline=${lastDeadline}`,
    );
  }

  private async stopInstance(): Promise<void> {
    let failure: unknown;
    try {
      const stopStatus = Number(
        await this.call("instanceStop", [this.instanceHandle]),
      );
      if (stopStatus !== 0) {
        throw new Error(
          await this.instanceError(`core stop (${stopStatus})`),
        );
      }

      let lastState = 0;
      let lastDeadline = NO_DEADLINE;
      for (let attempt = 0; attempt < MAX_STOP_DRIVES; attempt += 1) {
        if (this.completionRequested) {
          this.completionRequested = false;
          const notifyStatus = Number(
            await this.call("notifyCompletions", [this.instanceHandle]),
          );
          if (notifyStatus !== 0) {
            throw new Error(
              await this.instanceError(
                `completion notification (${notifyStatus})`,
              ),
            );
          }
        }
        lastState = Number(
          await this.call("instanceDrive", [this.instanceHandle]),
        );
        if (lastState < 0) {
          throw new Error(
            await this.instanceError(`core drive (${lastState})`),
          );
        }
        await this.dataPlane?.drainCompletions();
        if (lastState === INSTANCE_STOPPED) {
          break;
        }
        lastDeadline = BigInt(
          await this.call("nextDeadlineMillis", [this.instanceHandle]),
        );
        if (lastDeadline > 0n && lastDeadline !== NO_DEADLINE) {
          const wait = Number(
            lastDeadline > 1000n ? 1000n : lastDeadline,
          );
          await new Promise((resolve) => setTimeout(resolve, wait));
          this.clock?.advanceMillis(wait);
        } else if (lastDeadline === NO_DEADLINE) {
          await new Promise((resolve) => setTimeout(resolve, 0));
        }
      }
      if (lastState !== INSTANCE_STOPPED) {
        throw new Error(
          `core did not stop: state=${lastState}, deadline=${lastDeadline}`,
        );
      }
    } catch (error) {
      failure = error;
    }

    try {
      if (this.instanceHandle !== 0n) {
        const dropStatus = Number(
          await this.call("instanceDrop", [this.instanceHandle]),
        );
        if (dropStatus !== 0) {
          throw new Error(
            await this.instanceError(`core drop (${dropStatus})`),
          );
        }
      }
    } catch (error) {
      failure ??= error;
    } finally {
      this.releaseRuntimeResources();
    }

    if (failure !== undefined) {
      throw failure;
    }
  }

  private releaseRuntimeResources(): void {
    this.cancelTimer();
    this.clock?.interrupt();
    this.dataPlane?.shutdown();
    this.dataPlane = undefined;
    this.host.shutdown();
    this.instanceHandle = 0n;
    this.exports = undefined;
    this.memory = undefined;
    this.clock = undefined;
    this.completionRequested = false;
    this.pumpQueued = false;
  }

  private requestHostCompletion(): void {
    this.completionRequested = true;
    this.clock?.interrupt();
    if (this.stopping) {
      return;
    }
    this.queuePump();
  }

  private queuePump(): void {
    if (this.pumpQueued || this.stopping) {
      return;
    }
    this.pumpQueued = true;
    void this.ready
      .then(() =>
        this.enqueue(async () => {
          this.pumpQueued = false;
          if (this.stopping) {
            return;
          }
          if (this.completionRequested) {
            this.completionRequested = false;
            const status = Number(
              await this.call("notifyCompletions", [this.instanceHandle]),
            );
            if (status !== 0) {
              throw new Error(
                await this.instanceError(`completion notification (${status})`),
              );
            }
          }
          await this.driveUntilIdle();
          this.armNextDrive();
        }),
      )
      .catch((error: unknown) => {
        this.lastError = error;
        this.pumpQueued = false;
        console.error(
          JSON.stringify({
            event: "easytier_core_pump_failed",
            error: String(error),
          }),
        );
      });
  }

  private async driveUntilIdle(): Promise<void> {
    for (let turn = 0; turn < MAX_ZERO_DEADLINE_DRIVES; turn += 1) {
      const state = Number(
        await this.call("instanceDrive", [this.instanceHandle]),
      );
      if (state < 0) {
        throw new Error(await this.instanceError(`core drive (${state})`));
      }
      await this.dataPlane?.drainCompletions();
      const deadline = BigInt(
        await this.call("nextDeadlineMillis", [this.instanceHandle]),
      );
      if (deadline !== 0n) {
        return;
      }
    }
  }

  private armNextDrive(): void {
    if (this.stopping) {
      this.cancelTimer();
      return;
    }
    const request = ++this.armRequest;
    void this.enqueue(async () => {
      if (request !== this.armRequest) {
        return;
      }
      const deadline = BigInt(
        await this.call("nextDeadlineMillis", [this.instanceHandle]),
      );
      if (request !== this.armRequest) {
        return;
      }
      if (deadline === NO_DEADLINE) {
        this.cancelTimer();
        return;
      }
      const milliseconds = Number(
        deadline > 2_147_483_647n ? 2_147_483_647n : deadline,
      );
      const dueAt = Date.now() + milliseconds;
      if (
        this.timer !== undefined &&
        this.timerDueAt !== undefined &&
        this.timerDueAt <= dueAt
      ) {
        return;
      }
      if (this.timer !== undefined) {
        clearTimeout(this.timer);
      }
      const generation = ++this.timerGeneration;
      const timer = setTimeout(() => {
        if (generation !== this.timerGeneration) {
          return;
        }
        if (this.timer === timer) {
          this.timer = undefined;
          this.timerDueAt = undefined;
        }
        this.clock?.syncWallTime();
        this.queuePump();
      }, milliseconds);
      this.timer = timer;
      this.timerDueAt = dueAt;
    }).catch((error: unknown) => {
      this.lastError = error;
      console.error(
        JSON.stringify({
          event: "easytier_core_timer_failed",
          error: String(error),
        }),
      );
    });
  }

  private wrapExports(raw: CoreExports): PromisingCoreExports {
    const wrap = (callable: WasmCallable): PromisingExport =>
      WebAssembly.promising(callable) as PromisingExport;
    const wrapOptional = (
      callable: WasmCallable | undefined,
    ): PromisingExport | undefined =>
      callable === undefined ? undefined : wrap(callable);
    return {
      start: wrap(raw._start),
      bufferAlloc: wrap(raw.easytier_buffer_alloc),
      bufferFree: wrap(raw.easytier_buffer_free),
      instanceCreate: wrap(raw.easytier_instance_create),
      instanceStart: wrap(raw.easytier_instance_start),
      instanceStop: wrap(raw.easytier_instance_stop),
      instanceDrive: wrap(raw.easytier_instance_drive),
      notifyCompletions: wrap(raw.easytier_instance_notify_completions),
      instanceState: wrap(raw.easytier_instance_state),
      nextDeadlineMillis: wrap(raw.easytier_instance_next_deadline_millis),
      errorLength: wrap(raw.easytier_instance_error_len),
      errorCopy: wrap(raw.easytier_instance_error_copy),
      instanceDrop: wrap(raw.easytier_instance_drop),
      tunnelAbiVersion: wrap(raw.easytier_host_tunnel_abi_version),
      acceptTunnel: wrap(raw.easytier_instance_accept_tunnel),
      dataPlaneAbiVersion: wrapOptional(raw.easytier_data_plane_abi_version),
      dataPlaneCapabilities: wrapOptional(
        raw.easytier_data_plane_capabilities,
      ),
      dataPlaneTcpConnectSubmit: wrapOptional(
        raw.easytier_data_plane_tcp_connect_submit,
      ),
      dataPlaneTcpBindSubmit: wrapOptional(
        raw.easytier_data_plane_tcp_bind_submit,
      ),
      dataPlaneTcpAcceptSubmit: wrapOptional(
        raw.easytier_data_plane_tcp_accept_submit,
      ),
      dataPlaneTcpReadSubmit: wrapOptional(
        raw.easytier_data_plane_tcp_read_submit,
      ),
      dataPlaneTcpWriteSubmit: wrapOptional(
        raw.easytier_data_plane_tcp_write_submit,
      ),
      dataPlaneTcpShutdownWriteSubmit: wrapOptional(
        raw.easytier_data_plane_tcp_shutdown_write_submit,
      ),
      dataPlaneCompletionDrain: wrapOptional(
        raw.easytier_data_plane_completion_drain,
      ),
      dataPlaneResultSize: wrapOptional(raw.easytier_data_plane_result_size),
      dataPlaneTcpConnectResultTake: wrapOptional(
        raw.easytier_data_plane_tcp_connect_result_take,
      ),
      dataPlaneTcpBindResultTake: wrapOptional(
        raw.easytier_data_plane_tcp_bind_result_take,
      ),
      dataPlaneTcpAcceptResultTake: wrapOptional(
        raw.easytier_data_plane_tcp_accept_result_take,
      ),
      dataPlaneTcpReadResultTake: wrapOptional(
        raw.easytier_data_plane_tcp_read_result_take,
      ),
      dataPlaneTcpWriteResultTake: wrapOptional(
        raw.easytier_data_plane_tcp_write_result_take,
      ),
      dataPlaneTcpShutdownWriteResultTake: wrapOptional(
        raw.easytier_data_plane_tcp_shutdown_write_result_take,
      ),
      dataPlaneOperationFree: wrapOptional(
        raw.easytier_data_plane_operation_free,
      ),
      dataPlaneResourceClose: wrapOptional(
        raw.easytier_data_plane_resource_close,
      ),
    };
  }

  private cancelTimer(): void {
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
      this.timerDueAt = undefined;
    }
    this.timerGeneration += 1;
  }

  private async copyIntoGuest(bytes: Uint8Array): Promise<number> {
    const pointer = Number(await this.call("bufferAlloc", [bytes.byteLength]));
    if (pointer === 0) {
      throw new Error("guest buffer allocation failed");
    }
    const memory = this.requireMemory();
    new Uint8Array(memory.buffer, pointer, bytes.byteLength).set(bytes);
    return pointer;
  }

  private async instanceError(context: string): Promise<string> {
    const errorLength = Number(
      await this.call("errorLength", [this.instanceHandle]),
    );
    if (errorLength <= 0) {
      return `${context} failed`;
    }
    const pointer = Number(await this.call("bufferAlloc", [errorLength]));
    if (pointer === 0) {
      return `${context} failed and error allocation failed`;
    }
    try {
      const copied = Number(
        await this.call("errorCopy", [
          this.instanceHandle,
          pointer,
          errorLength,
        ]),
      );
      if (copied < 0) {
        return `${context} failed and error copy returned ${copied}`;
      }
      const encoded = new Uint8Array(
        this.requireMemory().buffer,
        pointer,
        copied,
      ).slice();
      return `${context} failed: ${new TextDecoder().decode(encoded)}`;
    } finally {
      await this.call("bufferFree", [pointer]);
    }
  }

  private call(
    name: keyof PromisingCoreExports | DataPlaneExportName,
    parameters: Array<number | bigint>,
  ): Promise<number | bigint> {
    if (this.lastError !== undefined) {
      return Promise.reject(this.lastError);
    }
    const callable = this.exports?.[name];
    if (callable === undefined) {
      return Promise.reject(new Error(`guest export ${name} is unavailable`));
    }
    return callable(...parameters);
  }

  private requireMemory(): WebAssembly.Memory {
    if (this.memory === undefined) {
      throw new Error("guest memory is unavailable");
    }
    return this.memory;
  }

  private requireRunning(): void {
    if (this.stopping) {
      throw new Error("EasyTier runtime is stopped");
    }
  }

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.serial.then(operation, operation);
    this.serial = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }
}
