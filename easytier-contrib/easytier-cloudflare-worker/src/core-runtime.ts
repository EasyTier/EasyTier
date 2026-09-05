import { WasiClock } from "./wasi-clock";
import { WasiPreview1 } from "./wasi-preview1";
import {
  WebSocketHost,
  type HostWebSocketMetadata,
  type WebSocketHostHealth,
} from "./websocket-host";

const CORE_CONFIG_VERSION = 14;
const HOST_WEBSOCKET_ABI_VERSION = 1;
const PACKET_SINK_HANDLE = 1n;
const INSTANCE_RUNNING = 2;
const NO_DEADLINE = 0x7fff_ffff_ffff_ffffn;
const MAX_ZERO_DEADLINE_DRIVES = 64;
const MAX_START_DRIVES = 512;

type WasmValue = number | bigint;
type WasmCallable = (...parameters: WasmValue[]) => WasmValue;
type PromisingExport = (...parameters: WasmValue[]) => Promise<WasmValue>;

interface CoreExports extends WebAssembly.Exports {
  memory: WebAssembly.Memory;
  _start: WasmCallable;
  easytier_buffer_alloc: WasmCallable;
  easytier_buffer_free: WasmCallable;
  easytier_instance_create: WasmCallable;
  easytier_instance_start: WasmCallable;
  easytier_instance_drive: WasmCallable;
  easytier_instance_notify_completions: WasmCallable;
  easytier_instance_state: WasmCallable;
  easytier_instance_next_deadline_millis: WasmCallable;
  easytier_instance_error_len: WasmCallable;
  easytier_instance_error_copy: WasmCallable;
  easytier_host_websocket_abi_version: WasmCallable;
  easytier_instance_accept_websocket: WasmCallable;
}

interface PromisingCoreExports {
  start: PromisingExport;
  bufferAlloc: PromisingExport;
  bufferFree: PromisingExport;
  instanceCreate: PromisingExport;
  instanceStart: PromisingExport;
  instanceDrive: PromisingExport;
  notifyCompletions: PromisingExport;
  instanceState: PromisingExport;
  nextDeadlineMillis: PromisingExport;
  errorLength: PromisingExport;
  errorCopy: PromisingExport;
  websocketAbiVersion: PromisingExport;
  acceptWebSocket: PromisingExport;
}

export interface CoreHealth extends WebSocketHostHealth {
  state: number;
  websocketAbiVersion: number;
}

export class EasyTierRuntime {
  readonly host = new WebSocketHost();
  readonly ready: Promise<void>;

  private instanceHandle = 0n;
  private exports: PromisingCoreExports | undefined;
  private memory: WebAssembly.Memory | undefined;
  private clock: WasiClock | undefined;
  private serial = Promise.resolve();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private timerGeneration = 0;
  private pumpQueued = false;
  private completionRequested = false;
  private lastError: unknown;

  constructor(
    private readonly module: WebAssembly.Module,
    private readonly config: string,
  ) {
    this.ready = this.enqueue(() => this.initialize());
    this.host.setWakeGuest(() => this.requestHostCompletion());
  }

  async attachWebSocket(
    websocketHandle: bigint,
    metadata: HostWebSocketMetadata,
  ): Promise<void> {
    await this.ready;
    await this.enqueue(async () => {
      const encoded = new TextEncoder().encode(JSON.stringify(metadata));
      const pointer = await this.copyIntoGuest(encoded);
      let transferred = false;
      try {
        try {
          const status = Number(
            await this.call("acceptWebSocket", [
              this.instanceHandle,
              websocketHandle,
              pointer,
              encoded.byteLength,
            ]),
          );
          if (status !== 0) {
            throw new Error(
              await this.instanceError(`WebSocket attach (${status})`),
            );
          }
          this.host.transferToGuest(websocketHandle);
          transferred = true;
        } finally {
          await this.call("bufferFree", [pointer]);
        }
        await this.driveUntilIdle();
        this.armNextDrive();
      } catch (error) {
        if (transferred) {
          this.host.abort(websocketHandle, "EasyTier admission failed");
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
      websocketAbiVersion: Number(await this.call("websocketAbiVersion", [])),
      ...this.host.health(),
    }));
  }

  private async initialize(): Promise<void> {
    if (
      typeof WebAssembly.Suspending !== "function" ||
      typeof WebAssembly.promising !== "function"
    ) {
      throw new Error("Cloudflare JSPI support is required");
    }

    let instance: WebAssembly.Instance | undefined;
    const clock = new WasiClock(() => {
      if (instance === undefined) {
        throw new Error("Wasm instance is not initialized");
      }
      return (instance.exports as CoreExports).memory;
    });
    const wasi = new WasiPreview1(clock);

    instance = new WebAssembly.Instance(this.module, {
      wasi_snapshot_preview1: wasi.imports,
      easytier_host: this.host.imports,
    });
    const raw = instance.exports as CoreExports;
    this.memory = raw.memory;
    this.host.bindMemory(raw.memory);
    wasi.bindMemory(raw.memory);
    this.clock = clock;
    this.exports = this.wrapExports(raw);
    await this.call("start", []);

    const abiVersion = Number(await this.call("websocketAbiVersion", []));
    if (abiVersion !== HOST_WEBSOCKET_ABI_VERSION) {
      throw new Error(
        `host WebSocket ABI ${abiVersion} is unsupported; expected ${HOST_WEBSOCKET_ABI_VERSION}`,
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
        ]),
      );
    } finally {
      await this.call("bufferFree", [configPointer]);
    }
    if (this.instanceHandle === 0n) {
      throw new Error(await this.instanceError("core instance creation"));
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
            websocketAbiVersion: abiVersion,
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

  private requestHostCompletion(): void {
    this.completionRequested = true;
    this.clock?.interrupt();
    this.queuePump();
  }

  private queuePump(): void {
    if (this.pumpQueued) {
      return;
    }
    this.pumpQueued = true;
    void this.ready
      .then(() =>
        this.enqueue(async () => {
          this.pumpQueued = false;
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
      const deadline = BigInt(
        await this.call("nextDeadlineMillis", [this.instanceHandle]),
      );
      if (deadline !== 0n) {
        return;
      }
    }
  }

  private armNextDrive(): void {
    const generation = ++this.timerGeneration;
    if (this.timer !== undefined) {
      clearTimeout(this.timer);
      this.timer = undefined;
    }
    void this.enqueue(async () => {
      if (generation !== this.timerGeneration) {
        return;
      }
      const deadline = BigInt(
        await this.call("nextDeadlineMillis", [this.instanceHandle]),
      );
      if (generation !== this.timerGeneration) {
        return;
      }
      if (deadline === NO_DEADLINE) {
        return;
      }
      const milliseconds = Number(
        deadline > 2_147_483_647n ? 2_147_483_647n : deadline,
      );
      const timer = setTimeout(() => {
        if (generation !== this.timerGeneration) {
          return;
        }
        if (this.timer === timer) {
          this.timer = undefined;
        }
        this.clock?.advanceMillis(milliseconds);
        this.queuePump();
      }, milliseconds);
      this.timer = timer;
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
    return {
      start: wrap(raw._start),
      bufferAlloc: wrap(raw.easytier_buffer_alloc),
      bufferFree: wrap(raw.easytier_buffer_free),
      instanceCreate: wrap(raw.easytier_instance_create),
      instanceStart: wrap(raw.easytier_instance_start),
      instanceDrive: wrap(raw.easytier_instance_drive),
      notifyCompletions: wrap(raw.easytier_instance_notify_completions),
      instanceState: wrap(raw.easytier_instance_state),
      nextDeadlineMillis: wrap(raw.easytier_instance_next_deadline_millis),
      errorLength: wrap(raw.easytier_instance_error_len),
      errorCopy: wrap(raw.easytier_instance_error_copy),
      websocketAbiVersion: wrap(raw.easytier_host_websocket_abi_version),
      acceptWebSocket: wrap(raw.easytier_instance_accept_websocket),
    };
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
    name: keyof PromisingCoreExports,
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

  private enqueue<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.serial.then(operation, operation);
    this.serial = next.then(
      () => undefined,
      () => undefined,
    );
    return next;
  }
}
