import { WasiClock } from "./wasi-clock.js";

const WASI_SUCCESS = 0;
const IOVEC_SIZE = 8;
const RANDOM_CHUNK_SIZE = 65_536;

export class WasiPreview1 {
  readonly imports: WebAssembly.ModuleImports;

  private memory: WebAssembly.Memory | undefined;

  constructor(clock: WasiClock) {
    this.imports = {
      random_get: (pointer: number, length: number) =>
        this.randomGet(pointer, length),
      clock_time_get: clock.clockTimeGet,
      environ_get: (pointers: number, buffer: number) =>
        this.environGet(pointers, buffer),
      environ_sizes_get: (count: number, size: number) =>
        this.environSizesGet(count, size),
      fd_write: (
        descriptor: number,
        iovecs: number,
        iovecCount: number,
        written: number,
      ) => this.fdWrite(descriptor, iovecs, iovecCount, written),
      poll_oneoff: new WebAssembly.Suspending(
        clock.pollOneoff as (...parameters: never[]) => Promise<number>,
      ),
      proc_exit: (exitCode: number) => {
        throw new Error(`WASI process exited with status ${exitCode}`);
      },
      sched_yield: () => WASI_SUCCESS,
    };
  }

  bindMemory(memory: WebAssembly.Memory): void {
    this.memory = memory;
  }

  private randomGet(pointer: number, length: number): number {
    const destination = this.bytes(pointer, length);
    for (let offset = 0; offset < destination.byteLength; ) {
      const end = Math.min(offset + RANDOM_CHUNK_SIZE, destination.byteLength);
      crypto.getRandomValues(destination.subarray(offset, end));
      offset = end;
    }
    return WASI_SUCCESS;
  }

  private environSizesGet(
    countPointer: number,
    sizePointer: number,
  ): number {
    const view = this.view();
    view.setUint32(countPointer, 0, true);
    view.setUint32(sizePointer, 0, true);
    return WASI_SUCCESS;
  }

  private environGet(_pointers: number, _buffer: number): number {
    return WASI_SUCCESS;
  }

  private fdWrite(
    descriptor: number,
    iovecsPointer: number,
    iovecCount: number,
    writtenPointer: number,
  ): number {
    const view = this.view();
    const chunks: Uint8Array[] = [];
    let byteLength = 0;
    for (let index = 0; index < iovecCount; index += 1) {
      const offset = iovecsPointer + index * IOVEC_SIZE;
      const pointer = view.getUint32(offset, true);
      const length = view.getUint32(offset + 4, true);
      chunks.push(this.bytes(pointer, length));
      byteLength += length;
    }
    view.setUint32(writtenPointer, byteLength, true);

    if ((descriptor === 1 || descriptor === 2) && byteLength > 0) {
      const output = new Uint8Array(byteLength);
      let offset = 0;
      for (const chunk of chunks) {
        output.set(chunk, offset);
        offset += chunk.byteLength;
      }
      const message = new TextDecoder().decode(output).trimEnd();
      if (message.length > 0) {
        if (descriptor === 2) {
          console.error(message);
        } else {
          console.log(message);
        }
      }
    }
    return WASI_SUCCESS;
  }

  private bytes(pointer: number, length: number): Uint8Array {
    return new Uint8Array(this.requireMemory().buffer, pointer, length);
  }

  private view(): DataView {
    return new DataView(this.requireMemory().buffer);
  }

  private requireMemory(): WebAssembly.Memory {
    if (this.memory === undefined) {
      throw new Error("WASI memory is not bound");
    }
    return this.memory;
  }
}
