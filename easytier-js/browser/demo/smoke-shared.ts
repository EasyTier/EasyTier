export const SMOKE_TIMEOUT_MILLISECONDS = 30_000;
export const SMOKE_RETRY_MILLISECONDS = 100;

export interface SmokeStream {
  read(): Promise<{ data: Uint8Array; eof: boolean }>;
  write(data: Uint8Array): Promise<number>;
  close(): Promise<void>;
}

export function deadline(): number {
  return Date.now() + SMOKE_TIMEOUT_MILLISECONDS;
}

export async function waitForPeer(
  peerAdded: () => boolean,
  timeoutAt: number,
  error: string,
): Promise<void> {
  while (!peerAdded() && Date.now() < timeoutAt) {
    await new Promise((resolve) => setTimeout(resolve, SMOKE_RETRY_MILLISECONDS));
  }
  if (!peerAdded()) {
    throw new Error(error);
  }
}

export async function connectWithRetry(
  connect: () => Promise<SmokeStream>,
  timeoutAt: number,
): Promise<SmokeStream> {
  for (;;) {
    try {
      return await connect();
    } catch (error) {
      if (Date.now() >= timeoutAt) {
        throw error;
      }
      await new Promise((resolve) => setTimeout(resolve, SMOKE_RETRY_MILLISECONDS));
    }
  }
}

export async function probeHttpMarker(
  stream: SmokeStream,
  host: string,
  marker: string,
): Promise<void> {
  const request = new TextEncoder().encode(
    `GET / HTTP/1.1\r\nHost: ${host}\r\nConnection: close\r\n\r\n`,
  );
  let requestOffset = 0;
  while (requestOffset < request.byteLength) {
    const written = await stream.write(request.subarray(requestOffset));
    if (written <= 0) {
      throw new Error(`invalid HTTP request write length ${written}`);
    }
    requestOffset += written;
  }
  let response = "";
  while (!response.includes(marker)) {
    const result = await stream.read();
    response += new TextDecoder().decode(result.data);
    if (result.eof) {
      break;
    }
  }
  await stream.close();
  if (!response.includes(marker)) {
    throw new Error(`unexpected TCP response: ${response}`);
  }
}
