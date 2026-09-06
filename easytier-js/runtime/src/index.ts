export type EasyTierState =
  | "created"
  | "starting"
  | "running"
  | "stopping"
  | "stopped";

export interface EasyTierNetworkConfig {
  networkName: string;
  networkSecret: string;
  instanceName?: string;
  encryption?: boolean;
}

export interface EasyTierEvent {
  kind: string;
  message: string;
}

export interface EasyTierStatus {
  state: EasyTierState;
  connections: number;
}

export interface EasyTierOperationOptions {
  /** Timeout in milliseconds. Omit to wait indefinitely. */
  timeout?: number;
}

export interface EasyTierIpv4SocketAddress {
  ipv4: string;
  port: number;
}

export interface EasyTierTcpReadResult {
  data: Uint8Array;
  eof: boolean;
}

export interface EasyTierTcpStream {
  readonly localAddress: EasyTierIpv4SocketAddress;
  readonly peerAddress: EasyTierIpv4SocketAddress;
  read(maxLength?: number): Promise<EasyTierTcpReadResult>;
  write(data: Uint8Array): Promise<number>;
  shutdownWrite(): Promise<void>;
  close(): Promise<void>;
}

export interface EasyTierTcpListener {
  readonly localAddress: EasyTierIpv4SocketAddress;
  accept(options?: EasyTierOperationOptions): Promise<EasyTierTcpStream>;
  close(): Promise<void>;
}

export interface EasyTierInstance {
  connectTcp(
    address: string,
    options?: EasyTierOperationOptions,
  ): Promise<EasyTierTcpStream>;
  listenTcp(
    port: number,
    options?: EasyTierOperationOptions,
  ): Promise<EasyTierTcpListener>;
  status(): Promise<EasyTierStatus>;
  close(): Promise<void>;
}
