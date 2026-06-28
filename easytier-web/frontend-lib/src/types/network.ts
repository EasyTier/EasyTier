import { v4 as uuidv4 } from 'uuid'
import {
  NetworkConfig as NetworkConfigPb,
  NetworkingMethod,
  type NetworkConfig as ProtoNetworkConfig,
  type PortForwardConfig,
} from '../generated/proto/api_manage'
import {
  Action as AclAction,
  ChainType as AclChainType,
  Protocol as AclProtocol,
  type Acl,
  type AclV1,
  type Chain as AclChain,
  type GroupIdentity,
  type GroupInfo,
  type Rule as AclRule,
} from '../generated/proto/acl'
import { CompressionAlgoPb, NatType, type SecureModeConfig } from '../generated/proto/common'
import { prepareNetworkConfigForProtoJson } from './networkCompat'

export { AclAction, AclChainType, AclProtocol, CompressionAlgoPb, NatType, NetworkingMethod }
export type { Acl, AclChain, AclRule, AclV1, GroupIdentity, GroupInfo, PortForwardConfig, SecureModeConfig }

export type NetworkConfig = Omit<
  ProtoNetworkConfig,
  'instance_id' | 'instance_recv_bps_limit' | 'mtu' | 'networking_method'
> & {
  instance_id: string
  mtu: number | null
  instance_recv_bps_limit: number | string | null
  networking_method: NetworkingMethod | string
}

const UINT64_MAX = (1n << 64n) - 1n

interface NetworkingConfigFields {
  peer_urls: string[]
  public_server_url?: string
  networking_method?: NetworkingMethod | string
}

export function DEFAULT_NETWORK_CONFIG(): NetworkConfig {
  return {
    ...NetworkConfigPb.create(),

    instance_id: uuidv4(),

    dhcp: true,
    virtual_ipv4: '',
    network_length: 24,
    network_name: 'easytier',
    network_secret: '',
    credential_file: '',

    networking_method: NetworkingMethod.Manual,
    public_server_url: '',
    peer_urls: [],

    proxy_cidrs: [],

    enable_vpn_portal: false,
    vpn_portal_listen_port: 22022,
    vpn_portal_client_network_addr: '',
    vpn_portal_client_network_len: 24,

    advanced_settings: false,

    listener_urls: [
      'tcp://0.0.0.0:11010',
      'udp://0.0.0.0:11010',
      'wg://0.0.0.0:11011',
    ],
    latency_first: false,
    dev_name: '',

    use_smoltcp: false,
    disable_ipv6: false,
    ipv6_public_addr_auto: false,
    enable_kcp_proxy: false,
    disable_kcp_input: false,
    enable_quic_proxy: false,
    disable_quic_input: false,
    disable_p2p: false,
    p2p_only: false,
    lazy_p2p: false,
    bind_device: true,
    no_tun: false,
    enable_exit_node: false,
    relay_all_peer_rpc: false,
    need_p2p: false,
    multi_thread: true,
    proxy_forward_by_system: false,
    disable_encryption: false,
    disable_tcp_hole_punching: false,
    disable_udp_hole_punching: false,
    disable_upnp: false,
    enable_udp_broadcast_relay: false,
    disable_sym_hole_punching: false,
    enable_relay_network_whitelist: false,
    relay_network_whitelist: [],
    enable_manual_routes: false,
    routes: [],
    exit_nodes: [],
    enable_socks5: false,
    socks5_port: 1080,
    mtu: null,
    instance_recv_bps_limit: null,
    mapped_listeners: [],
    enable_magic_dns: false,
    enable_private_mode: false,
    port_forwards: [],
    acl: {
      acl_v1: {
        group: {
          declares: [],
          members: [],
        },
        chains: [],
      },
    },
  }
}

function cleanPeerUrls(urls: string[] | undefined): string[] {
  return (urls ?? []).map((url) => url.trim()).filter((url) => url.length > 0)
}

function normalizeUint64ForInput(v: bigint | number | string | null | undefined): number | string | null {
  if (v == null) return null

  try {
    const n = typeof v === 'bigint' ? v : BigInt(v)
    if (n === 0n || n > UINT64_MAX) return null
    return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n.toString()
  } catch {
    return null
  }
}

function normalizeNumberForInput(v: number | string | null | undefined): number | null {
  if (v == null) return null
  const n = Number(v)
  return Number.isFinite(n) ? n : null
}

function toBackendUint64(v: number | bigint | string | null | undefined): bigint | undefined {
  if (v == null || v === '') return undefined
  try {
    const n = typeof v === 'bigint' ? v : BigInt(v)
    return n > 0n && n <= UINT64_MAX ? n : undefined
  } catch {
    return undefined
  }
}

function applyNetworkingMethod(config: NetworkingConfigFields): void {
  config.peer_urls = cleanPeerUrls(config.peer_urls)

  const publicServerUrl = config.public_server_url?.trim() ?? ''
  const networkingMethod = config.networking_method ?? NetworkingMethod.Manual

  switch (networkingMethod) {
    case NetworkingMethod.PublicServer:
      config.peer_urls = publicServerUrl ? [publicServerUrl] : []
      break
    case NetworkingMethod.Manual:
      break
    case NetworkingMethod.Standalone:
    default:
      config.peer_urls = []
      break
  }

  config.networking_method = NetworkingMethod.Manual
  config.public_server_url = ''
}

export function normalizeNetworkConfig(config: NetworkConfig): NetworkConfig {
  const normalized = NetworkConfigPb.fromJson(prepareNetworkConfigForProtoJson(config) as any, {
    ignoreUnknownFields: true,
  }) as unknown as NetworkConfig

  applyNetworkingMethod(normalized)
  normalized.mtu = normalizeNumberForInput(normalized.mtu)
  normalized.instance_recv_bps_limit = normalizeUint64ForInput(
    normalized.instance_recv_bps_limit as any,
  )

  return normalized
}

export function toBackendNetworkConfig(config: NetworkConfig): NetworkConfig {
  const backend = NetworkConfigPb.fromJson(prepareNetworkConfigForProtoJson(config) as any, {
    ignoreUnknownFields: true,
  })

  applyNetworkingMethod(backend)
  backend.mtu = normalizeNumberForInput(config.mtu) ?? undefined
  backend.instance_recv_bps_limit = toBackendUint64(config.instance_recv_bps_limit)

  return NetworkConfigPb.toJson(backend, {
    useProtoFieldName: true,
  }) as unknown as NetworkConfig
}

export interface NetworkInstance {
  instance_id: string

  running: boolean
  error_msg: string

  detail?: NetworkInstanceRunningInfo
}

export interface NetworkInstanceRunningInfo {
  dev_name: string
  my_node_info: NodeInfo
  events: Array<string>,
  routes: Route[]
  peers: PeerInfo[]
  peer_route_pairs: PeerRoutePair[]
  running: boolean
  error_msg?: string
}

export interface Ipv4Addr {
  addr: number
}

export interface Ipv4Inet {
  address: Ipv4Addr
  network_length: number
}

export interface Ipv6Addr {
  part1: number
  part2: number
  part3: number
  part4: number
}

export interface Url {
  url: string
}

export interface NodeInfo {
  virtual_ipv4: Ipv4Inet,
  hostname: string
  version: string
  ips: {
    public_ipv4: Ipv4Addr
    interface_ipv4s: Ipv4Addr[]
    public_ipv6: Ipv6Addr
    interface_ipv6s: Ipv6Addr[]
    listeners: {
      serialization: string
      scheme_end: number
      username_end: number
      host_start: number
      host_end: number
      host: any
      port?: number
      path_start: number
      query_start?: number
      fragment_start?: number
    }[]
  }
  stun_info: StunInfo
  listeners: Url[]
  vpn_portal_cfg?: string
  peer_id: number
}

export interface StunInfo {
  udp_nat_type: number
  tcp_nat_type: number
  last_update_time: number
}

export interface Route {
  peer_id: number
  ipv4_addr: Ipv4Inet | string | null
  next_hop_peer_id: number
  cost: number
  proxy_cidrs: string[]
  hostname: string
  stun_info?: StunInfo
  inst_id: string
  version: string
}

export interface PeerInfo {
  peer_id: number
  conns: PeerConnInfo[]
}

export interface PeerConnInfo {
  conn_id: string
  my_peer_id: number
  is_client: boolean
  peer_id: number
  features: string[]
  tunnel?: TunnelInfo
  stats?: PeerConnStats
  loss_rate: number
}

export interface PeerRoutePair {
  route: Route
  peer?: PeerInfo
}

export interface UrlPb {
  url: string
}

export interface TunnelInfo {
  tunnel_type: string
  local_addr: UrlPb
  remote_addr: UrlPb
}

export interface PeerConnStats {
  rx_bytes: number
  tx_bytes: number
  rx_packets: number
  tx_packets: number
  latency_us: number
}

// 添加新行
export const addRow = (rows: PortForwardConfig[]) => {
  rows.push({
    proto: 'tcp',
    bind_ip: '',
    bind_port: 65535,
    dst_ip: '',
    dst_port: 65535,
  });
};

// 删除行
export const removeRow = (index: number, rows: PortForwardConfig[]) => {
  rows.splice(index, 1);
};

export enum EventType {
  TunDeviceReady = 'TunDeviceReady', // string
  TunDeviceError = 'TunDeviceError', // string

  PeerAdded = 'PeerAdded', // number
  PeerRemoved = 'PeerRemoved', // number
  PeerConnAdded = 'PeerConnAdded', // PeerConnInfo
  PeerConnRemoved = 'PeerConnRemoved', // PeerConnInfo

  ListenerAdded = 'ListenerAdded', // any
  ListenerAddFailed = 'ListenerAddFailed', // any, string
  ListenerAcceptFailed = 'ListenerAcceptFailed', // any, string
  ConnectionAccepted = 'ConnectionAccepted', // string, string
  ConnectionError = 'ConnectionError', // string, string, string

  Connecting = 'Connecting', // any
  ConnectError = 'ConnectError', // string, string, string

  VpnPortalStarted = 'VpnPortalStarted', // string
  VpnPortalClientConnected = 'VpnPortalClientConnected', // string, string
  VpnPortalClientDisconnected = 'VpnPortalClientDisconnected', // string, string, string

  DhcpIpv4Changed = 'DhcpIpv4Changed', // ipv4 | null, ipv4 | null
  DhcpIpv4Conflicted = 'DhcpIpv4Conflicted', // ipv4 | null

  PortForwardAdded = 'PortForwardAdded', // PortForwardConfigPb

  ProxyCidrsUpdated = 'ProxyCidrsUpdated', // string[], string[]

  UdpBroadcastRelayStartResult = 'UdpBroadcastRelayStartResult', // { capture_backend?: string, error?: string }
}
