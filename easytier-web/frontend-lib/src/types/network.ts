import { v4 as uuidv4 } from 'uuid'

export enum NetworkingMethod {
  PublicServer = 0,
  Manual = 1,
  Standalone = 2,
}

export interface SecureModeConfig {
  enabled: boolean
  // Keep protocol compatibility with backend/import-export flows even though the GUI
  // does not render secure-mode or credential inputs.
  local_private_key?: string
  local_public_key?: string
}

export enum AclProtocol {
  Unspecified = 0,
  TCP = 1,
  UDP = 2,
  ICMP = 3,
  ICMPv6 = 4,
  Any = 5,
}

export enum AclAction {
  Noop = 0,
  Allow = 1,
  Drop = 2,
}

export enum AclChainType {
  UnspecifiedChain = 0,
  Inbound = 1,
  Outbound = 2,
  Forward = 3,
}

export function parseEnum(enumObj: Record<string, any>, v: string | number | null | undefined, fallback: number): number
export function parseEnum(enumObj: Record<string, any>, v: string | number | null | undefined, fallback?: number): number | undefined
export function parseEnum(enumObj: Record<string, any>, v: string | number | null | undefined, fallback?: number): number | undefined {
  if (v == null) return fallback
  if (typeof v === 'string') return (enumObj[v] as number | undefined) ?? fallback
  return v
}

export interface AclRule {
  name: string
  description: string
  priority: number
  enabled: boolean
  protocol: AclProtocol
  ports: string[]
  source_ips: string[]
  destination_ips: string[]
  source_ports: string[]
  action: AclAction
  rate_limit: number
  burst_limit: number
  stateful: boolean
  source_groups: string[]
  destination_groups: string[]
}

export interface AclChain {
  name: string
  chain_type: AclChainType
  description: string
  enabled: boolean
  rules: AclRule[]
  default_action: AclAction
}

export interface GroupIdentity {
  group_name: string
  group_secret: string
}

export interface GroupInfo {
  declares: GroupIdentity[]
  members: string[]
}

export interface AclV1 {
  chains: AclChain[]
  group?: GroupInfo
}

export interface Acl {
  acl_v1?: AclV1
}

export interface NetworkConfig {
  instance_id: string

  dhcp: boolean
  virtual_ipv4: string
  network_length: number
  hostname?: string
  network_name: string
  network_secret?: string
  credential_file?: string
  secure_mode?: SecureModeConfig

  networking_method: NetworkingMethod | string

  public_server_url: string
  peer_urls: string[]

  proxy_cidrs: string[]

  enable_vpn_portal: boolean
  vpn_portal_listen_port: number
  vpn_portal_client_network_addr: string
  vpn_portal_client_network_len: number

  advanced_settings: boolean

  listener_urls: string[]
  latency_first: boolean

  dev_name: string

  use_smoltcp?: boolean
  disable_ipv6?: boolean
  ipv6_public_addr_auto?: boolean
  enable_kcp_proxy?: boolean
  disable_kcp_input?: boolean
  enable_quic_proxy?: boolean
  disable_quic_input?: boolean
  disable_p2p?: boolean
  p2p_only?: boolean
  lazy_p2p?: boolean
  bind_device?: boolean
  no_tun?: boolean
  enable_exit_node?: boolean
  relay_all_peer_rpc?: boolean
  need_p2p?: boolean
  multi_thread?: boolean
  proxy_forward_by_system?: boolean
  disable_encryption?: boolean
  disable_tcp_hole_punching?: boolean
  disable_udp_hole_punching?: boolean
  disable_upnp?: boolean
  enable_udp_broadcast_relay?: boolean
  disable_sym_hole_punching?: boolean

  enable_relay_network_whitelist?: boolean
  relay_network_whitelist: string[]

  enable_manual_routes: boolean
  routes: string[]

  exit_nodes: string[]

  enable_socks5?: boolean
  socks5_port: number

  mtu: number | null
  instance_recv_bps_limit: number | null
  mapped_listeners: string[]

  enable_magic_dns?: boolean
  enable_private_mode?: boolean

  port_forwards: PortForwardConfig[]
  acl?: Acl
}

export function DEFAULT_NETWORK_CONFIG(): NetworkConfig {
  return {
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

function convertEnumToName(enumObj: Record<string, any>, value: any, defaultKey: number): string {
  if (value == null) return enumObj[defaultKey]
  if (typeof value === 'number') return enumObj[value] ?? enumObj[defaultKey]
  if (typeof value === 'string') {
    if (typeof enumObj[value] === 'number') return value
    const n = Number(value)
    if (!Number.isNaN(n)) return enumObj[n] ?? enumObj[defaultKey]
  }
  return enumObj[defaultKey]
}

export function normalizeNetworkConfig(config: NetworkConfig): NetworkConfig {
  const normalized: NetworkConfig = {
    ...config,
    peer_urls: cleanPeerUrls(config.peer_urls),
  }

  const publicServerUrl = normalized.public_server_url?.trim() ?? ''

  // pbjson encodes enum fields as string names (proto3 JSON mapping).
  // The old prost_wkt_build serde and the client-side enum constants both
  // use integers. Convert to the string name so pbjson can deserialise it.
  const rawMethod: any = normalized.networking_method
  const methodStr: string =
    typeof rawMethod === 'number' ? NetworkingMethod[rawMethod] ?? 'Manual'
    : typeof rawMethod === 'string' ? rawMethod
    : 'Manual'

  switch (methodStr) {
    case 'PublicServer':
      normalized.peer_urls = publicServerUrl ? [publicServerUrl] : []
      break
    case 'Manual':
      break
    case 'Standalone':
    default:
      normalized.peer_urls = []
      break
  }

  normalized.networking_method = methodStr as any
  normalized.public_server_url = ''

  // Normalize ACL enum fields from pbjson string names to numeric values.
  const aclV1 = normalized.acl?.acl_v1
  if (aclV1) {
    for (const chain of aclV1.chains) {
      chain.chain_type = parseEnum(AclChainType, chain.chain_type, AclChainType.UnspecifiedChain)
      chain.default_action = parseEnum(AclAction, chain.default_action, AclAction.Allow)
      for (const rule of chain.rules) {
        rule.protocol = parseEnum(AclProtocol, rule.protocol, AclProtocol.Any)
        rule.action = parseEnum(AclAction, rule.action, AclAction.Allow)
      }
    }
  }

  // instance_recv_bps_limit is uint64 in proto, pbjson encodes it as string.
  // Convert to number for UI InputNumber; pbjson can deserialize either form.
  const rawRecvBpsLimit: any = normalized.instance_recv_bps_limit
  if (typeof rawRecvBpsLimit === 'string') {
    const n = Number(rawRecvBpsLimit)
    normalized.instance_recv_bps_limit = Number.isNaN(n) ? null : n
  }

  return normalized
}

export function toBackendNetworkConfig(config: NetworkConfig): NetworkConfig {
  const backend: NetworkConfig = JSON.parse(JSON.stringify(config))

  backend.peer_urls = cleanPeerUrls(backend.peer_urls)

  const publicServerUrl = backend.public_server_url?.trim() ?? ''
  const rawMethod: any = backend.networking_method
  const methodStr: string =
    typeof rawMethod === 'number' ? NetworkingMethod[rawMethod] ?? 'Manual'
    : typeof rawMethod === 'string' ? rawMethod
    : 'Manual'

  switch (methodStr) {
    case 'PublicServer':
      backend.peer_urls = publicServerUrl ? [publicServerUrl] : []
      break
    case 'Manual':
      break
    case 'Standalone':
    default:
      backend.peer_urls = []
      break
  }

  backend.networking_method = methodStr as any
  backend.public_server_url = ''

  const aclV1 = backend.acl?.acl_v1
  if (aclV1) {
    for (const chain of aclV1.chains) {
      chain.chain_type = convertEnumToName(AclChainType, chain.chain_type, AclChainType.UnspecifiedChain) as any
      chain.default_action = convertEnumToName(AclAction, chain.default_action, AclAction.Allow) as any
      for (const rule of chain.rules) {
        rule.protocol = convertEnumToName(AclProtocol, rule.protocol, AclProtocol.Any) as any
        rule.action = convertEnumToName(AclAction, rule.action, AclAction.Allow) as any
      }
    }
  }

  const rawLimit: any = backend.instance_recv_bps_limit
  if (rawLimit != null) {
    backend.instance_recv_bps_limit = String(rawLimit) as any
  }

  return backend
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

export enum NatType {
  Unknown = 0,
  OpenInternet = 1,
  NoPAT = 2,
  FullCone = 3,
  Restricted = 4,
  PortRestricted = 5,
  Symmetric = 6,
  SymUdpFirewall = 7,
  SymmetricEasyInc = 8,
  SymmetricEasyDec = 9,
}

export interface StunInfo {
  udp_nat_type: string | number
  tcp_nat_type: string | number
  last_update_time: string | number
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
  rx_bytes: string | number
  tx_bytes: string | number
  rx_packets: string | number
  tx_packets: string | number
  latency_us: string | number
}

export interface PortForwardConfig {
  bind_ip: string,
  bind_port: number,
  dst_ip: string,
  dst_port: number,
  proto: string
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
