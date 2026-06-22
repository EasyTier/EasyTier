import { v4 as uuidv4 } from 'uuid'
import * as proto from '../gen/proto.js'
import type Long from 'long'

// ==========================================================================
// 1. Proto-generated types — the single source of truth
// ==========================================================================
// pbts exposes optional fields as T|null|undefined.  The frontend model treats
// null the same as absent, so exported UI-facing aliases remove null.  Parsed
// pbjson also uses longs:Number, so Long-valued fields are exposed as numbers.
type FrontendProto<T> = T extends Long ? number
  : T extends (infer U)[] ? FrontendProto<U>[]
  : T extends object ? { [K in keyof T]: FrontendProto<NonNullable<T[K]>> }
  : NonNullable<T>

// --- api.manage ---
export type NetworkConfig = FrontendProto<proto.api.manage.NetworkConfig.$Properties>
export type PortForwardConfig = FrontendProto<proto.api.manage.PortForwardConfig.$Properties>
export type NetworkInstanceRunningInfo = FrontendProto<proto.api.manage.NetworkInstanceRunningInfo.$Properties>
export type MyNodeInfo = FrontendProto<proto.api.manage.MyNodeInfo.$Properties>
export type NodeInfo = MyNodeInfo

// --- common ---
export type SecureModeConfig = FrontendProto<proto.common.SecureModeConfig.$Properties>
export type Ipv4Addr = FrontendProto<proto.common.Ipv4Addr.$Properties>
export type Ipv4Inet = FrontendProto<proto.common.Ipv4Inet.$Properties>
export type Ipv6Addr = FrontendProto<proto.common.Ipv6Addr.$Properties>
export type Url = FrontendProto<proto.common.Url.$Properties>
export type StunInfo = FrontendProto<proto.common.StunInfo.$Properties>
export type TunnelInfo = FrontendProto<proto.common.TunnelInfo.$Properties>
export type PeerFeatureFlag = FrontendProto<proto.common.PeerFeatureFlag.$Properties>

// --- acl ---
export type AclRule = FrontendProto<proto.acl.Rule.$Properties>
export type AclChain = FrontendProto<proto.acl.Chain.$Properties>
export type AclV1 = FrontendProto<proto.acl.AclV1.$Properties>
export type Acl = FrontendProto<proto.acl.Acl.$Properties>
export type GroupInfo = FrontendProto<proto.acl.GroupInfo.$Properties>
export type GroupIdentity = FrontendProto<proto.acl.GroupIdentity.$Properties>

// --- api.instance ---
export type PeerConnStats = FrontendProto<proto.api.instance.PeerConnStats.$Properties>
export type PeerConnInfo = FrontendProto<proto.api.instance.PeerConnInfo.$Properties>
export type PeerInfo = FrontendProto<proto.api.instance.PeerInfo.$Properties>
export type Route = FrontendProto<proto.api.instance.Route.$Properties>
export type PeerRoutePair = FrontendProto<proto.api.instance.PeerRoutePair.$Properties>

// --- enums ---
export const NetworkingMethod = proto.api.manage.NetworkingMethod
export type NetworkingMethod = proto.api.manage.NetworkingMethod
export const NatType = proto.common.NatType
export type NatType = proto.common.NatType
export const AclProtocol = proto.acl.Protocol
export type AclProtocol = proto.acl.Protocol
export const AclAction = proto.acl.Action
export type AclAction = proto.acl.Action
export const AclChainType = proto.acl.ChainType
export type AclChainType = proto.acl.ChainType

// ==========================================================================
// 2. Pbjson conversion
// ==========================================================================

// Parse backend pbjson → typed plain object.
// fromObject converts enum strings→numbers, toObject({defaults:true,longs:Number})
// fills proto3 defaults and converts int64 strings→numbers.
function parse(cls: any, json: any): any {
  return cls.toObject(cls.fromObject(json), { defaults: true, longs: Number })
}

export const pbjsonParseNetworkConfig = (json: any): NetworkConfig =>
  parse(proto.api.manage.NetworkConfig, json) as NetworkConfig
export const pbjsonParseNetworkInstanceRunningInfo = (json: any): NetworkInstanceRunningInfo =>
  parse(proto.api.manage.NetworkInstanceRunningInfo, json) as NetworkInstanceRunningInfo
export const pbjsonParseNetworkMeta = (json: any): NetworkMeta =>
  parse(proto.api.manage.NetworkMeta, json) as NetworkMeta

export function pbjsonSerializeNetworkConfig(config: NetworkConfig): any {
  const inst = proto.api.manage.NetworkConfig.fromObject(config)
  // defaults:false omits fields whose value equals the proto3 default
  // (false/0/""/[]).  This is safe because proto3 defines absent == default:
  // the backend treats a missing "dhcp" key exactly the same as "dhcp":false.
  return proto.api.manage.NetworkConfig.toObject(inst, { enums: String, longs: String, defaults: false })
}

// ==========================================================================
// 3. Helpers
// ==========================================================================

function cleanPeerUrls(urls: string[] | undefined): string[] {
  return (urls ?? []).map((url) => url.trim()).filter((url) => url.length > 0)
}

export function DEFAULT_NETWORK_CONFIG(): NetworkConfig {
  return {
    instance_id: uuidv4(),
    dhcp: true, virtual_ipv4: '', network_length: 24,
    network_name: 'easytier', network_secret: '', credential_file: '',
    networking_method: NetworkingMethod.Manual, public_server_url: '',
    peer_urls: [], proxy_cidrs: [],
    enable_vpn_portal: false, vpn_portal_listen_port: 22022,
    vpn_portal_client_network_addr: '', vpn_portal_client_network_len: 24,
    advanced_settings: false,
    listener_urls: ['tcp://0.0.0.0:11010', 'udp://0.0.0.0:11010', 'wg://0.0.0.0:11011'],
    latency_first: false, dev_name: '',
    use_smoltcp: false, disable_ipv6: false, ipv6_public_addr_auto: false,
    enable_kcp_proxy: false, disable_kcp_input: false,
    enable_quic_proxy: false, disable_quic_input: false,
    disable_p2p: false, p2p_only: false, lazy_p2p: false,
    bind_device: true, no_tun: false, enable_exit_node: false,
    relay_all_peer_rpc: false, need_p2p: false, multi_thread: true,
    proxy_forward_by_system: false, disable_encryption: false,
    disable_tcp_hole_punching: false, disable_udp_hole_punching: false,
    disable_upnp: false, enable_udp_broadcast_relay: false, disable_sym_hole_punching: false,
    enable_relay_network_whitelist: false, relay_network_whitelist: [],
    enable_manual_routes: false, routes: [], exit_nodes: [],
    enable_socks5: false, socks5_port: 1080,
    mtu: undefined, instance_recv_bps_limit: undefined,
    mapped_listeners: [],
    enable_magic_dns: false, enable_private_mode: false,
    port_forwards: [],
    acl: { acl_v1: { group: { declares: [], members: [] }, chains: [] } },
  }
}

export function normalizeNetworkConfig(config: NetworkConfig): NetworkConfig {
  const normalized: NetworkConfig = { ...config, peer_urls: cleanPeerUrls(config.peer_urls) }
  const publicServerUrl = (normalized.public_server_url ?? '').trim()
  switch (normalized.networking_method) {
    case NetworkingMethod.PublicServer: normalized.peer_urls = publicServerUrl ? [publicServerUrl] : []; break
    case NetworkingMethod.Manual: break
    default: normalized.peer_urls = []; break
  }
  normalized.networking_method = NetworkingMethod.Manual
  normalized.public_server_url = ''
  return normalized
}

// Returns a JSON-compatible blob for backend consumption. The `any` return type
// is intentional — all callers pass the result directly as an opaque request body
// to axios or Tauri invoke, neither of which benefits from a stricter type.
export function toBackendNetworkConfig(config: NetworkConfig): any {
  return pbjsonSerializeNetworkConfig(normalizeNetworkConfig(config))
}

// 添加新行
export const addRow = (rows: PortForwardConfig[]) => {
  rows.push({ proto: 'tcp', bind_ip: '', bind_port: 65535, dst_ip: '', dst_port: 65535 })
}
// 删除行
export const removeRow = (index: number, rows: PortForwardConfig[]) => { rows.splice(index, 1) }

// ==========================================================================
// 4. Custom UI types (not from proto)
// ==========================================================================

export type NetworkMeta = FrontendProto<proto.api.manage.NetworkMeta.$Properties>

export interface NetworkInstance {
  instance_id: string; running: boolean; error_msg: string
  detail?: NetworkInstanceRunningInfo
}

export enum EventType {
  TunDeviceReady = 'TunDeviceReady', TunDeviceError = 'TunDeviceError',
  PeerAdded = 'PeerAdded', PeerRemoved = 'PeerRemoved',
  PeerConnAdded = 'PeerConnAdded', PeerConnRemoved = 'PeerConnRemoved',
  ListenerAdded = 'ListenerAdded', ListenerAddFailed = 'ListenerAddFailed',
  ListenerAcceptFailed = 'ListenerAcceptFailed', ConnectionAccepted = 'ConnectionAccepted',
  ConnectionError = 'ConnectionError', Connecting = 'Connecting', ConnectError = 'ConnectError',
  VpnPortalStarted = 'VpnPortalStarted', VpnPortalClientConnected = 'VpnPortalClientConnected',
  VpnPortalClientDisconnected = 'VpnPortalClientDisconnected',
  DhcpIpv4Changed = 'DhcpIpv4Changed', DhcpIpv4Conflicted = 'DhcpIpv4Conflicted',
  PortForwardAdded = 'PortForwardAdded', ProxyCidrsUpdated = 'ProxyCidrsUpdated',
  UdpBroadcastRelayStartResult = 'UdpBroadcastRelayStartResult',
}
