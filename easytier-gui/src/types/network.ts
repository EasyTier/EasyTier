import { v4 as uuidv4 } from 'uuid'

export enum NetworkingMethod {
  PublicServer = 'PublicServer',
  Manual = 'Manual',
  Standalone = 'Standalone',
}

export interface NetworkConfig {
  instance_id: string

  dhcp: boolean
  virtual_ipv4: string
  hostname?: string
  network_name: string
  network_secret: string

  networking_method: NetworkingMethod

  public_server_url: string
  peer_urls: string[]

  proxy_cidrs: string[]

  enable_vpn_portal: boolean
  vpn_portal_listen_port: number
  vpn_portal_client_network_addr: string
  vpn_portal_client_network_len: number

  advanced_settings: boolean

  listener_urls: string[]
  rpc_port: number
}

export function DEFAULT_NETWORK_CONFIG(): NetworkConfig {
  return {
    instance_id: uuidv4(),

    dhcp: true,
    virtual_ipv4: '',
    network_name: 'easytier',
    network_secret: '',

    networking_method: NetworkingMethod.PublicServer,

    public_server_url: 'tcp://easytier.public.kkrainbow.top:11010',
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
    rpc_port: 0,
  }
}

export interface NetworkInstance {
  instance_id: string

  running: boolean
  error_msg: string

  detail?: NetworkInstanceRunningInfo
}

export interface NetworkInstanceRunningInfo {
  my_node_info: NodeInfo
  events: Record<string, any>
  node_info: NodeInfo
  routes: Route[]
  peers: PeerInfo[]
  peer_route_pairs: PeerRoutePair[]
  running: boolean
  error_msg?: string
}

export interface NodeInfo {
  virtual_ipv4: string
  ips: {
    public_ipv4: string
    interface_ipv4s: string[]
    public_ipv6: string
    interface_ipv6s: string[]
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
  listeners: string[]
  vpn_portal_cfg?: string
}

export interface StunInfo {
  udp_nat_type: number
  tcp_nat_type: number
  last_update_time: number
}

export interface Route {
  peer_id: number
  ipv4_addr: string
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

export interface TunnelInfo {
  tunnel_type: string
  local_addr: string
  remote_addr: string
}

export interface PeerConnStats {
  rx_bytes: number
  tx_bytes: number
  rx_packets: number
  tx_packets: number
  latency_us: number
}
