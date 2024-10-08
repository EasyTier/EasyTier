export enum InstanceStatus {
  starting = 'starting',
  online = 'online',
  offline = 'offline',
  error = 'error',
}

// export enum NatType {
//   unknown = 'unknown',
//   symmetric = 'symmetric',
//   fullCone = 'full cone',
//   restrictedCone = 'restricted cone',
//   portRestrictedCone = 'port restricted cone',
// }

export enum NatType {
  /// has NAT; but own a single public IP, port is not changed
  Unknown = 0,
  OpenInternet = 1,
  NoPat = 2,
  FullCone = 3,
  Restricted = 4,
  PortRestricted = 5,
  Symmetric = 6,
  SymUdpFirewall = 7,
}

export interface InstanceData {
  id: string
  name: string
  ipv4?: string
  version?: string
  hostname?: string
  udpNatType?: number
  tcpNatType?: number
  config: InstanceConfig
  events: string[]
  prps: PeerRoutePair[]
  err?: string
  status: boolean
  stats: InstanceTimePeer[]
}

export interface InstanceInstantData {
  id: string
  name: string
  ipv4: string
  version: string
  hostname: string
  udpNatType?: number
  tcpNatType?: number
  events: string[]
  prps: PeerRoutePair[]
  err?: string
  status: boolean
  stat: InstanceTimePeer
}

export interface PeerRoutePair {
  route: Route
  peer?: PeerInfo
}

export interface Route {
  peer_id: number
  ipv4_addr: string
  next_hop_peer_id: number
  cost: number
  proxy_cidr: string[]
  hostname: string
  stun_info?: {
    udp_nat_type: NatType
    tcp_nat_type: NatType
    last_update_time: number
    public_ip: string[]
    min_port: number
    max_port: number
  }
  inst_id: string
  feature_flag: FeatureFlag
}

export interface FeatureFlag {
  is_public_server: boolean
  no_relay_data: boolean
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
  tunnel?: {
    tunnel_type: string
    local_addr?: string
    remote_addr?: string
  }
  stats?: {
    rx_bytes: number
    tx_bytes: number
    rx_packets: number
    tx_packets: number
    latency_us: number
  }
  loss_rate: number
  is_client: boolean
  network_name: string
}

export interface InstanceConfig {
  str: string
  obj: {
    [key: string]: any
  }
}

export interface InstancePeer {
  id: string
  name: string
  ipv4?: string
  ipv6?: string
  version?: string
  server: boolean
  relay: boolean
  up: number
  down: number
  cost: number
  lost: number
  latency: number
}

export interface InstancePeerDetail {
  id: string
  name: string
  version?: string
  stats: InstancePeerStat[]
}

export interface InstancePeerStat {
  time: number
  ipv4?: string
  ipv6?: string
  server: boolean
  relay: boolean
  up: number
  down: number
  cost: number
  lost: number
  latency: number
}

export interface InstanceTimePeer {
  time: number
  peers: InstancePeer[]
}

export interface InstanceChartStat {
  time: number
  total: number
  up: number
  down: number
  lost: number
}

export enum TransitionFunc {
  linear = 'linear',
  easeOutSine = 'easeOutSine',
  easeInOutSine = 'easeInOutSine',
  easeInQuad = 'easeInQuad',
  easeOutQuad = 'easeOutQuad',
  easeInOutQuad = 'easeInOutQuad',
  easeInCubic = 'easeInCubic',
  easeOutCubic = 'easeOutCubic',
  easeInOutCubic = 'easeInOutCubic',
  easeInQuart = 'easeInQuart',
  easeOutQuart = 'easeOutQuart',
  easeInOutQuart = 'easeInOutQuart',
  easeInQuint = 'easeInQuint',
  easeOutQuint = 'easeOutQuint',
  easeInOutQuint = 'easeInOutQuint',
  easeInExpo = 'easeInExpo',
  easeOutExpo = 'easeOutExpo',
  easeInOutExpo = 'easeInOutExpo',
  easeInCirc = 'easeInCirc',
  easeOutCirc = 'easeOutCirc',
  easeInOutCirc = 'easeInOutCirc',
  easeInBack = 'easeInBack',
  easeOutBack = 'easeOutBack',
  easeInOutBack = 'easeInOutBack',
}
