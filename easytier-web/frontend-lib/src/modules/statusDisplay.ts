import { NatType, type PeerRoutePair, type StunInfo } from '../types/network'

const udpNatTypeStrMap: Record<NatType, string> = {
  [NatType.Unknown]: 'Unknown',
  [NatType.OpenInternet]: 'Open Internet',
  [NatType.NoPAT]: 'No PAT',
  [NatType.FullCone]: 'Full Cone',
  [NatType.Restricted]: 'Restricted',
  [NatType.PortRestricted]: 'Port Restricted',
  [NatType.Symmetric]: 'Symmetric',
  [NatType.SymUdpFirewall]: 'Symmetric UDP Firewall',
  [NatType.SymmetricEasyInc]: 'Symmetric Easy Inc',
  [NatType.SymmetricEasyDec]: 'Symmetric Easy Dec',
}

export function numericValue(value: unknown): number | undefined {
  if (typeof value === 'number')
    return Number.isFinite(value) ? value : undefined

  if (typeof value !== 'string' || value.trim() === '')
    return undefined

  const parsed = Number(value)
  return Number.isFinite(parsed) ? parsed : undefined
}

export function peerConns(info: PeerRoutePair) {
  return info.peer?.conns || []
}

export type TrafficCounters = Map<string, { tx: number, rx: number }>

// Keep counters per connection: peers come and go, so a delta of the summed
// counters jumps by whole lifetime totals and is not a rate.
export function trafficCounters(infos: PeerRoutePair[]): TrafficCounters {
  const counters: TrafficCounters = new Map()
  for (const info of infos) {
    for (const conn of peerConns(info)) {
      counters.set(conn.conn_id, {
        tx: numericValue(conn.stats?.tx_bytes) ?? 0,
        rx: numericValue(conn.stats?.rx_bytes) ?? 0,
      })
    }
  }
  return counters
}

// Bytes per second; connections missing from either sample and counters that
// went backwards (the node restarted) add nothing.
export function trafficRate(prev: TrafficCounters, cur: TrafficCounters, seconds: number) {
  let tx = 0
  let rx = 0
  for (const [connId, counter] of cur) {
    const before = prev.get(connId)
    if (!before)
      continue

    tx += Math.max(0, counter.tx - before.tx)
    rx += Math.max(0, counter.rx - before.rx)
  }
  return { tx: tx / seconds, rx: rx / seconds }
}

function defaultConnId(info: PeerRoutePair) {
  const defaultConn = info.peer?.default_conn_id
  if (!defaultConn)
    return undefined

  const part1 = defaultConn.part1 ?? 0
  const part2 = defaultConn.part2 ?? 0
  const part3 = defaultConn.part3 ?? 0
  const part4 = defaultConn.part4 ?? 0
  if (part1 === 0 && part2 === 0 && part3 === 0 && part4 === 0)
    return undefined

  const toHex = (value: number) => value.toString(16).padStart(8, '0')
  const part1Hex = toHex(part1)
  const part2Hex = toHex(part2)
  const part3Hex = toHex(part3)
  const part4Hex = toHex(part4)
  return `${part1Hex}-${part2Hex.slice(0, 4)}-${part2Hex.slice(4, 8)}-${part3Hex.slice(0, 4)}-${part3Hex.slice(4, 8)}${part4Hex}`
}

function defaultConnFirst(info: PeerRoutePair) {
  const conns = peerConns(info)
  const connId = defaultConnId(info)
  if (!connId)
    return conns

  const defaultConn = conns.find(conn => conn.conn_id === connId)
  return defaultConn ? [defaultConn, ...conns.filter(conn => conn !== defaultConn)] : conns
}

export function latencyMs(info: PeerRoutePair) {
  const connId = defaultConnId(info)
  let minLatencyUs: number | undefined

  for (const conn of peerConns(info)) {
    if (!conn.stats)
      continue

    const latencyUs = numericValue(conn.stats.latency_us)
    if (latencyUs === undefined)
      continue

    if (connId === conn.conn_id)
      return `${Math.ceil(latencyUs / 1000)}ms`

    minLatencyUs = Math.min(minLatencyUs ?? latencyUs, latencyUs)
  }

  if (minLatencyUs === undefined)
    return ''

  return `${Math.ceil(minLatencyUs / 1000)}ms`
}

export function lossRate(info: PeerRoutePair) {
  for (const conn of defaultConnFirst(info)) {
    const loss = numericValue(conn.loss_rate ?? 0)
    if (loss === undefined)
      continue

    return `${Math.round(loss * 100)}%`
  }

  return ''
}

export function udpNatTypeName(stunInfo: StunInfo | undefined) {
  if (!stunInfo)
    return ''

  const value = stunInfo.udp_nat_type ?? NatType.Unknown
  const natType = numericValue(value) ?? NatType[value as keyof typeof NatType]
  return udpNatTypeStrMap[natType as NatType] ?? udpNatTypeStrMap[NatType.Unknown]
}
