import { IPv4 } from 'ip-num/IPNumber'
import { IPv4CidrRange } from 'ip-num/IPRange'
import type { NetworkInstance, NodeInfo, VpnPortalClientConfig, VpnPortalConfig } from '../types/network'
import { ipv4ToString, ipv6ToString } from './utils'

export function createVpnPortalConfig(): VpnPortalConfig {
  const key = crypto.getRandomValues(new Uint8Array(32))
  key[0] &= 248
  key[31] = (key[31] & 127) | 64
  return {
    wireguard_listen: '0.0.0.0:22022',
    wireguard_private_key: btoa(String.fromCharCode(...key)),
    clients: [],
  }
}

export function vpnPortalListener(listener: string): URL | undefined {
  try {
    return new URL(listener.includes('://') ? listener : `wg://${listener}`)
  } catch {
    return undefined
  }
}

export function vpnPortalEndpoint(listener: string, node?: NodeInfo): string {
  const url = vpnPortalListener(listener)
  if (!url?.port || url.port === '0') return ''

  const ipv4 = node?.ips?.public_ipv4?.addr ? ipv4ToString(node.ips.public_ipv4) : ''
  const ipv6 = node?.ips?.public_ipv6
  const publicIpv6 = ipv6 && [ipv6.part1, ipv6.part2, ipv6.part3, ipv6.part4].some(part => part)
    ? `[${ipv6ToString(ipv6)}]` : ''
  const wildcard = url.hostname === '0.0.0.0' || url.hostname === '[::]'
  const host = wildcard ? ipv4 || publicIpv6 : url.hostname
  return host ? `${host}:${url.port}` : ''
}

export function normalizeVpnPortalEndpoint(value: string, port: string): string {
  const input = value.trim()
  if (!input || /[\s/#?@]/.test(input)) return ''
  const url = vpnPortalListener(input)
  if (!url || ['0.0.0.0', '[::]'].includes(url.hostname)) return ''
  const resolvedPort = url.port || port
  if (!resolvedPort || Number(resolvedPort) < 1 || Number(resolvedPort) > 65535) return ''
  return `${url.hostname}:${resolvedPort}`
}

export function vpnPortalClientConfig(config: string, endpoint: string): string {
  if (!config || !endpoint) return ''
  return config.replace(/^Endpoint\s*=.*$/m, `Endpoint = ${endpoint}`)
}

export function vpnPortalIpv4(value: string): number | undefined {
  try {
    return Number(IPv4.fromString(value).getValue())
  } catch {
    return undefined
  }
}

export function vpnPortalUsedIps(instance: NetworkInstance, clients: { virtual_ip: string }[]): Set<number> {
  const addresses = clients.map(client => vpnPortalIpv4(client.virtual_ip.split('/')[0]))
  addresses.push(instance.detail?.my_node_info?.virtual_ipv4?.address?.addr)
  for (const pair of instance.detail?.peer_route_pairs ?? []) {
    const address = pair.route?.ipv4_addr
    addresses.push(typeof address === 'string' ? vpnPortalIpv4(address.split('/')[0]) : address?.address?.addr)
  }
  return new Set(addresses.filter((address): address is number => address !== undefined))
}

export function suggestVpnPortalAddress(
  instance: NetworkInstance,
  clients: VpnPortalClientConfig[],
  used: Set<number>,
): { address: string, prefix?: number } {
  const local = instance.detail?.my_node_info?.virtual_ipv4
  const cidr = clients[0]?.virtual_ip
    || (local?.address?.addr ? `${ipv4ToString(local.address)}/${local.network_length}` : '')
  try {
    const range = IPv4CidrRange.fromCidr(cidr)
    const first = Number(range.getFirst().getValue())
    const last = Number(range.getLast().getValue())
    const prefix = Number(range.getPrefix().getValue())
    for (let address = first + 1; address < last; address++) {
      if (!used.has(address)) return { address: IPv4.fromNumber(address).toString(), prefix }
    }
    return { address: '', prefix }
  } catch {
    return { address: '' }
  }
}

export function validVpnPortalAddress(address: string, prefix: number | undefined, used: Set<number>): boolean {
  const parsed = vpnPortalIpv4(address)
  if (parsed === undefined || used.has(parsed) || prefix === undefined) return false
  try {
    const range = IPv4CidrRange.fromCidr(`${address}/${prefix}`)
    return parsed > Number(range.getFirst().getValue()) && parsed < Number(range.getLast().getValue())
  } catch {
    return false
  }
}
