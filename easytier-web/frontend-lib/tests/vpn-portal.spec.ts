import { describe, expect, it } from 'vitest'
import {
  createVpnPortalConfig, normalizeVpnPortalEndpoint, suggestVpnPortalAddress,
  validVpnPortalAddress, vpnPortalClientConfig, vpnPortalEndpoint,
} from '../src/modules/vpnPortal'
import type { NetworkInstance, NodeInfo } from '../src/types/network'

const node = {
  virtual_ipv4: { address: { addr: 0x0a000001 }, network_length: 24 },
  ips: {
    public_ipv4: { addr: 0xcb007109 },
    public_ipv6: { part1: 0, part2: 0, part3: 0, part4: 0 },
  },
} as NodeInfo

describe('WireGuard configuration defaults', () => {
  it('generates independent private keys that survive serialization', () => {
    const first = createVpnPortalConfig()
    const second = createVpnPortalConfig()
    expect(first.wireguard_private_key).not.toBe(second.wireguard_private_key)
    expect(atob(first.wireguard_private_key!)).toHaveLength(32)
    expect(JSON.parse(JSON.stringify(first))).toEqual(first)
  })

  it('combines the running listener port with the public address', () => {
    expect(vpnPortalEndpoint('wg://0.0.0.0:22022', node)).toBe('203.0.113.9:22022')
    expect(vpnPortalEndpoint('[::]:23456', node)).toBe('203.0.113.9:23456')
    expect(vpnPortalEndpoint('wg://0.0.0.0:0', node)).toBe('')
    expect(vpnPortalEndpoint('wg://0.0.0.0:22022', { ips: {} } as NodeInfo)).toBe('')
  })

  it('preserves explicit IPv4, IPv6 and hostname listeners', () => {
    for (const host of ['127.0.0.1', '192.168.1.10', '[2001:db8::2]', 'vpn.example.com']) {
      expect(vpnPortalEndpoint(`${host}:22022`, node)).toBe(`${host}:22022`)
    }
  })

  it('handles IPv6 and rejects unspecified addresses in all spellings', () => {
    const ipv6Node = { ips: { public_ipv6: { part1: 0x20010db8, part2: 0, part3: 0, part4: 1 } } } as NodeInfo
    expect(normalizeVpnPortalEndpoint(vpnPortalEndpoint('wg://[::]:22022', ipv6Node), '')).toBe('[2001:db8::1]:22022')
    expect(normalizeVpnPortalEndpoint('[0:0:0:0:0:0:0:0]:22022', '')).toBe('')
    expect(normalizeVpnPortalEndpoint('0.0.0.0:22022', '')).toBe('')
  })

  it('uses a custom domain or port and replaces only the endpoint line', () => {
    expect(normalizeVpnPortalEndpoint('vpn.example.com', '22022')).toBe('vpn.example.com:22022')
    expect(normalizeVpnPortalEndpoint('vpn.example.com:51820', '22022')).toBe('vpn.example.com:51820')
    for (const endpoint of ['vpn.example.com:0', 'vpn.example.com:65536', 'https://vpn.example.com', 'user@vpn.example.com', 'vpn.example.com\nAddress=1']) {
      expect(normalizeVpnPortalEndpoint(endpoint, '22022')).toBe('')
    }
    expect(vpnPortalClientConfig('[Interface]\nPrivateKey = stable\n\n[Peer]\nEndpoint = 0.0.0.0:22022 # edit\nPersistentKeepalive = 25\n', 'vpn.example.com:51820'))
      .toBe('[Interface]\nPrivateKey = stable\n\n[Peer]\nEndpoint = vpn.example.com:51820\nPersistentKeepalive = 25\n')
  })

  it('suggests an unused host address and retains an existing independent client subnet', () => {
    const instance = { detail: { my_node_info: node } } as NetworkInstance
    expect(suggestVpnPortalAddress(instance, [], new Set([0x0a000001, 0x0a000002])))
      .toEqual({ address: '10.0.0.3', prefix: 24 })
    expect(suggestVpnPortalAddress(instance, [{ name: 'phone', virtual_ip: '10.80.0.2/16', groups: [] }], new Set([0x0a500002])))
      .toEqual({ address: '10.80.0.1', prefix: 16 })
    expect(suggestVpnPortalAddress({} as NetworkInstance, [], new Set())).toEqual({ address: '' })
  })

  it('does not suggest broadcast, network or occupied addresses in exhausted small subnets', () => {
    const clients = [{ name: 'phone', virtual_ip: '10.0.0.2/30', groups: [] }]
    expect(suggestVpnPortalAddress({} as NetworkInstance, clients, new Set([0x0a000001, 0x0a000002])))
      .toEqual({ address: '', prefix: 30 })
    for (const address of ['10.0.0.0', '10.0.0.1', '10.0.0.3', 'not-an-ip']) {
      expect(validVpnPortalAddress(address, 30, new Set([0x0a000001]))).toBe(false)
    }
    expect(validVpnPortalAddress('10.0.0.2', 30, new Set())).toBe(true)
    expect(validVpnPortalAddress('10.0.0.2', undefined, new Set())).toBe(false)
  })
})
