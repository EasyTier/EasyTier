import { beforeEach, describe, expect, it, vi } from 'vitest'
import { IPv4CidrRange, IPv6CidrRange } from 'ip-num/IPRange'
import type { MobileTunConfig } from './backend'

const mocks = vi.hoisted(() => {
  const listeners = new Map<string, (payload: unknown) => Promise<void>>()
  const configs = new Map<string, Record<string, unknown>>()
  const networkInfo = new Map<string, unknown>()

  return {
    listeners,
    configs,
    networkInfo,
    addPluginListener: vi.fn(async (_plugin: string, event: string, listener: (payload: unknown) => Promise<void>) => {
      listeners.set(event, listener)
    }),
    collectNetworkInfo: vi.fn(async (instanceId: string) => ({
      info: { map: { [instanceId]: networkInfo.get(instanceId) } },
    })),
    consumeVpnTileAction: vi.fn(async () => ({})),
    getConfig: vi.fn(async (instanceId: string) => configs.get(instanceId)),
    getVpnStatus: vi.fn<() => Promise<Record<string, unknown>>>(async () => ({ running: false })),
    listNetworkInstanceIds: vi.fn<() => Promise<{ running_inst_ids: unknown[] }>>(async () => ({ running_inst_ids: [] })),
    prepareVpn: vi.fn(async () => ({ granted: true })),
    getMobileTunConfig: vi.fn(async (instanceIds: string[]) => makeMobileTunConfig(instanceIds)),
    setTunFd: vi.fn(async (fd: number, instanceIds?: string[]) => fd > 0
      ? makeMobileTunConfig(instanceIds ?? [...configs.keys()])
      : { instance_ids: [], addresses: [], routes: [], rejected: [] }),
    startVpn: vi.fn(async () => {
      await listeners.get('vpn_service_start')?.({ fd: 1 })
      return {}
    }),
    stopVpn: vi.fn(async () => {
      await listeners.get('vpn_service_stop')?.({})
      return {}
    }),
  }
})

vi.mock('@tauri-apps/api/core', () => ({
  addPluginListener: mocks.addPluginListener,
}))

vi.mock('easytier-frontend-lib', () => ({
  Utils: {
    UuidToStr: (value: unknown) => String(value),
    ipv4ToString: (address: { addr: string }) => address.addr,
  },
}))

vi.mock('tauri-plugin-vpnservice-api', () => ({
  consume_vpn_tile_action: mocks.consumeVpnTileAction,
  get_vpn_status: mocks.getVpnStatus,
  prepare_vpn: mocks.prepareVpn,
  start_vpn: mocks.startVpn,
  stop_vpn: mocks.stopVpn,
}))

vi.mock('./backend', () => ({
  collectNetworkInfo: mocks.collectNetworkInfo,
  getConfig: mocks.getConfig,
  getMobileTunConfig: mocks.getMobileTunConfig,
  listNetworkInstanceIds: mocks.listNetworkInstanceIds,
  setTunFd: mocks.setTunFd,
}))

function makeMobileTunConfig(instanceIds: string[]): MobileTunConfig {
  const addresses: string[] = []
  const routes = new Set<string>()
  let dns: string | undefined
  for (const id of instanceIds) {
    const config = mocks.configs.get(id)!
    const info = mocks.networkInfo.get(id) as any
    const ipv4 = info?.my_node_info?.virtual_ipv4
    const ipv6 = info?.my_node_info?.virtual_ipv6
    if ((!ipv4?.address?.addr && !ipv6?.address?.addr) || info.error_msg)
      continue
    if (ipv4?.address?.addr) {
      const address = `${ipv4.address.addr}/${ipv4.network_length || 24}`
      addresses.push(address)
      const range = IPv4CidrRange.fromCidr(address)
      routes.add(`${range.getFirst()}/${range.getPrefix()}`)
    }
    if (ipv6?.address?.addr) {
      const address = `${ipv6.address.addr}/${ipv6.network_length || 64}`
      addresses.push(address)
      const range = IPv6CidrRange.fromCidr(address)
      routes.add(`${range.getFirst()}/${range.getPrefix()}`)
    }
    const configuredRoutes = config.enable_manual_routes
      ? config.routes as string[]
      : (info.routes ?? []).flatMap((route: any) => route.proxy_cidrs ?? [])
    configuredRoutes.forEach((route: string) => routes.add(route.includes('/') ? route : `${route}/32`))
    if (config.enable_magic_dns && ipv4?.address?.addr) {
      routes.add('100.100.100.101/32')
      dns = '100.100.100.101'
    }
  }
  return { instance_ids: [...instanceIds].sort(), addresses: addresses.sort(), routes: [...routes].sort(), dns, rejected: [] }
}

function setConfig(instanceId: string, noTun = false, devName?: string) {
  mocks.configs.set(instanceId, {
    no_tun: noTun,
    dev_name: devName,
    dhcp: false,
    enable_magic_dns: false,
    routes: [],
  })
  mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: [...mocks.configs.keys()] })
}

function setReady(instanceId: string, ipv4: string) {
  mocks.networkInfo.set(instanceId, {
    my_node_info: {
      virtual_ipv4: {
        address: { addr: ipv4 },
        network_length: 24,
      },
    },
    routes: [],
  })
}

function setReadyIpv6(instanceId: string, ipv6: string) {
  const info = mocks.networkInfo.get(instanceId) as any ?? { my_node_info: {}, routes: [] }
  info.my_node_info.virtual_ipv6 = { address: { addr: ipv6 }, network_length: 64 }
  mocks.networkInfo.set(instanceId, info)
}

async function loadVpnModule() {
  const mobileVpn = await import('./mobile_vpn')
  await mobileVpn.initMobileVpnService()
  return mobileVpn
}

beforeEach(() => {
  vi.useFakeTimers()
  vi.clearAllTimers()
  vi.resetModules()
  mocks.listeners.clear()
  mocks.configs.clear()
  mocks.networkInfo.clear()
  mocks.addPluginListener.mockClear()
  mocks.collectNetworkInfo.mockClear()
  mocks.consumeVpnTileAction.mockReset()
  mocks.consumeVpnTileAction.mockResolvedValue({})
  mocks.getConfig.mockClear()
  mocks.getVpnStatus.mockReset()
  mocks.getVpnStatus.mockResolvedValue({ running: false })
  mocks.listNetworkInstanceIds.mockReset()
  mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: [] })
  mocks.prepareVpn.mockClear()
  mocks.setTunFd.mockClear()
  mocks.setTunFd.mockImplementation(async (fd: number, instanceIds?: string[]) => fd > 0
    ? makeMobileTunConfig(instanceIds ?? [...mocks.configs.keys()])
    : { instance_ids: [], addresses: [], routes: [], rejected: [] })
  mocks.getMobileTunConfig.mockReset()
  mocks.getMobileTunConfig.mockImplementation(async instanceIds => makeMobileTunConfig(instanceIds))
  mocks.startVpn.mockClear()
  mocks.stopVpn.mockClear()
})

describe('mobile VPN reconciliation', () => {
  it('starts an IPv6-only VPN after DHCPv6 becomes ready', async () => {
    setConfig('A')
    mocks.configs.get('A')!.dhcpv6 = true
    mocks.configs.get('A')!.enable_magic_dns = true
    mocks.networkInfo.set('A', { my_node_info: {}, routes: [] })
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    expect(mocks.startVpn).not.toHaveBeenCalled()

    setReadyIpv6('A', 'fd12::7')
    await vi.advanceTimersByTimeAsync(2000)
    expect(mocks.startVpn).toHaveBeenCalledOnce()
    expect(mocks.startVpn).toHaveBeenCalledWith(expect.objectContaining({
      ipv4Addrs: ['fd12::7/64'],
      routes: ['fd12:0:0:0:0:0:0:0/64'],
      dns: undefined,
    }))
    expect(mocks.setTunFd).toHaveBeenCalledWith(1, ['A'])
  })

  it('preserves IPv4 when the DHCPv6 address changes or is withdrawn', async () => {
    setConfig('A')
    mocks.configs.get('A')!.dhcpv6 = true
    setReady('A', '10.0.0.1')
    setReadyIpv6('A', 'fd12::7')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')

    setReadyIpv6('A', 'fd13::8')
    await vpn.onNetworkInstanceUpdate('A')
    expect(mocks.stopVpn).toHaveBeenCalledOnce()
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24', 'fd13::8/64'],
      routes: ['10.0.0.0/24', 'fd13:0:0:0:0:0:0:0/64'],
    }))

    setReady('A', '10.0.0.1')
    await vpn.onNetworkInstanceUpdate('A')
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24'],
      routes: ['10.0.0.0/24'],
    }))
  })

  it('keeps IPv6 active after IPv4 is withdrawn and stops after both are lost', async () => {
    setConfig('A')
    mocks.configs.get('A')!.dhcp = true
    mocks.configs.get('A')!.dhcpv6 = true
    setReady('A', '10.0.0.1')
    setReadyIpv6('A', 'fd12::7')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')

    mocks.networkInfo.set('A', { my_node_info: {}, routes: [] })
    setReadyIpv6('A', 'fd12::7')
    await vpn.onNetworkInstanceUpdate('A')
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({
      ipv4Addrs: ['fd12::7/64'],
    }))
    expect(mocks.setTunFd).toHaveBeenLastCalledWith(1, ['A'])

    mocks.networkInfo.set('A', { my_node_info: {}, routes: [] })
    await vpn.onNetworkInstanceUpdate('A')
    expect(mocks.setTunFd).toHaveBeenLastCalledWith(0)
  })

  it('adds a DHCPv6 member to the shared VPN without blocking a ready IPv4 member', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    mocks.configs.get('B')!.dhcpv6 = true
    mocks.networkInfo.set('B', { my_node_info: {}, routes: [] })
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    expect(mocks.startVpn).toHaveBeenCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24'],
    }))

    setReadyIpv6('B', 'fd12::7')
    await vpn.onNetworkInstanceUpdate('B')
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24', 'fd12::7/64'],
    }))
    expect(mocks.setTunFd).toHaveBeenLastCalledWith(1, ['A', 'B'])
  })

  it('preserves healthy members and reports a rejected bootstrap member', async () => {
    setConfig('A')
    setReady('A', '10.126.126.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    const errorHandler = vi.fn()
    vpn.setMobileVpnErrorHandler(errorHandler)
    mocks.startVpn.mockClear()
    mocks.setTunFd.mockClear()
    setConfig('B')
    setReady('B', '10.126.126.2')
    mocks.getMobileTunConfig.mockResolvedValue({ ...makeMobileTunConfig(['A']), rejected: [{ instance_id: 'B', error: 'overlapping subnet' }] })
    await vpn.onNetworkInstanceChange('B')
    await vpn.onNetworkInstanceUpdate('B')
    expect(mocks.stopVpn).not.toHaveBeenCalled()
    expect(mocks.startVpn).not.toHaveBeenCalled()
    expect(mocks.setTunFd).not.toHaveBeenCalled()
    expect(errorHandler).toHaveBeenCalledOnce()
    expect(errorHandler).toHaveBeenCalledWith('B: overlapping subnet')
  })

  it('does not invalidate healthy attachments on a collection notification', async () => {
    setConfig('A')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    mocks.setTunFd.mockClear()
    await vpn.onNetworkInstancesChange()
    expect(mocks.stopVpn).not.toHaveBeenCalled()
    expect(mocks.startVpn).toHaveBeenCalledOnce()
    expect(mocks.setTunFd).not.toHaveBeenCalled()
  })

  it('corrects OS configuration when attachment admits fewer members', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    setReady('B', '10.0.1.1')
    const actual = { ...makeMobileTunConfig(['A']), rejected: [{ instance_id: 'B', error: 'claim changed during attachment' }] }
    mocks.setTunFd.mockResolvedValue(actual)
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    expect(mocks.stopVpn).not.toHaveBeenCalled()
    mocks.getMobileTunConfig.mockResolvedValue(actual)
    await vi.advanceTimersByTimeAsync(2000)
    expect(mocks.stopVpn).toHaveBeenCalledOnce()
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({ ipv4Addrs: ['10.0.0.1/24'], routes: ['10.0.0.0/24'] }))
  })

  it('waits for native attachment completion before completing startup', async () => {
    setConfig('A')
    setReady('A', '10.0.0.1')
    let resolve!: (value: ReturnType<typeof makeMobileTunConfig>) => void
    mocks.setTunFd.mockImplementationOnce(() => new Promise(r => { resolve = r }))
    const vpn = await loadVpnModule()
    let completed = false
    const start = vpn.onNetworkInstanceChange('A').then(() => { completed = true })
    await vi.waitFor(() => expect(mocks.setTunFd).toHaveBeenCalledWith(1, ['A']))
    expect(completed).toBe(false)
    resolve(makeMobileTunConfig(['A']))
    await start
    expect(completed).toBe(true)
  })

  it('stops the VPN and reports a physical TUN attachment failure', async () => {
    setConfig('A')
    setReady('A', '10.0.0.1')
    mocks.setTunFd.mockRejectedValueOnce(new Error('physical TUN failed'))
    const vpn = await loadVpnModule()
    const errorHandler = vi.fn()
    vpn.setMobileVpnErrorHandler(errorHandler)
    await vpn.onNetworkInstanceChange('A')
    expect(mocks.stopVpn).toHaveBeenCalledOnce()
    expect(errorHandler).toHaveBeenCalledWith('Error: physical TUN failed')
  })

  it('keeps attached shared members during a temporary status gap', async () => {
    setConfig('A', false, 'shared0')
    setConfig('B', false, 'shared0')
    setReady('A', '10.0.0.1')
    setReady('B', '10.0.1.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    mocks.startVpn.mockClear()

    mocks.networkInfo.delete('B')
    await vpn.onNetworkInstanceUpdate('B')
    expect(mocks.stopVpn).not.toHaveBeenCalled()
    expect(mocks.startVpn).not.toHaveBeenCalled()

    setReady('B', '10.0.1.2')
    await vpn.onNetworkInstanceUpdate('B')
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24', '10.0.1.2/24'],
    }))
  })

  it('keeps a ready member active while a new shared member awaits an IP', async () => {
    setConfig('A', false, 'shared0')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')

    setConfig('B', false, 'shared0')
    await vpn.onNetworkInstanceChange('B')
    expect(mocks.stopVpn).not.toHaveBeenCalled()
    expect(mocks.startVpn).toHaveBeenCalledTimes(1)

    setReady('B', '10.0.1.1')
    await vpn.onNetworkInstanceUpdate('B')
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24', '10.0.1.1/24'],
    }))
  })

  it('uses one VPN for different dev_name values and keeps the remaining member', async () => {
    setConfig('A', false, 'shared0')
    setConfig('B', false, 'other0')
    setConfig('C', true)
    setReady('A', '10.0.0.1')
    setReady('B', '10.0.1.1')
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')
    expect(mocks.startVpn).toHaveBeenCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24', '10.0.1.1/24'],
    }))
    expect(mocks.setTunFd).toHaveBeenCalledWith(1, ['A', 'B'])

    mocks.startVpn.mockClear()
    mocks.stopVpn.mockClear()
    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: ['C', 'B'] })
    await vpn.onNetworkInstanceChange('A')

    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.1.1/24'],
    }))
    expect(mocks.setTunFd).toHaveBeenLastCalledWith(1, ['B'])
  })

  it.each(['A', 'B'])('reattaches a replacement member %s with the same VPN configuration', async (replacementId) => {
    setConfig('A')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    mocks.setTunFd.mockClear()

    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: [] })
    const stopA = vpn.onNetworkInstanceChange('A')
    setConfig(replacementId)
    setReady(replacementId, '10.0.0.1')
    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: [replacementId] })
    const startReplacement = vpn.onNetworkInstanceChange(replacementId)
    await Promise.all([stopA, startReplacement])

    expect(mocks.setTunFd).toHaveBeenLastCalledWith(1, [replacementId])
    expect(mocks.startVpn).toHaveBeenCalledTimes(2)
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)

    mocks.setTunFd.mockClear()
    await vpn.onNetworkInstanceUpdate(replacementId)
    expect(mocks.setTunFd).not.toHaveBeenCalled()
  })

  it('does not reattach unchanged members when their order changes', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    setReady('B', '10.0.1.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    mocks.setTunFd.mockClear()

    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: ['B', 'A'] })
    await vpn.onNetworkInstanceUpdate('A')

    expect(mocks.setTunFd).not.toHaveBeenCalled()
    expect(mocks.stopVpn).not.toHaveBeenCalled()
  })

  it('stops the VPN when only confirmed IPv4-less members remain', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    mocks.networkInfo.set('B', { my_node_info: {}, routes: [] })
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')

    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: ['B'] })
    await vpn.onNetworkInstanceChange('A')

    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.setTunFd).toHaveBeenLastCalledWith(0)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('applies DHCP updates while another member has no configured IPv4', async () => {
    setConfig('A')
    setConfig('B')
    mocks.configs.get('A')!.dhcp = true
    setReady('A', '10.0.0.1')
    mocks.networkInfo.set('B', { my_node_info: {}, routes: [] })
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')

    setReady('A', '10.0.1.1')
    await vpn.onNetworkInstanceUpdate('A')

    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.1.1/24'],
      routes: ['10.0.1.0/24'],
    }))
    expect(vi.getTimerCount()).toBe(0)
  })

  it.each([
    { virtualIpv4: '', info: { routes: [] } },
    { virtualIpv4: '10.0.1.1', info: { my_node_info: {}, routes: [] } },
  ])('waits for unconfirmed static IPv4 state: %j', async ({ virtualIpv4, info }) => {
    setConfig('A')
    setConfig('B')
    mocks.configs.get('B')!.virtual_ipv4 = virtualIpv4
    setReady('A', '10.0.0.1')
    mocks.networkInfo.set('B', info)
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')

    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: ['B'] })
    await vpn.onNetworkInstanceChange('A')

    expect(mocks.stopVpn).not.toHaveBeenCalled()
    expect(vi.getTimerCount()).toBe(1)
  })

  it('removes a shared member when its DHCP address is withdrawn', async () => {
    setConfig('A', false, 'shared0')
    setConfig('B', false, 'shared0')
    mocks.configs.get('B')!.dhcp = true
    setReady('A', '10.0.0.1')
    setReady('B', '10.0.1.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')

    mocks.networkInfo.set('B', { my_node_info: {}, routes: [] })
    await vpn.onNetworkInstanceUpdate('B')

    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenLastCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24'],
    }))
    expect(mocks.setTunFd).toHaveBeenLastCalledWith(1, ['A', 'B'])
  })

  it('uses manual routes instead of peer proxy routes', async () => {
    setConfig('A')
    mocks.configs.get('A')!.enable_manual_routes = true
    mocks.configs.get('A')!.routes = ['192.0.2.0/24']
    setReady('A', '10.0.0.1')
    const info = mocks.networkInfo.get('A') as { routes: unknown[] }
    info.routes = [{ proxy_cidrs: ['10.9.0.0/16'] }]
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')

    expect(mocks.startVpn).toHaveBeenCalledWith(expect.objectContaining({
      routes: ['10.0.0.0/24', '192.0.2.0/24'],
    }))
  })

  it('keeps the VPN during pre-run of another instance', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')
    mocks.stopVpn.mockClear()

    await vpn.prepareVpnService('B')

    expect(mocks.stopVpn).not.toHaveBeenCalled()
  })

  it('preserves the VPN while retrying the same instance', async () => {
    setConfig('A')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')
    mocks.stopVpn.mockClear()
    mocks.networkInfo.delete('A')

    await vpn.onNetworkInstanceUpdate('A')

    expect(mocks.stopVpn).not.toHaveBeenCalled()
  })

  it('reconciles all running members after any member update', async () => {
    setConfig('A')
    setConfig('B', false, 'other0')
    setReady('A', '10.0.0.1')
    setReady('B', '10.0.1.1')
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')
    mocks.startVpn.mockClear()
    setReady('B', '10.0.1.2')

    await vpn.onNetworkInstanceUpdate('A')

    expect(mocks.startVpn).toHaveBeenCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.0.1/24', '10.0.1.2/24'],
    }))
  })

  it('does not apply a stale in-flight network result', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')
    mocks.startVpn.mockClear()
    mocks.stopVpn.mockClear()

    interface NetworkInfoResponse { info: { map: Record<string, unknown> } }
    let resolveNetworkInfo: (value: NetworkInfoResponse) => void = () => undefined
    let markCollectStarted: () => void = () => undefined
    const collectStarted = new Promise<void>((resolve) => {
      markCollectStarted = resolve
    })
    mocks.collectNetworkInfo.mockImplementationOnce(async () => await new Promise<NetworkInfoResponse>((resolve) => {
      resolveNetworkInfo = resolve
      markCollectStarted()
    }))

    const staleUpdate = vpn.onNetworkInstanceUpdate('A')
    await collectStarted
    const newerUpdate = vpn.onNetworkInstanceChange('B')
    resolveNetworkInfo({
      info: {
        map: {
          A: {
            my_node_info: {
              virtual_ipv4: {
                address: { addr: '10.0.0.99' },
                network_length: 24,
              },
            },
            routes: [],
          },
        },
      },
    })

    await Promise.all([staleUpdate, newerUpdate])

    expect(mocks.startVpn).not.toHaveBeenCalled()
    expect(mocks.stopVpn).not.toHaveBeenCalled()
  })

  it('preserves a native VPN while network info is unavailable', async () => {
    setConfig('A')
    mocks.getVpnStatus.mockResolvedValue({
      running: true,
      ipv4Addr: '10.0.0.1/24',
      routes: [],
    })
    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: ['A'] })
    const vpn = await loadVpnModule()

    await vpn.syncMobileVpnService()

    expect(mocks.stopVpn).not.toHaveBeenCalled()
    expect(mocks.startVpn).not.toHaveBeenCalled()
  })
})

describe('mobile VPN tile action delivery', () => {
  it('does not consume a pending action before a handler is ready', async () => {
    const vpn = await loadVpnModule()

    expect(await vpn.consumePendingMobileVpnTileAction()).toBe(false)
    expect(mocks.consumeVpnTileAction).not.toHaveBeenCalled()
  })

  it('consumes and dispatches a pending action once a handler is registered', async () => {
    const vpn = await loadVpnModule()
    const handler = vi.fn(async () => undefined)
    mocks.consumeVpnTileAction.mockResolvedValue({ action: 'start' })
    vpn.setMobileVpnTileActionHandler(handler)

    expect(await vpn.consumePendingMobileVpnTileAction()).toBe(true)
    expect(handler).toHaveBeenCalledWith('start')
  })
})
