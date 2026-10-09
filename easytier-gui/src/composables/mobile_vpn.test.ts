import { beforeEach, describe, expect, it, vi } from 'vitest'

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
    setTunFd: vi.fn(async () => undefined),
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
  listNetworkInstanceIds: mocks.listNetworkInstanceIds,
  setTunFd: mocks.setTunFd,
}))

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

async function loadVpnModule() {
  const mobileVpn = await import('./mobile_vpn')
  await mobileVpn.initMobileVpnService()
  return mobileVpn
}

beforeEach(() => {
  vi.useFakeTimers()
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
  mocks.startVpn.mockClear()
  mocks.stopVpn.mockClear()
})

describe('mobile VPN reconciliation', () => {
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
    expect(mocks.setTunFd).toHaveBeenCalledWith(1)

    mocks.startVpn.mockClear()
    mocks.stopVpn.mockClear()
    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: ['C', 'B'] })
    await vpn.onNetworkInstanceChange('A')

    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenCalledWith(expect.objectContaining({
      ipv4Addrs: ['10.0.1.1/24'],
    }))
    expect(mocks.setTunFd).toHaveBeenLastCalledWith(1)
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
    expect(mocks.setTunFd).toHaveBeenLastCalledWith(1)
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
