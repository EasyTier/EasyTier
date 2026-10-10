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

function setConfig(instanceId: string, noTun = false) {
  mocks.configs.set(instanceId, {
    no_tun: noTun,
    dhcp: false,
    enable_magic_dns: false,
    routes: [],
  })
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

function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>((done) => {
    resolve = done
  })
  return { promise, resolve }
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

describe('mobile VPN reconciliation ownership', () => {
  it('ignores an intermediate empty running-ID reply after replacement B attaches', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    setReady('B', '10.0.0.2')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')

    const reply = deferred<{ running_inst_ids: unknown[] }>()
    const queried = deferred<void>()
    mocks.listNetworkInstanceIds.mockImplementationOnce(() => {
      queried.resolve()
      return reply.promise
    })
    // Represents the stop notification sent between removing A and starting B.
    mocks.getVpnStatus.mockResolvedValueOnce({ running: true, ipv4Addr: '10.0.0.1/24', routes: [] })
    const oldSync = vpn.syncMobileVpnService()
    await queried.promise
    await vpn.prepareVpnService('B')
    await vpn.onNetworkInstanceChange('B')
    expect(mocks.startVpn).toHaveBeenCalledTimes(2)
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)

    reply.resolve({ running_inst_ids: [] })
    await oldSync
    await vi.advanceTimersByTimeAsync(4000)
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    await vpn.onNetworkInstanceUpdate('B')
    expect(mocks.startVpn).toHaveBeenCalledTimes(2)
  })

  it('ignores a stale native-status reply before it can clear B ownership', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    setReady('B', '10.0.0.2')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    const reply = deferred<{ running: boolean }>()
    mocks.getVpnStatus.mockImplementationOnce(() => reply.promise)
    const oldSync = vpn.syncMobileVpnService()
    await vpn.prepareVpnService('B')
    await vpn.onNetworkInstanceChange('B')

    reply.resolve({ running: false })
    await oldSync
    expect(mocks.listNetworkInstanceIds).not.toHaveBeenCalled()
    await vpn.onNetworkInstanceUpdate('B')
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenCalledTimes(2)
  })

  it('discards the old sync as soon as a newer sync begins, before either applies a result', async () => {
    setConfig('A')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    mocks.getVpnStatus.mockResolvedValue({ running: true, ipv4Addr: '10.0.0.1/24', routes: [] })
    const oldReply = deferred<{ running_inst_ids: unknown[] }>()
    const newReply = deferred<{ running_inst_ids: unknown[] }>()
    const firstQuery = deferred<void>()
    const secondQuery = deferred<void>()
    mocks.listNetworkInstanceIds
      .mockImplementationOnce(() => {
        firstQuery.resolve()
        return oldReply.promise
      })
      .mockImplementationOnce(() => {
        secondQuery.resolve()
        return newReply.promise
      })
    const oldSync = vpn.syncMobileVpnService()
    await firstQuery.promise
    const newSync = vpn.syncMobileVpnService()
    await secondQuery.promise

    oldReply.resolve({ running_inst_ids: [] })
    await oldSync
    expect(mocks.stopVpn).not.toHaveBeenCalled()
    newReply.resolve({ running_inst_ids: ['A'] })
    await newSync
    expect(mocks.stopVpn).not.toHaveBeenCalled()
    expect(mocks.startVpn).toHaveBeenCalledTimes(1)
  })

  it('still stops an attached VPN when a current query confirms no running network', async () => {
    setConfig('A')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    mocks.getVpnStatus.mockResolvedValueOnce({ running: true, ipv4Addr: '10.0.0.1/24', routes: [] })
    await vpn.syncMobileVpnService()
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenCalledTimes(1)
  })

  it('still clears the VPN and pending retries when replacement B fails to start', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()
    await vpn.onNetworkInstanceChange('A')
    await vpn.prepareVpnService('B')
    // B never becomes ready and leaves a pending reconciliation retry.
    await vpn.onNetworkInstanceChange('B')
    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: [] })
    await vpn.syncMobileVpnService()
    setReady('B', '10.0.0.2')
    await vi.advanceTimersByTimeAsync(4000)
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenCalledTimes(1)
  })

  it('stops A before retrying an unavailable B, then starts B when it becomes ready', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')
    expect(mocks.startVpn).toHaveBeenCalledTimes(1)

    mocks.startVpn.mockClear()
    await vpn.onNetworkInstanceChange('B')

    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).not.toHaveBeenCalled()

    setReady('B', '10.0.0.2')
    await vpn.onNetworkInstanceUpdate('B')

    expect(mocks.startVpn).toHaveBeenCalledTimes(1)
    expect(mocks.startVpn).toHaveBeenCalledWith(expect.objectContaining({ ipv4Addr: '10.0.0.2/24' }))
  })

  it('stops the previous owner during pre-run even if the new instance never reaches post-run', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')
    mocks.stopVpn.mockClear()

    await vpn.prepareVpnService('B')

    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
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

  it('ignores an update from an instance that no longer owns the VPN', async () => {
    setConfig('A')
    setConfig('B')
    setReady('A', '10.0.0.1')
    const vpn = await loadVpnModule()

    await vpn.onNetworkInstanceChange('A')
    await vpn.onNetworkInstanceChange('B')
    mocks.collectNetworkInfo.mockClear()

    await vpn.onNetworkInstanceUpdate('A')

    expect(mocks.collectNetworkInfo).not.toHaveBeenCalled()
  })

  it('does not apply an in-flight result after the desired instance changes', async () => {
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
    const switchToB = vpn.onNetworkInstanceChange('B')
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

    await Promise.all([staleUpdate, switchToB])

    expect(mocks.startVpn).not.toHaveBeenCalled()
    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
  })

  it('stops a native VPN with unknown ownership before retrying the selected instance', async () => {
    setConfig('A')
    mocks.getVpnStatus.mockResolvedValue({
      running: true,
      ipv4Addr: '10.0.0.1/24',
      routes: [],
    })
    mocks.listNetworkInstanceIds.mockResolvedValue({ running_inst_ids: ['A'] })
    const vpn = await loadVpnModule()

    await vpn.syncMobileVpnService()

    expect(mocks.stopVpn).toHaveBeenCalledTimes(1)
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
