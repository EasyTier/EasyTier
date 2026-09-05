import type { Api, NetworkTypes } from 'easytier-frontend-lib'
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { executeVpnTileAction } from './mobile_vpn_tile'

vi.mock('easytier-frontend-lib', () => ({
  Utils: {
    UuidToStr: (value: unknown) => String(value),
  },
}))

function createApi(runningIds: string[], disabledIds: string[], noTunIds: string[] = []) {
  const configs = new Map(
    [...new Set([...runningIds, ...disabledIds])].map(instanceId => [
      instanceId,
      { instance_id: instanceId, no_tun: noTunIds.includes(instanceId) } as NetworkTypes.NetworkConfig,
    ]),
  )
  return {
    api: {
      list_network_instance_ids: vi.fn(async () => ({
        running_inst_ids: runningIds,
        disabled_inst_ids: disabledIds,
      })),
      get_network_config: vi.fn(async (instanceId: string) => configs.get(instanceId)!),
      run_network: vi.fn(async () => undefined),
      update_network_instance_state: vi.fn(async () => undefined),
    } as unknown as Api.RemoteClient,
    configs,
  }
}

describe('vpn quick settings tile actions', () => {
  const syncVpnService = vi.fn(async () => undefined)

  beforeEach(() => {
    syncVpnService.mockClear()
  })

  it('starts the last configured network and reconciles the Android VPN', async () => {
    const { api, configs } = createApi([], ['first', 'last'])

    const result = await executeVpnTileAction('start', api, {
      lastInstanceId: 'last',
      syncVpnService,
    })

    expect(api.run_network).toHaveBeenCalledWith(configs.get('last'), true)
    expect(syncVpnService).toHaveBeenCalledOnce()
    expect(result).toEqual({ action: 'start', instanceId: 'last', changed: true })
  })

  it('skips a no_tun last network and starts the first TUN-capable network', async () => {
    const { api, configs } = createApi([], ['first', 'last'], ['last'])

    const result = await executeVpnTileAction('start', api, {
      lastInstanceId: 'last',
      syncVpnService,
    })

    expect(api.run_network).toHaveBeenCalledWith(configs.get('first'), true)
    expect(syncVpnService).toHaveBeenCalledOnce()
    expect(result).toEqual({ action: 'start', instanceId: 'first', changed: true })
  })

  it('does nothing when only no_tun networks are configured', async () => {
    const { api } = createApi([], ['headless'], ['headless'])

    const result = await executeVpnTileAction('start', api, {
      lastInstanceId: 'headless',
      syncVpnService,
    })

    expect(api.run_network).not.toHaveBeenCalled()
    expect(syncVpnService).not.toHaveBeenCalled()
    expect(result).toEqual({ action: 'start', changed: false })
  })

  it('does not restart an already running network', async () => {
    const { api } = createApi(['running'], [])

    const result = await executeVpnTileAction('start', api, {
      lastInstanceId: 'running',
      syncVpnService,
    })

    expect(api.run_network).not.toHaveBeenCalled()
    expect(syncVpnService).toHaveBeenCalledOnce()
    expect(result.changed).toBe(false)
  })

  it('stops the last running network, falling back to the first running network', async () => {
    const { api } = createApi(['first', 'second'], ['disabled'])

    const result = await executeVpnTileAction('stop', api, {
      lastInstanceId: 'disabled',
      syncVpnService,
    })

    expect(api.update_network_instance_state).toHaveBeenCalledWith('first', true)
    expect(syncVpnService).toHaveBeenCalledOnce()
    expect(result).toEqual({ action: 'stop', instanceId: 'first', changed: true })
  })

  it('does not select a running no_tun network for stop', async () => {
    const { api } = createApi(['headless', 'vpn'], [], ['headless'])

    const result = await executeVpnTileAction('stop', api, {
      lastInstanceId: 'headless',
      syncVpnService,
    })

    expect(api.update_network_instance_state).toHaveBeenCalledWith('vpn', true)
    expect(syncVpnService).toHaveBeenCalledOnce()
    expect(result).toEqual({ action: 'stop', instanceId: 'vpn', changed: true })
  })

  it('reports that no action is possible when no matching network exists', async () => {
    const { api } = createApi([], ['configured'])

    const result = await executeVpnTileAction('stop', api, {
      syncVpnService,
    })

    expect(api.update_network_instance_state).not.toHaveBeenCalled()
    expect(syncVpnService).not.toHaveBeenCalled()
    expect(result).toEqual({ action: 'stop', changed: false })
  })
})
