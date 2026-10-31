import type { Api, NetworkTypes } from 'easytier-frontend-lib'
import { describe, expect, it, vi } from 'vitest'
import { type GuiSettings, startConfiguredNetwork } from './settings'

vi.mock('easytier-frontend-lib', () => ({
  Utils: { UuidToStr: (value: unknown) => String(value) },
}))

function createApi(running: string[] = [], disabled: string[] = ['first', 'selected']) {
  return {
    list_network_instance_ids: vi.fn(async () => ({ running_inst_ids: running, disabled_inst_ids: disabled })),
    get_network_config: vi.fn(async (id: string) => ({ instance_id: id }) as NetworkTypes.NetworkConfig),
    run_network: vi.fn(async () => undefined),
  } as unknown as Api.RemoteClient
}

const enabled: GuiSettings = { closeToTray: true, autoStartNetwork: true, startupNetworkId: 'selected' }

describe('gui startup network', () => {
  it('starts only the explicitly selected network without re-saving its configuration', async () => {
    const api = createApi()
    expect(await startConfiguredNetwork(api, enabled)).toBe('selected')
    expect(api.get_network_config).toHaveBeenCalledOnce()
    expect(api.get_network_config).toHaveBeenCalledWith('selected')
    expect(api.run_network).toHaveBeenCalledOnce()
    expect(api.run_network).toHaveBeenCalledWith({ instance_id: 'selected' }, false)
  })

  it.each([
    { ...enabled, autoStartNetwork: false },
    { ...enabled, startupNetworkId: null },
  ])('does not access networks when automatic startup is disabled or unconfigured', async (settings) => {
    const api = createApi()
    await startConfiguredNetwork(api, settings)
    expect(api.list_network_instance_ids).not.toHaveBeenCalled()
    expect(api.run_network).not.toHaveBeenCalled()
  })

  it('does not restart an already running network', async () => {
    const api = createApi(['selected'])
    expect(await startConfiguredNetwork(api, enabled)).toBe('selected')
    expect(api.get_network_config).not.toHaveBeenCalled()
    expect(api.run_network).not.toHaveBeenCalled()
  })

  it('reports a deleted selection without starting a different network', async () => {
    const api = createApi([], ['first'])
    await expect(startConfiguredNetwork(api, enabled)).rejects.toThrow('no longer exists')
    expect(api.run_network).not.toHaveBeenCalled()
  })

  it('propagates startup failures so the GUI can report them', async () => {
    const api = createApi()
    vi.mocked(api.run_network).mockRejectedValue(new Error('TUN unavailable'))
    await expect(startConfiguredNetwork(api, enabled)).rejects.toThrow('TUN unavailable')
    expect(api.run_network).toHaveBeenCalledOnce()
  })
})
