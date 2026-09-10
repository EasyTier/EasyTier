import type { Api } from 'easytier-frontend-lib'
import type { VpnTileAction } from 'tauri-plugin-vpnservice-api'
import { Utils } from 'easytier-frontend-lib'

export interface VpnTileActionResult {
  action: VpnTileAction
  instanceId?: string
  changed: boolean
}

export interface VpnTileActionOptions {
  lastInstanceId?: string | null
  syncVpnService: () => Promise<void>
}

export async function executeVpnTileAction(
  action: VpnTileAction,
  api: Api.RemoteClient,
  options: VpnTileActionOptions,
): Promise<VpnTileActionResult> {
  const response = await api.list_network_instance_ids()
  const runningIds = (response.running_inst_ids ?? []).map(Utils.UuidToStr)
  const disabledIds = (response.disabled_inst_ids ?? []).map(Utils.UuidToStr)
  const configuredIds = [...new Set([...runningIds, ...disabledIds])]

  const candidateIds = action === 'stop' ? runningIds : configuredIds
  const candidateConfigs = new Map(
    await Promise.all(candidateIds.map(async (instanceId) => {
      const config = await api.get_network_config(instanceId)
      return [instanceId, config] as const
    })),
  )
  const candidates = candidateIds.filter(instanceId => !candidateConfigs.get(instanceId)?.no_tun)
  const instanceId = options.lastInstanceId && candidates.includes(options.lastInstanceId)
    ? options.lastInstanceId
    : candidates[0]

  if (!instanceId) {
    return { action, changed: false }
  }

  let changed = false
  if (action === 'start' && !runningIds.includes(instanceId)) {
    const config = candidateConfigs.get(instanceId)!
    await api.run_network(config, true)
    changed = true
  }
  else if (action === 'stop') {
    await api.update_network_instance_state(instanceId, true)
    changed = true
  }

  await options.syncVpnService()
  return { action, instanceId, changed }
}
