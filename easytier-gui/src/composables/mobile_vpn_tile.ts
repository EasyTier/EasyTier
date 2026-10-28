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
  stoppedInstanceIds?: string[]
  saveStoppedInstanceIds?: (instanceIds: string[]) => void
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
  const stoppedCandidates = [...new Set(options.stoppedInstanceIds ?? [])]
    .filter(instanceId => candidates.includes(instanceId))
  const restoringStoppedGroup = action === 'start' && !!options.stoppedInstanceIds?.length
  const selectedCandidates = restoringStoppedGroup
    ? stoppedCandidates
    : candidates
  const instanceId = options.lastInstanceId && selectedCandidates.includes(options.lastInstanceId)
    ? options.lastInstanceId
    : selectedCandidates[0]

  if (!instanceId) {
    if (restoringStoppedGroup)
      options.saveStoppedInstanceIds?.([])
    return { action, changed: false }
  }

  let changed = false
  if (action === 'start') {
    const startIds = restoringStoppedGroup ? stoppedCandidates : [instanceId]
    for (const candidateId of startIds) {
      if (!runningIds.includes(candidateId)) {
        await api.run_network(candidateConfigs.get(candidateId)!, true)
        changed = true
      }
    }
    options.saveStoppedInstanceIds?.([])
  }
  else if (action === 'stop') {
    // Save before stopping so a partially completed action can also be resumed.
    options.saveStoppedInstanceIds?.([...candidates])
    for (const candidateId of candidates) {
      await api.update_network_instance_state(candidateId, true)
    }
    changed = true
  }

  await options.syncVpnService()
  return { action, instanceId, changed }
}
