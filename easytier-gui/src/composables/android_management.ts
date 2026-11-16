import type { Mode } from './mode'
import { invoke } from '@tauri-apps/api/core'
import { NetworkTypes } from 'easytier-frontend-lib'
import { parseStoredConfigs } from './backend'

interface Snapshot {
  schema_version: number
  configs: unknown[]
  desired_enabled: string[]
  profile: Mode
  selected_network: string | null
}

// UI cache only. The encrypted native repository is authoritative after migration.
let preferences: Pick<Snapshot, 'profile' | 'selected_network'> | undefined
let committedPreferences: typeof preferences
let pendingWrite: Promise<void> = Promise.resolve()

export async function bootstrapAndroidManagement() {
  let snapshot = await invoke<Snapshot | null>('bootstrap_android_management', { legacy: null })
  if (!snapshot) {
    const raw = localStorage.getItem('networkList')
    const entries: unknown = JSON.parse(raw || '[]')
    if (!Array.isArray(entries) || entries.some(entry => !entry || typeof entry !== 'object' || ('config' in entry && !entry.config))) {
      throw new Error('Invalid legacy network storage; migration was not performed')
    }
    const configs = parseStoredConfigs(raw)
    snapshot = await invoke<Snapshot>('bootstrap_android_management', {
      legacy: {
        schema_version: 1,
        configs: configs.map(({ config, source }) => ({
          config: NetworkTypes.toBackendNetworkConfig(config),
          source,
        })),
        // Existing versions do not persist an auto-start selection. Do not invent one.
        desired_enabled: [],
        profile: JSON.parse(localStorage.getItem('app_mode') || '{"mode":"normal"}'),
        selected_network: localStorage.getItem('last_network_instance_id'),
      },
    })
  }
  if (!snapshot)
    throw new Error('Android management storage was not initialized')
  preferences = { profile: snapshot.profile, selected_network: snapshot.selected_network }
  committedPreferences = preferences
  // Only remove the plaintext legacy copy after the durable native commit succeeds.
  localStorage.removeItem('networkList')
  localStorage.removeItem('app_mode')
  localStorage.removeItem('last_network_instance_id')
}

export function androidPreferences() {
  if (!preferences)
    throw new Error('Android management storage is not initialized')
  return preferences
}

export function saveAndroidPreferences(change: Partial<Pick<Snapshot, 'profile' | 'selected_network'>>) {
  const next = { ...androidPreferences(), ...change }
  preferences = next
  // Preserve call order even when selection and mode change in the same UI turn.
  const write = pendingWrite.catch(() => {}).then(async () => {
    try {
      await invoke<void>('save_android_management_preferences', {
        profile: next.profile,
        selectedNetwork: next.selected_network,
      })
      committedPreferences = next
    }
    catch (error) {
      if (preferences === next)
        preferences = committedPreferences
      throw error
    }
  })
  pendingWrite = write
  return write
}
