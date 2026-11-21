import { invoke } from '@tauri-apps/api/core'

export async function loadDockHiddenPreference(): Promise<boolean> {
  try {
    return await invoke<boolean>('get_dock_hidden_preference')
  }
  catch (e) {
    console.error('Failed to load dock visibility preference:', e)
    return false
  }
}

export async function saveDockHiddenPreference(hidden: boolean): Promise<boolean> {
  try {
    return await invoke<boolean>('set_dock_hidden_preference', { hidden })
  }
  catch (e) {
    console.error('Failed to save dock visibility preference:', e)
    return loadDockHiddenPreference()
  }
}
