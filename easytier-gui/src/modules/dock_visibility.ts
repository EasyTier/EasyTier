import { invoke } from '@tauri-apps/api/core'

export async function loadDockVisibilityAsync(visible: boolean): Promise<boolean> {
  try {
    await invoke('set_dock_visibility', { visible })
    localStorage.setItem('dock_visibility', JSON.stringify(visible))
    return visible
  }
  catch (e) {
    console.error('Failed to set dock visibility:', e)
    return getDockVisibilityStatus()
  }
}

export function getDockVisibilityStatus(): boolean {
  const stored = localStorage.getItem('dock_visibility')
  return stored !== null ? JSON.parse(stored) : true
}
