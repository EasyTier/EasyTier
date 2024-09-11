import { disable, enable, isEnabled } from '@tauri-apps/plugin-autostart'

export async function loadAutoLaunchStatusAsync(target_enable: boolean): Promise<boolean> {
  try {
    target_enable ? await enable() : await disable()
    localStorage.setItem('auto_launch', JSON.stringify(await isEnabled()))
    return isEnabled()
  }
  catch (e) {
    console.error(e)
    return false
  }
}

export function getAutoLaunchStatusAsync(): boolean {
  return localStorage.getItem('auto_launch') === 'true'
}
