import { disable, enable, isEnabled } from '@tauri-apps/plugin-autostart'

export async function loadAutoLaunchStatusAsync(target_enable: boolean): Promise<boolean> {
  try {
    if (target_enable) {
      await enable()
    }
    else {
      // 消除没有配置自启动时进行关闭操作报错
      try {
        await disable()
      }
      catch { }
    }
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
