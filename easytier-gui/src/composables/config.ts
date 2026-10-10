import { type } from '@tauri-apps/plugin-os'
import { androidPreferences, saveAndroidPreferences } from './android_management'

/**
 * 配置持久化相关的函数
 * 用于保存和加载应用程序的各种配置状态
 */

/**
 * 保存上次使用的网络实例 ID
 * @param instanceId 网络实例 ID
 */
export async function saveLastNetworkInstanceId(instanceId: string) {
    if (type() === 'android') {
        await saveAndroidPreferences({ selected_network: instanceId })
        return
    }
    localStorage.setItem('last_network_instance_id', instanceId)
}

/**
 * 加载上次使用的网络实例 ID
 * @returns 上次使用的网络实例 ID，如果没有则返回 null
 */
export function loadLastNetworkInstanceId(): string | null {
    if (type() === 'android') return androidPreferences().selected_network
    return localStorage.getItem('last_network_instance_id')
}
