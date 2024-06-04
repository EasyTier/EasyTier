import { setAutoLaunchStatus } from "~/composables/network"

export async function loadAutoLaunchStatusAsync(enable: boolean): Promise<boolean> {
    try {
        const ret = await setAutoLaunchStatus(enable)
        localStorage.setItem('auto_launch', JSON.stringify(ret))
        return ret
    } catch (e) {
        console.error(e)
        return false
    }
}

export function getAutoLaunchStatusAsync(): boolean {
    return localStorage.getItem('auto_launch') === 'true'
}
