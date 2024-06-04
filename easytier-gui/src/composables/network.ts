import { invoke } from '@tauri-apps/api/tauri'
import type { NetworkConfig, NetworkInstanceRunningInfo } from '~/types/network'

export async function parseNetworkConfig(cfg: NetworkConfig) {
  return invoke<string>('parse_network_config', { cfg })
}

export async function runNetworkInstance(cfg: NetworkConfig) {
  return invoke('run_network_instance', { cfg })
}

export async function retainNetworkInstance(instanceIds: string[]) {
  return invoke('retain_network_instance', { instanceIds })
}

export async function collectNetworkInfos() {
  return await invoke<Record<string, NetworkInstanceRunningInfo>>('collect_network_infos')
}

export async function getOsHostname() {
  return await invoke<string>('get_os_hostname')
}

export async function setAutoLaunchStatus(enable: boolean) {
  return await invoke<boolean>('set_auto_launch_status', { enable })
}
