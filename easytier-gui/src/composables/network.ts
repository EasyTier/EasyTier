import { invoke } from '@tauri-apps/api/tauri'
import type { NetworkConfig } from '~/types/network'

export async function parseNetworkConfig(cfg: NetworkConfig): Promise<string> {
  const ret: string = await invoke('parse_network_config', { cfg: JSON.stringify(cfg) })
  return ret
}

export async function runNetworkInstance(cfg: NetworkConfig) {
  const ret: string = await invoke('run_network_instance', { cfg: JSON.stringify(cfg) })
  return ret
}

export async function retainNetworkInstance(instanceIds: Array<string>) {
  const ret: string = await invoke('retain_network_instance', { instanceIds: JSON.stringify(instanceIds) })
  return ret
}

export async function collectNetworkInfos() {
  const ret: string = await invoke('collect_network_infos', {})
  return JSON.parse(ret)
}

export async function getOsHostname(): Promise<string> {
  return await invoke('get_os_hostname')
}