import { invoke } from '@tauri-apps/api/tauri'
import type { NetworkConfig, NetworkInstanceRunningInfo } from '~/types/network'

export async function parseNetworkConfig(cfg: NetworkConfig): Promise<string> {
  return invoke<string>('parse_network_config', { cfg: JSON.stringify(cfg) })
}

export async function runNetworkInstance(cfg: NetworkConfig): Promise<string> {
  return invoke<string>('run_network_instance', { cfg: JSON.stringify(cfg) })
}

export async function retainNetworkInstance(instanceIds: string[]): Promise<string> {
  return invoke<string>('retain_network_instance', { instanceIds: JSON.stringify(instanceIds) })
}

export async function collectNetworkInfos(): Promise<Record<string, NetworkInstanceRunningInfo>> {
  return JSON.parse(await invoke<string>('collect_network_infos'))
}
