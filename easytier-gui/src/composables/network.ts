import type { NetworkTypes } from 'easytier-frontend-lib'
import { invoke } from '@tauri-apps/api/core'

type NetworkConfig = NetworkTypes.NetworkConfig
type NetworkInstanceRunningInfo = NetworkTypes.NetworkInstanceRunningInfo

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

export async function isAutostart() {
  return await invoke<boolean>('is_autostart')
}

export async function setLoggingLevel(level: string) {
  return await invoke('set_logging_level', { level })
}

export async function setTunFd(instanceId: string, fd: number) {
  return await invoke('set_tun_fd', { instanceId, fd })
}

export async function getEasytierVersion() {
  return await invoke<string>('easytier_version')
}
