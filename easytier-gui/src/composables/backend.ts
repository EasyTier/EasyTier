import { invoke } from '@tauri-apps/api/core'
import { Api, type NetworkTypes } from 'easytier-frontend-lib'
import { GetNetworkMetasResponse } from 'node_modules/easytier-frontend-lib/dist/modules/api'
import { getAutoLaunchStatusAsync } from '~/modules/auto_launch'

type NetworkConfig = NetworkTypes.NetworkConfig
type ValidateConfigResponse = Api.ValidateConfigResponse
type ListNetworkInstanceIdResponse = Api.ListNetworkInstanceIdResponse

export async function parseNetworkConfig(cfg: NetworkConfig) {
  return invoke<string>('parse_network_config', { cfg })
}

export async function generateNetworkConfig(tomlConfig: string) {
  return invoke<NetworkConfig>('generate_network_config', { tomlConfig })
}

export async function runNetworkInstance(cfg: NetworkConfig, save: boolean) {
  return invoke('run_network_instance', { cfg, save })
}

export async function collectNetworkInfo(instanceId: string) {
  return await invoke<Api.CollectNetworkInfoResponse>('collect_network_info', { instanceId })
}

export async function setLoggingLevel(level: string) {
  return await invoke('set_logging_level', { level })
}

export async function setTunFd(fd: number) {
  return await invoke('set_tun_fd', { fd })
}

export async function getEasytierVersion() {
  return await invoke<string>('easytier_version')
}

export async function listNetworkInstanceIds() {
  return await invoke<ListNetworkInstanceIdResponse>('list_network_instance_ids')
}

export async function deleteNetworkInstance(instanceId: string) {
  return await invoke('remove_network_instance', { instanceId })
}

export async function updateNetworkConfigState(instanceId: string, disabled: boolean) {
  return await invoke('update_network_config_state', { instanceId, disabled })
}

export async function saveNetworkConfig(cfg: NetworkConfig) {
  return await invoke('save_network_config', { cfg })
}

export async function validateConfig(cfg: NetworkConfig) {
  return await invoke<ValidateConfigResponse>('validate_config', { cfg })
}

export async function getConfig(instanceId: string) {
  return await invoke<NetworkConfig>('get_config', { instanceId })
}

export async function sendConfigs() {
  let networkList: NetworkConfig[] = JSON.parse(localStorage.getItem('networkList') || '[]');
  let autoStartInstIds = getAutoLaunchStatusAsync() ? JSON.parse(localStorage.getItem('autoStartInstIds') || '[]') : []
  return await invoke('load_configs', { configs: networkList, enabledNetworks: autoStartInstIds })
}

export async function getNetworkMetas(instanceIds: string[]) {
  return await invoke<GetNetworkMetasResponse>('get_network_metas', { instanceIds })
}
