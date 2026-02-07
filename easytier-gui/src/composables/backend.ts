import { invoke } from '@tauri-apps/api/core'
import { Api, type NetworkTypes } from 'easytier-frontend-lib'
import { GetNetworkMetasResponse } from 'node_modules/easytier-frontend-lib/dist/modules/api'


type NetworkConfig = NetworkTypes.NetworkConfig
type ValidateConfigResponse = Api.ValidateConfigResponse
type ListNetworkInstanceIdResponse = Api.ListNetworkInstanceIdResponse
interface ServiceOptions {
  config_dir: string
  rpc_portal: string
  file_log_level: string
  file_log_dir: string
  config_server?: string
}

export type ServiceStatus = "Running" | "Stopped" | "NotInstalled"

export async function parseNetworkConfig(cfg: NetworkConfig) {
  return invoke<string>('parse_network_config', { cfg })
}

export async function generateNetworkConfig(tomlConfig: string) {
  return invoke<NetworkConfig>('generate_network_config', { tomlConfig })
}

export async function runNetworkInstance(cfg: NetworkConfig, save: boolean) {
  if (save) {
    let networkList: NetworkConfig[] = JSON.parse(localStorage.getItem('networkList') || '[]');
    const index = networkList.findIndex(c => c.instance_id === cfg.instance_id);
    if (index !== -1) {
      networkList[index] = cfg;
    } else {
      networkList.push(cfg);
    }
    localStorage.setItem('networkList', JSON.stringify(networkList));
  }
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
  let networkList: NetworkConfig[] = JSON.parse(localStorage.getItem('networkList') || '[]');
  networkList = networkList.filter(c => c.instance_id !== instanceId);
  localStorage.setItem('networkList', JSON.stringify(networkList));
  return await invoke('remove_network_instance', { instanceId })
}

export async function updateNetworkConfigState(instanceId: string, disabled: boolean) {
  return await invoke('update_network_config_state', { instanceId, disabled })
}

export async function saveNetworkConfig(cfg: NetworkConfig) {
  let networkList: NetworkConfig[] = JSON.parse(localStorage.getItem('networkList') || '[]');
  const index = networkList.findIndex(c => c.instance_id === cfg.instance_id);
  if (index !== -1) {
    networkList[index] = cfg;
  } else {
    networkList.push(cfg);
  }
  localStorage.setItem('networkList', JSON.stringify(networkList));
  return await invoke('save_network_config', { cfg })
}

export async function validateConfig(cfg: NetworkConfig) {
  return await invoke<ValidateConfigResponse>('validate_config', { cfg })
}

export async function getConfig(instanceId: string) {
  return await invoke<NetworkConfig>('get_config', { instanceId })
}

export async function sendConfigs(enabledNetworks: string[]) {
  let networkList: NetworkConfig[] = JSON.parse(localStorage.getItem('networkList') || '[]');
  return await invoke('load_configs', { configs: networkList, enabledNetworks })
}

export async function getNetworkMetas(instanceIds: string[]) {
  return await invoke<GetNetworkMetasResponse>('get_network_metas', { instanceIds })
}

export async function initService(opts?: ServiceOptions) {
  return await invoke('init_service', { opts })
}

export async function setServiceStatus(enable: boolean) {
  return await invoke('set_service_status', { enable })
}

export async function getServiceStatus() {
  return await invoke<ServiceStatus>('get_service_status')
}

export async function initRpcConnection(isNormalMode: boolean, url?: string) {
  return await invoke('init_rpc_connection', { isNormalMode, url })
}

export async function isClientRunning() {
  return await invoke<boolean>('is_client_running')
}

export async function initWebClient(url?: string) {
  return await invoke('init_web_client', { url })
}

export async function isWebClientConnected() {
  return await invoke<boolean>('is_web_client_connected')
}
