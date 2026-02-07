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

export function getStoredNetworkList(): NetworkConfig[] {
  try {
    const list = JSON.parse(localStorage.getItem('networkList') || '[]');
    if (Array.isArray(list)) {
      return list;
    }
  } catch (e) {
    console.error("Failed to parse networkList from localStorage", e);
  }
  return [];
}

export function saveStoredNetworkList(list: NetworkConfig[]) {
  localStorage.setItem('networkList', JSON.stringify(list));
}

export function upsertNetworkConfigInLocalStorage(cfg: NetworkConfig) {
  const networkList = getStoredNetworkList();
  const index = networkList.findIndex(c => c.instance_id === cfg.instance_id);
  if (index !== -1) {
    networkList[index] = cfg;
  } else {
    networkList.push(cfg);
  }
  saveStoredNetworkList(networkList);
}

export async function runNetworkInstance(cfg: NetworkConfig, save: boolean) {
  if (save) {
    upsertNetworkConfigInLocalStorage(cfg);
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
  const ret = await invoke('remove_network_instance', { instanceId })
  const networkList = getStoredNetworkList().filter(c => c.instance_id !== instanceId);
  saveStoredNetworkList(networkList);
  return ret;
}

export async function updateNetworkConfigState(instanceId: string, disabled: boolean) {
  return await invoke('update_network_config_state', { instanceId, disabled })
}

export async function saveNetworkConfig(cfg: NetworkConfig) {
  upsertNetworkConfigInLocalStorage(cfg);
  return await invoke('save_network_config', { cfg })
}

export async function validateConfig(cfg: NetworkConfig) {
  return await invoke<ValidateConfigResponse>('validate_config', { cfg })
}

export async function getConfig(instanceId: string) {
  return await invoke<NetworkConfig>('get_config', { instanceId })
}

export async function sendConfigs(enabledNetworks: string[]) {
  const networkList = getStoredNetworkList();
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
