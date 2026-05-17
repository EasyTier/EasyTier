import { invoke } from '@tauri-apps/api/core'
import { Api, NetworkTypes } from 'easytier-frontend-lib'
import { GetNetworkMetasResponse } from 'node_modules/easytier-frontend-lib/dist/modules/api'


type NetworkConfig = NetworkTypes.NetworkConfig
type ValidateConfigResponse = Api.ValidateConfigResponse
type ListNetworkInstanceIdResponse = Api.ListNetworkInstanceIdResponse
type ConfigSource = 'user' | 'webhook' | 'legacy'
interface ServiceOptions {
  config_dir: string
  rpc_portal: string
  file_log_level: string
  file_log_dir: string
  config_server?: string
}

export type ServiceStatus = "Running" | "Stopped" | "NotInstalled"

interface StoredGuiConfig {
  config: NetworkConfig
  source: ConfigSource
}

function parseStoredConfigs(raw: string | null): StoredGuiConfig[] {
  const parsed: unknown = JSON.parse(raw || '[]')
  if (!Array.isArray(parsed)) {
    return []
  }

  return parsed.flatMap((entry): StoredGuiConfig[] => {
    if (entry && typeof entry === 'object' && 'config' in entry) {
      const { config, source } = entry as {
        config?: NetworkConfig
        source?: ConfigSource
      }
      if (!config) {
        return []
      }
      return [{
        config: NetworkTypes.normalizeNetworkConfig(config),
        source: source === 'user' || source === 'webhook' ? source : 'legacy',
      }]
    }

    return [{
      config: NetworkTypes.normalizeNetworkConfig(entry as NetworkConfig),
      source: 'legacy',
    }]
  })
}

export async function parseNetworkConfig(cfg: NetworkConfig) {
  return invoke<string>('parse_network_config', { cfg: NetworkTypes.toBackendNetworkConfig(cfg) })
}

export async function generateNetworkConfig(tomlConfig: string) {
  const config = await invoke<NetworkConfig>('generate_network_config', { tomlConfig })
  return NetworkTypes.normalizeNetworkConfig(config)
}

export async function runNetworkInstance(cfg: NetworkConfig, save: boolean) {
  return invoke('run_network_instance', { cfg: NetworkTypes.toBackendNetworkConfig(cfg), save })
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
  return await invoke('save_network_config', { cfg: NetworkTypes.toBackendNetworkConfig(cfg) })
}

export async function validateConfig(cfg: NetworkConfig) {
  return await invoke<ValidateConfigResponse>('validate_config', { cfg: NetworkTypes.toBackendNetworkConfig(cfg) })
}

export async function getConfig(instanceId: string) {
  const config = await invoke<NetworkConfig>('get_config', { instanceId })
  return NetworkTypes.normalizeNetworkConfig(config)
}

export async function sendConfigs(enabledNetworks: string[]) {
  const networkList = parseStoredConfigs(localStorage.getItem('networkList'))
  return await invoke('load_configs', {
    configs: networkList.map(({ config, source }) => ({
      config: NetworkTypes.toBackendNetworkConfig(config),
      source,
    })),
    enabledNetworks
  })
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
