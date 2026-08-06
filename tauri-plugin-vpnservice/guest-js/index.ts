import { invoke } from '@tauri-apps/api/core'

export async function ping(value: string): Promise<string | null> {
  return await invoke<{ value?: string }>('plugin:vpnservice|ping', {
    payload: {
      value,
    },
  }).then((r) => (r.value ? r.value : null));
}

export interface InvokeResponse {
  errorMsg?: string;
  granted?: boolean;
}

export interface StartVpnRequest {
  ipv4Addr?: string;
  routes?: string[];
  dns?: string;
  disallowedApplications?: string[];
  mtu?: number;
}

export interface VpnStatusResponse {
  running: boolean;
  ipv4Addr?: string;
  routes?: string[];
  dns?: string;
}

export interface PendingTileToggleResponse {
  pending: boolean;
  targetActive: boolean;
}

export async function prepare_vpn(): Promise<InvokeResponse | null> {
  return await invoke<InvokeResponse>('plugin:vpnservice|prepare_vpn', {})
}

export async function start_vpn(request: StartVpnRequest): Promise<InvokeResponse | null> {
  return await invoke<InvokeResponse>('plugin:vpnservice|start_vpn', {
    payload: request,
  })
}

export async function stop_vpn(): Promise<InvokeResponse | null> {
  return await invoke<InvokeResponse>('plugin:vpnservice|stop_vpn', {})
}

export async function get_vpn_status(): Promise<VpnStatusResponse | null> {
  return await invoke<VpnStatusResponse>('plugin:vpnservice|get_vpn_status', {})
}

export async function consume_tile_toggle(): Promise<PendingTileToggleResponse> {
  return await invoke<PendingTileToggleResponse>('plugin:vpnservice|consume_tile_toggle', {})
}

export async function complete_tile_toggle(): Promise<void> {
  await invoke('plugin:vpnservice|complete_tile_toggle', {})
}

export async function save_headless_profile(configToml: string): Promise<void> {
  await invoke('plugin:vpnservice|save_headless_profile', {
    payload: { configToml },
  })
}
