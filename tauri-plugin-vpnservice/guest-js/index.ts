import { invoke } from '@tauri-apps/api/core'

export async function ping(value: string): Promise<string | null> {
  return await invoke<{ value?: string }>('plugin:vpnservice|ping', {
    payload: {
      value,
    },
  }).then((r) => (r.value ? r.value : null));
}

export interface InvokeResponse {
  error_msg?: string;
}

export interface StartVpnRequest {
  ipv4_addr?: string;
  disallowed_applications?: string[];
}

export async function start_vpn(request: StartVpnRequest): Promise<InvokeResponse | null> {
  return await invoke<InvokeResponse>('plugin:vpnservice|start_vpn', {
    payload: request,
  })
}

export async function stop_vpn(): Promise<InvokeResponse | null> {
  return await invoke<InvokeResponse>('plugin:vpnservice|stop_vpn', {
    payload: {},
  })
}
