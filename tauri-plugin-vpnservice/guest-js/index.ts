import { invoke } from '@tauri-apps/api/core'

export async function ping(value: string): Promise<string | null> {
  return await invoke<{ value?: string }>('plugin:vpnservice|ping', {
    payload: {
      value,
    },
  }).then((r) => (r.value ? r.value : null));
}

export async function start_vpn(ipv4_addr: string): Promise<string | null> {
  return await invoke<{ ipv4_addr?: string }>('plugin:vpnservice|start_vpn', {
    payload: {
      ipv4_addr,
    },
  }).then((r) => (r.ipv4_addr ? r.ipv4_addr : null));
}
