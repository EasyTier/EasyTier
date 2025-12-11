declare module 'tauri-plugin-vpnservice-api' {
  export function prepare_vpn(...args: any[]): Promise<any>;
  export function start_vpn(...args: any[]): Promise<any>;
  export function stop_vpn(...args: any[]): Promise<any>;
}
