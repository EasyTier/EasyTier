import { type } from '@tauri-apps/plugin-os';

export interface WebClientConfig {
    config_server_url?: string
}

interface NormalMode extends WebClientConfig {
    mode: 'normal'
}

export interface ServiceMode extends WebClientConfig {
    mode: 'service'
    config_dir: string
    rpc_portal: string
    file_log_level: 'off' | 'warn' | 'info' | 'debug' | 'trace'
    file_log_dir: string
}

export interface RemoteMode {
    mode: 'remote'
    remote_rpc_address: string
}

export function saveMode(mode: Mode) {
    localStorage.setItem('app_mode', JSON.stringify(mode))
}


export function loadMode(): Mode {
    const modeStr = localStorage.getItem('app_mode')
    if (modeStr) {
        let mode = JSON.parse(modeStr) as Mode
        if (type() === 'android') {
            return { ...mode, mode: 'normal' }
        }
        return mode
    } else {
        return { mode: 'normal' }
    }
}

export type Mode = NormalMode | ServiceMode | RemoteMode
