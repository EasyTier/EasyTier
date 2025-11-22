interface NormalMode {
    mode: 'normal'
}

export interface ServiceMode {
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

import { type } from '@tauri-apps/plugin-os';

export function loadMode(): Mode {
    if (type() === 'android') {
        return { mode: 'normal' };
    }
    const modeStr = localStorage.getItem('app_mode')
    if (modeStr) {
        return JSON.parse(modeStr) as Mode
    } else {
        return { mode: 'normal' }
    }
}

export type Mode = NormalMode | ServiceMode | RemoteMode
