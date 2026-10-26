import type { Api } from 'easytier-frontend-lib'
import { invoke } from '@tauri-apps/api/core'
import { Utils } from 'easytier-frontend-lib'

export interface GuiSettings {
  closeToTray: boolean
  autoStartNetwork: boolean
  startupNetworkId: string | null
}

export function getGuiSettings() {
  return invoke<GuiSettings>('get_gui_settings')
}

export function saveGuiSettings(settings: GuiSettings) {
  return invoke<void>('save_gui_settings', { settings })
}

// Called once after the initial RPC connection and saved configs are ready.
// Reconnects and mode changes must not restart a network the user has stopped.
export async function startConfiguredNetwork(api: Api.RemoteClient, settings: GuiSettings) {
  if (!settings.autoStartNetwork || !settings.startupNetworkId)
    return

  const id = settings.startupNetworkId
  const response = await api.list_network_instance_ids()
  if ((response.running_inst_ids ?? []).map(Utils.UuidToStr).includes(id))
    return id
  if (!(response.disabled_inst_ids ?? []).map(Utils.UuidToStr).includes(id))
    throw new Error(`Startup network ${id} no longer exists`)

  const config = await api.get_network_config(id)
  await api.run_network(config, false)
  return id
}
