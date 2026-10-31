// @vitest-environment happy-dom
import type { Api } from 'easytier-frontend-lib'
import PrimeVue from 'primevue/config'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { type App, createApp, h, nextTick, ref } from 'vue'
import GuiSettings from './GuiSettings.vue'

const mocks = vi.hoisted(() => ({
  get: vi.fn(),
  save: vi.fn(),
  isEnabled: vi.fn(),
  enable: vi.fn(),
  disable: vi.fn(),
  toast: vi.fn(),
}))
vi.mock('~/composables/settings', () => ({ getGuiSettings: mocks.get, saveGuiSettings: mocks.save }))
vi.mock('@tauri-apps/plugin-os', () => ({ type: () => 'windows' }))
vi.mock('@tauri-apps/plugin-autostart', () => ({ isEnabled: mocks.isEnabled, enable: mocks.enable, disable: mocks.disable }))
vi.mock('vue-i18n', () => ({ useI18n: () => ({ t: (key: string) => key }) }))
vi.mock('primevue', () => ({ useToast: () => ({ add: mocks.toast }) }))
vi.mock('easytier-frontend-lib', () => ({ Utils: { UuidToStr: (id: unknown) => String(id) } }))

let app: App
const visible = ref(false)
async function settle() {
  await new Promise(resolve => setTimeout(resolve, 0))
  await nextTick()
}
function button(label: string) {
  return Array.from(document.querySelectorAll('button')).find(element => element.textContent === label)!
}

beforeEach(async () => {
  vi.resetAllMocks()
  mocks.get.mockResolvedValue({ closeToTray: true, autoStartNetwork: false, startupNetworkId: null })
  mocks.save.mockResolvedValue(undefined)
  mocks.isEnabled.mockResolvedValue(false)
  mocks.enable.mockResolvedValue(undefined)
  visible.value = false
  const host = document.createElement('div')
  document.body.append(host)
  const api = {
    list_network_instance_ids: vi.fn(async () => ({ running_inst_ids: [], disabled_inst_ids: ['selected'] })),
    get_network_metas: vi.fn(async () => ({ metas: { selected: { network_name: 'Office' } } })),
  } as unknown as Api.RemoteClient
  app = createApp({
    render: () => h(GuiSettings, { 'visible': visible.value, 'onUpdate:visible': value => visible.value = value, api, 'mode': { mode: 'normal' }, 'clientRunning': true }),
  })
  app.use(PrimeVue, { unstyled: true })
  app.mount(host)
  visible.value = true
  await settle()
})

afterEach(() => {
  app?.unmount()
  document.body.innerHTML = ''
})

describe('gui settings dialog', () => {
  it('persists close behavior only after Save', async () => {
    document.querySelector<HTMLInputElement>('#gui-close-to-tray')!.click()
    await settle()
    expect(mocks.save).not.toHaveBeenCalled()
    button('web.common.save').click()
    await settle()
    expect(mocks.save).toHaveBeenCalledWith({ closeToTray: false, autoStartNetwork: false, startupNetworkId: null })
    expect(visible.value).toBe(false)
  })

  it('discards unsaved preferences on Cancel', async () => {
    document.querySelector<HTMLInputElement>('#gui-close-to-tray')!.click()
    button('web.common.cancel').click()
    await settle()
    expect(mocks.save).not.toHaveBeenCalled()
    expect(visible.value).toBe(false)
  })

  it('requires an explicit network selection before saving automatic startup', async () => {
    document.querySelector<HTMLInputElement>('#gui-auto-network')!.click()
    await settle()
    expect(button('web.common.save').disabled).toBe(true)
    expect(mocks.save).not.toHaveBeenCalled()
  })

  it('keeps the dialog open when saving preferences fails', async () => {
    mocks.save.mockRejectedValue(new Error('Disk full'))
    button('web.common.save').click()
    await settle()
    expect(visible.value).toBe(true)
    expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ severity: 'error', detail: 'Error: Disk full' }))
  })

  it('restores the autostart switch to the OS state after an error', async () => {
    mocks.enable.mockRejectedValue(new Error('Access denied'))
    const input = document.querySelector<HTMLInputElement>('#gui-autostart')!
    input.click()
    await settle()
    expect(mocks.enable).toHaveBeenCalledOnce()
    expect(input.checked).toBe(false)
    expect(mocks.toast).toHaveBeenCalledWith(expect.objectContaining({ severity: 'error' }))
  })
})
