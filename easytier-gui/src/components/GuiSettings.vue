<script setup lang="ts">
import type { Mode } from '~/composables/mode'
import { disable, enable, isEnabled } from '@tauri-apps/plugin-autostart'
import { type } from '@tauri-apps/plugin-os'
import { type Api, Utils } from 'easytier-frontend-lib'
import { useToast } from 'primevue'
import { computed, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { getGuiSettings, type GuiSettings, saveGuiSettings } from '~/composables/settings'

const props = defineProps<{ api: Api.RemoteClient, mode: Mode, clientRunning: boolean }>()
const visible = defineModel<boolean>('visible', { default: false })
const { t } = useI18n()
const toast = useToast()
const desktop = !['android', 'ios'].includes(type())
const loading = ref(false)
const saving = ref(false)
const loadFailed = ref(false)
const autostart = ref(false)
const autostartAvailable = ref(false)
const autostartSaving = ref(false)
const settings = ref<GuiSettings>({ closeToTray: true, autoStartNetwork: false, startupNetworkId: null })
const networks = ref<Array<{ id: string, label: string }>>([])
const networkLoadFailed = ref(false)
const missingNetwork = computed(() => settings.value.startupNetworkId
  && !networks.value.some(network => network.id === settings.value.startupNetworkId))
const invalidNetwork = computed(() => desktop && props.mode.mode === 'normal' && settings.value.autoStartNetwork
  && (!settings.value.startupNetworkId || missingNetwork.value || networkLoadFailed.value))

function showError(error: unknown) {
  toast.add({ severity: 'error', summary: t('error'), detail: String(error), life: 8000 })
}

watch(visible, async (open) => {
  if (!open)
    return
  loading.value = true
  loadFailed.value = false
  networks.value = []
  networkLoadFailed.value = false
  try {
    settings.value = await getGuiSettings()
  }
  catch (error) {
    loadFailed.value = true
    showError(error)
  }
  if (desktop) {
    autostartAvailable.value = false
    try {
      autostart.value = await isEnabled()
      autostartAvailable.value = true
    }
    catch (error) {
      showError(error)
    }
    if (props.mode.mode === 'normal' && props.clientRunning) {
      try {
        const response = await props.api.list_network_instance_ids()
        const ids = [...new Set([...response.running_inst_ids, ...response.disabled_inst_ids].map(Utils.UuidToStr))]
        const { metas } = await props.api.get_network_metas(ids)
        networks.value = ids.map(id => ({ id, label: `${metas[id]?.network_name || t('network')} (${id})` }))
      }
      catch (error) {
        networkLoadFailed.value = true
        showError(error)
      }
    }
  }
  loading.value = false
})

async function changeAutostart(value: boolean) {
  const previous = autostart.value
  autostart.value = value
  autostartSaving.value = true
  try {
    if (value)
      await enable()
    else await disable()
    autostart.value = await isEnabled()
  }
  catch (error) {
    showError(error)
    // Reflect the actual OS state even if a write succeeded but its response failed.
    try {
      autostart.value = await isEnabled()
    }
    catch {
      autostart.value = previous
      autostartAvailable.value = false
    }
  }
  finally {
    autostartSaving.value = false
  }
}

async function save() {
  if (invalidNetwork.value || saving.value)
    return
  saving.value = true
  try {
    await saveGuiSettings({ ...settings.value })
    visible.value = false
    toast.add({ severity: 'success', summary: t('gui_settings.saved'), life: 3000 })
  }
  catch (error) {
    showError(error)
  }
  finally {
    saving.value = false
  }
}
</script>

<template>
  <Dialog
    v-model:visible="visible" modal :header="t('gui_settings.title')"
    :style="{ width: '38rem', maxWidth: 'calc(100vw - 2rem)' }" :closable="!saving && !autostartSaving"
  >
    <div class="flex flex-col gap-5">
      <template v-if="desktop">
        <div class="flex items-center justify-between gap-4">
          <div>
            <label for="gui-autostart" class="font-medium">{{ t('gui_settings.autostart') }}</label>
            <p class="text-sm text-surface-500 mt-1">
              {{ t('gui_settings.autostart_hint') }}
            </p>
          </div>
          <ToggleSwitch
            input-id="gui-autostart" :model-value="autostart"
            :disabled="loading || !autostartAvailable || autostartSaving || saving" @update:model-value="changeAutostart"
          />
        </div>
        <div class="flex items-center justify-between gap-4">
          <div>
            <label for="gui-close-to-tray" class="font-medium">{{ t('gui_settings.close_to_tray') }}</label>
            <p class="text-sm text-surface-500 mt-1">
              {{ t('gui_settings.close_to_tray_hint') }}
            </p>
          </div>
          <ToggleSwitch v-model="settings.closeToTray" input-id="gui-close-to-tray" :disabled="loading || loadFailed || saving" />
        </div>
        <div class="flex flex-col gap-3">
          <div class="flex items-center justify-between gap-4">
            <label for="gui-auto-network" class="font-medium">{{ t('gui_settings.auto_start_network') }}</label>
            <ToggleSwitch
              v-model="settings.autoStartNetwork" input-id="gui-auto-network"
              :disabled="loading || loadFailed || saving || mode.mode !== 'normal'"
            />
          </div>
          <p class="text-sm text-surface-500">
            {{ t(mode.mode === 'normal' ? 'gui_settings.auto_start_network_hint' : 'gui_settings.normal_mode_only') }}
          </p>
          <template v-if="mode.mode === 'normal' && settings.autoStartNetwork">
            <label for="gui-startup-network">{{ t('gui_settings.startup_network') }}</label>
            <Select
              v-model="settings.startupNetworkId" input-id="gui-startup-network" :options="networks"
              option-label="label" option-value="id" :placeholder="t('select_network')" filter
              :disabled="loading || saving || !clientRunning || networkLoadFailed" class="w-full"
              :empty-message="t('gui_settings.no_networks')"
            />
            <Message v-if="!loading && (!clientRunning || networkLoadFailed)" severity="warn" :closable="false">
              {{ t('gui_settings.networks_unavailable') }}
            </Message>
            <Message v-else-if="!loading && missingNetwork" severity="warn" :closable="false">
              {{ t('gui_settings.network_missing') }}
            </Message>
            <small v-else-if="!loading && networks.length === 0">{{ t('gui_settings.no_networks') }}</small>
          </template>
        </div>
        <Divider />
      </template>
      <div>
        <h3 class="font-medium mb-3">
          {{ t('gui_settings.tools') }}
        </h3>
        <slot />
      </div>
    </div>
    <template #footer>
      <Button :label="t('web.common.cancel')" text :disabled="saving || autostartSaving" @click="visible = false" />
      <Button
        :label="t('web.common.save')" icon="pi pi-check" :loading="saving" :disabled="loading || loadFailed || autostartSaving || !!invalidNetwork"
        @click="save"
      />
    </template>
  </Dialog>
</template>
