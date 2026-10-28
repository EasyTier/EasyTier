<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { Button, Dialog, InputNumber, InputText, MultiSelect, Tag } from 'primevue'
import QRCode from 'qrcode'
import { v4 as uuidv4 } from 'uuid'
import type { RemoteClient } from '../modules/api'
import { PeriodicTask } from '../modules/utils'
import {
  normalizeVpnPortalEndpoint, suggestVpnPortalAddress, validVpnPortalAddress,
  vpnPortalClientConfig, vpnPortalEndpoint, vpnPortalListener, vpnPortalUsedIps,
} from '../modules/vpnPortal'
import { VpnPortalClientState, type NetworkConfig, type NetworkInstance, type VpnPortalInfo } from '../types/network'

const props = defineProps<{
  instance: NetworkInstance,
  api: RemoteClient,
  readonly?: boolean,
}>()
const emit = defineEmits(['close'])
const { t } = useI18n()
const info = ref<VpnPortalInfo>()
const config = ref<NetworkConfig>()
const loading = ref(true)
const busy = ref(false)
const error = ref('')
const loadError = ref('')
const adding = ref(false)
const name = ref('')
const defaultName = ref('')
const address = ref('')
const prefix = ref<number>()
const groups = ref<string[]>([])
const selectedName = ref('')
const deletingName = ref('')
const endpointOverride = ref('')
const copied = ref(false)
const qrCode = ref('')
const qrError = ref('')
let refreshVersion = 0
let disposed = false

const clients = computed(() => info.value?.clients ?? [])
const available = computed(() => info.value?.vpn_type === 'wireguard' && !!info.value.listener)
const groupOptions = computed(() => config.value?.acl?.acl_v1?.group?.declares.map(group => group.group_name) ?? [])
const usedIps = computed(() => vpnPortalUsedIps(props.instance, clients.value))
const clientName = computed(() => name.value.trim() || defaultName.value)
const validName = computed(() => /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(clientName.value)
  && !clients.value.some(client => client.name === clientName.value))
const validAddress = computed(() => validVpnPortalAddress(address.value.trim(), prefix.value, usedIps.value))
const canAdd = computed(() => available.value && !props.readonly && validName.value && validAddress.value
  && clients.value.length < 64 && !busy.value)
const selectedClient = computed(() => clients.value.find(client => client.name === selectedName.value))
const automaticEndpoint = computed(() => vpnPortalEndpoint(info.value?.listener ?? '', props.instance.detail?.my_node_info))
const endpoint = computed(() => normalizeVpnPortalEndpoint(
  endpointOverride.value || automaticEndpoint.value, vpnPortalListener(info.value?.listener ?? '')?.port ?? '',
))
const clientConfig = computed(() => vpnPortalClientConfig(selectedClient.value?.client_config ?? '', endpoint.value))

async function refresh() {
  if (disposed) return
  const version = ++refreshVersion
  try {
    const [portal, network] = await Promise.all([
      props.api.get_vpn_portal_info(props.instance.instance_id),
      props.api.get_network_config(props.instance.instance_id),
    ])
    if (disposed || version !== refreshVersion) return
    info.value = portal
    config.value = network
  } catch (cause) {
    if (!disposed && version === refreshVersion) throw cause
  }
}

const refreshTask = new PeriodicTask(async () => {
  if (busy.value) return
  try {
    await refresh()
    loadError.value = ''
  } catch (cause) {
    loadError.value = `${t('vpn_portal_load_failed')}: ${String(cause)}`
  } finally {
    loading.value = false
  }
}, 3000)

onMounted(() => refreshTask.start())
onUnmounted(() => {
  disposed = true
  refreshVersion++
  refreshTask.stop()
})

function addDevice() {
  name.value = ''
  // Names determine WireGuard identities; a new device must not recycle a deleted one's default name.
  defaultName.value = `device-${uuidv4().slice(0, 8)}`
  const suggestion = suggestVpnPortalAddress(props.instance, config.value?.vpn_portal_config?.clients ?? [], usedIps.value)
  address.value = suggestion.address
  prefix.value = suggestion.prefix
  groups.value = []
  selectedName.value = ''
  error.value = ''
  adding.value = true
}

async function saveDevice() {
  if (!canAdd.value) return
  busy.value = true
  refreshVersion++
  error.value = ''
  const newName = clientName.value
  try {
    await props.api.add_vpn_portal_client(props.instance.instance_id, {
      name: newName,
      virtual_ip: `${address.value.trim()}/${prefix.value}`,
      groups: groups.value,
    })
    adding.value = false
    selectedName.value = newName
    await refresh()
  } catch (cause) {
    error.value = `${t('vpn_portal_save_failed')}: ${String(cause)}`
  } finally {
    busy.value = false
  }
}

async function removeDevice(clientName: string) {
  if (busy.value || props.readonly) return
  busy.value = true
  refreshVersion++
  error.value = ''
  try {
    await props.api.remove_vpn_portal_client(props.instance.instance_id, clientName)
    deletingName.value = ''
    if (selectedName.value === clientName) selectedName.value = ''
    await refresh()
  } catch (cause) {
    error.value = `${t('vpn_portal_remove_failed')}: ${String(cause)}`
  } finally {
    busy.value = false
  }
}

function stateKey(state: VpnPortalClientState | string): string {
  const normalized = typeof state === 'string'
    ? state.toLowerCase().replace('vpn_portal_client_state_', '')
    : VpnPortalClientState[state]?.toLowerCase()
  return `vpn_portal_state_${normalized ?? 'unspecified'}`
}

function stateSeverity(state: VpnPortalClientState | string): 'success' | 'warn' | 'danger' | 'secondary' {
  const key = stateKey(state)
  if (key.endsWith('online')) return 'success'
  if (key.endsWith('connecting')) return 'warn'
  if (key.endsWith('error')) return 'danger'
  return 'secondary'
}

watch(clientConfig, async (value, _, onCleanup) => {
  let active = true
  onCleanup(() => { active = false })
  qrCode.value = ''
  qrError.value = ''
  copied.value = false
  if (!value) return
  try {
    const svg = await QRCode.toString(value, { type: 'svg', errorCorrectionLevel: 'M', margin: 4 })
    if (active) qrCode.value = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
  } catch {
    if (active) qrError.value = t('vpn_portal_qr_failed')
  }
})

async function copyConfig() {
  if (!clientConfig.value) return
  const value = clientConfig.value
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value)
    } else {
      const textarea = document.createElement('textarea')
      textarea.value = value
      textarea.style.position = 'fixed'
      textarea.style.opacity = '0'
      document.body.appendChild(textarea)
      try {
        textarea.select()
        if (!document.execCommand('copy')) throw new Error(t('vpn_portal_copy_failed'))
      } finally {
        textarea.remove()
      }
    }
    if (clientConfig.value === value) copied.value = true
  } catch {
    error.value = t('vpn_portal_copy_failed')
  }
}

function downloadConfig() {
  if (!clientConfig.value || !selectedClient.value) return
  const url = URL.createObjectURL(new Blob([clientConfig.value], { type: 'text/plain' }))
  const link = document.createElement('a')
  link.href = url
  link.download = `${selectedClient.value.name}.conf`
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
</script>

<template>
  <Dialog :visible="true" modal :header="t('vpn_portal_devices')" class="w-[48rem] max-w-[95vw]"
    :baseZIndex="2000" @update:visible="emit('close')">
    <div class="flex flex-col gap-4">
      <p v-if="loading" class="py-6 text-center">{{ t('web.device_management.loading_network_status') }}</p>
      <p v-if="error || loadError" role="alert" class="text-red-500">{{ error || loadError }}</p>
      <p v-if="!loading && !available">{{ t('vpn_portal_not_configured') }}</p>
      <template v-if="available">
        <div class="flex items-center justify-between gap-3">
          <span class="text-sm text-surface-500">{{ t('vpn_portal_devices_help') }}</span>
          <Button v-if="!readonly" icon="pi pi-plus" :label="t('vpn_portal_add_client')"
            :disabled="busy || clients.length >= 64 || adding" @click="addDevice" />
        </div>
        <p v-if="clients.length === 0 && !adding" class="py-6 text-center text-surface-500">{{ t('vpn_portal_no_clients') }}</p>
        <div v-for="client in clients" :key="client.name" class="rounded border border-surface-200 dark:border-surface-700 p-3">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <div>
              <span class="font-medium">{{ client.name }}</span>
              <span class="ml-2 text-sm text-surface-500">{{ client.virtual_ip }}</span>
              <Tag class="ml-2" :severity="stateSeverity(client.state)" :value="t(stateKey(client.state))" />
            </div>
            <div class="flex gap-2">
              <Button size="small" severity="secondary" :label="t('vpn_portal_connect_device')" :disabled="busy"
                @click="selectedName = client.name; adding = false" />
              <Button v-if="!readonly" icon="pi pi-trash" severity="danger" text
                :aria-label="t('vpn_portal_remove_client')" :disabled="busy" @click="deletingName = client.name" />
            </div>
          </div>
          <p v-if="client.error" class="mt-2 text-sm text-red-500">{{ client.error }}</p>
          <div v-if="deletingName === client.name" class="mt-3 flex flex-wrap items-center gap-2">
            <span class="text-sm">{{ t('vpn_portal_remove_confirm') }}</span>
            <Button size="small" severity="danger" :label="t('vpn_portal_remove_client')" :disabled="busy"
              @click="removeDevice(client.name)" />
            <Button size="small" text :label="t('web.common.cancel')" :disabled="busy" @click="deletingName = ''" />
          </div>
        </div>

        <form v-if="adding" class="flex flex-col gap-3 rounded border border-surface-200 dark:border-surface-700 p-4"
          @submit.prevent="saveDevice">
          <label for="vpn_portal_client_name">{{ t('vpn_portal_client_name') }}</label>
          <InputText id="vpn_portal_client_name" v-model="name" :placeholder="defaultName" :disabled="busy" />
          <small v-if="!validName" class="text-red-500">{{ t('vpn_portal_invalid_name') }}</small>
          <label for="vpn_portal_client_address">{{ t('vpn_portal_client_address') }}</label>
          <InputText id="vpn_portal_client_address" v-model="address" placeholder="10.126.126.10" :disabled="busy" />
          <small class="text-surface-500">{{ t('vpn_portal_address_help') }}</small>
          <small v-if="address && !validAddress" class="text-red-500">{{ t('vpn_portal_invalid_address') }}</small>
          <details :open="prefix === undefined">
            <summary class="cursor-pointer text-sm">{{ t('vpn_portal_advanced') }}</summary>
            <div class="mt-3 flex flex-col gap-2">
              <label for="vpn_portal_client_prefix">{{ t('vpn_portal_client_prefix') }}</label>
              <InputNumber input-id="vpn_portal_client_prefix" v-model="prefix" :min="0" :max="30" :disabled="busy" />
              <template v-if="groupOptions.length">
                <label for="vpn_portal_client_groups">{{ t('vpn_portal_client_groups') }}</label>
                <MultiSelect input-id="vpn_portal_client_groups" v-model="groups" :options="groupOptions"
                  :placeholder="t('vpn_portal_client_groups_placeholder')" appendTo="self" filter fluid :disabled="busy" />
              </template>
            </div>
          </details>
          <div class="flex gap-2">
            <Button type="submit" :label="t('vpn_portal_generate_config')" :disabled="!canAdd" :loading="busy" />
            <Button text :label="t('web.common.cancel')" :disabled="busy" @click="adding = false" />
          </div>
        </form>

        <div v-if="selectedClient" class="flex flex-col gap-3 border-t border-surface-200 dark:border-surface-700 pt-4">
          <div class="font-medium">{{ t('vpn_portal_client_config') }} · {{ selectedClient.name }}</div>
          <p v-if="endpoint" class="text-sm">{{ t('vpn_portal_server_endpoint') }}: {{ endpoint }}</p>
          <details :open="!automaticEndpoint">
            <summary class="cursor-pointer text-sm">{{ t('vpn_portal_custom_endpoint') }}</summary>
            <div class="mt-2 flex flex-col gap-2">
              <label for="vpn_portal_server_endpoint">{{ t('vpn_portal_server_endpoint') }}</label>
              <InputText id="vpn_portal_server_endpoint" v-model="endpointOverride"
                :placeholder="automaticEndpoint || 'vpn.example.com:22022'" />
              <small>{{ t('vpn_portal_endpoint_help') }}</small>
            </div>
          </details>
          <p v-if="!endpoint" class="text-sm text-amber-600">{{ t('vpn_portal_endpoint_required') }}</p>
          <template v-if="clientConfig">
            <p class="text-sm">{{ t('vpn_portal_scan_help') }}</p>
            <img v-if="qrCode" :src="qrCode" :alt="t('vpn_portal_qr_alt')" width="280" height="280"
              class="max-w-full self-center" />
            <p v-if="qrError" class="text-sm text-amber-600">{{ qrError }}</p>
            <div class="flex flex-wrap gap-2 justify-center">
              <Button icon="pi pi-download" :label="t('vpn_portal_download_config')" @click="downloadConfig" />
              <Button icon="pi pi-copy" severity="secondary"
                :label="copied ? t('config_copied') : t('vpn_portal_copy_client_config')" @click="copyConfig" />
            </div>
            <details>
              <summary class="cursor-pointer text-sm">{{ t('vpn_portal_show_config') }}</summary>
              <pre class="mt-2 overflow-x-auto whitespace-pre-wrap break-all rounded bg-surface-100 p-3 text-xs dark:bg-surface-800">{{ clientConfig }}</pre>
            </details>
          </template>
        </div>
      </template>
    </div>
  </Dialog>
</template>
