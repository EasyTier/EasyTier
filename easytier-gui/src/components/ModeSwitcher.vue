<script setup lang="ts">
import { computed, watch, onMounted, ref } from 'vue';
import type { Mode, ServiceMode, RemoteMode, NormalMode } from '~/composables/mode';
import { appConfigDir, appLogDir } from '@tauri-apps/api/path';
import { join } from '@tauri-apps/api/path';
import { getServiceStatus, type ServiceStatus } from '~/composables/backend';

const { t } = useI18n()

const model = defineModel<Mode>({ required: true })
const emit = defineEmits(['uninstall-service', 'stop-service'])

const defaultConfigDir = ref('')
const defaultLogDir = ref('')
const serviceStatus = ref<ServiceStatus>('NotInstalled')
const isServiceStatusLoaded = ref(false)

function normalizeRpcListenPort(port: unknown): number {
  const defaultPort = 15999
  const numericPort = typeof port === 'number' ? port : Number.parseInt(String(port ?? ''), 10)
  if (Number.isNaN(numericPort))
    return defaultPort
  return Math.min(65535, Math.max(1, Math.floor(numericPort)))
}

onMounted(async () => {
  defaultConfigDir.value = await join(await appConfigDir(), 'config.d')
  defaultLogDir.value = await appLogDir()
})

const modeOptions = computed(() => [
  { label: t('mode.normal'), value: 'normal' },
  { label: t('mode.service'), value: 'service' },
  { label: t('mode.remote'), value: 'remote' },
]);

const normalMode = computed({
  get: () => model.value.mode === 'normal' ? model.value as NormalMode : undefined,
  set: (value) => {
    if (value) {
      model.value = value
    }
  }
})

const rpcListenOptions = computed(() => [
  { label: t('common.disable'), value: false },
  { label: t('common.enable'), value: true },
])

const rpcListenEnabled = computed<boolean>({
  get: () => !!normalMode.value?.enable_rpc_port_listen,
  set: (value) => {
    if (!normalMode.value)
      return
    normalMode.value.enable_rpc_port_listen = value
  },
})

const rpcListenPort = computed<string>({
  get: () => String(normalMode.value?.rpc_listen_port ?? 15999),
  set: (value) => {
    if (!normalMode.value)
      return
    const trimmed = value.trim()
    if (trimmed === '')
      return
    if (!/^\d+$/.test(trimmed))
      return
    normalMode.value.rpc_listen_port = Number.parseInt(trimmed, 10)
  },
})

const serviceMode = computed({
  get: () => model.value.mode === 'service' ? model.value as ServiceMode : undefined,
  set: (value) => {
    if (value) {
      model.value = value
    }
  }
})

const remoteMode = computed({
  get: () => model.value.mode === 'remote' ? model.value as RemoteMode : undefined,
  set: (value) => {
    if (value) {
      model.value = value
    }
  }
})

const statusColorClass = computed(() => {
  switch (serviceStatus.value) {
    case 'Running':
      return 'text-green-600'
    case 'Stopped':
      return 'text-orange-600'
    case 'NotInstalled':
      return 'text-gray-600'
    default:
      return 'text-gray-600'
  }
})

watch(() => [normalMode.value?.enable_rpc_port_listen, normalMode.value?.rpc_listen_port], ([enabled, port]) => {
  if (!normalMode.value)
    return

  if (!enabled) {
    normalMode.value.rpc_portal = undefined
    return
  }

  const normalizedPort = normalizeRpcListenPort(port)
  if (normalMode.value.rpc_listen_port !== normalizedPort)
    normalMode.value.rpc_listen_port = normalizedPort

  const desiredPortal = `tcp://0.0.0.0:${normalizedPort}`
  if (normalMode.value.rpc_portal !== desiredPortal)
    normalMode.value.rpc_portal = desiredPortal
}, { immediate: true })

watch(() => model.value.mode, async (newMode, oldMode) => {
  if (newMode === oldMode)
    return

  if (newMode === 'service' && !isServiceStatusLoaded.value) {
    serviceStatus.value = await getServiceStatus()
    isServiceStatusLoaded.value = true
  }

  const oldModelValue = { ...model.value }

  if (newMode === 'normal') {
    const portal = normalMode.value?.rpc_portal?.trim()
    model.value = {
      ...oldModelValue,
      rpc_portal: portal,
      enable_rpc_port_listen: normalMode.value?.enable_rpc_port_listen,
      rpc_listen_port: normalMode.value?.rpc_listen_port,
      mode: 'normal',
    }
  }
  else if (newMode === 'service') {
    model.value = {
      ...oldModelValue,
      mode: 'service',
      config_dir: serviceMode.value?.config_dir || defaultConfigDir.value,
      rpc_portal: serviceMode.value?.rpc_portal || '127.0.0.1:15999',
      file_log_level: serviceMode.value?.file_log_level || 'off',
      file_log_dir: serviceMode.value?.file_log_dir || defaultLogDir.value,
    }
  }
  else if (newMode === 'remote') {
    model.value = {
      ...oldModelValue,
      mode: 'remote',
      remote_rpc_address: remoteMode.value?.remote_rpc_address || 'tcp://127.0.0.1:15999',
    }
  }
}, { immediate: true })

</script>

<template>
  <div class="flex flex-col gap-4">
    <div>
      <SelectButton id="mode-select" v-model="model.mode" :options="modeOptions" option-label="label"
        option-value="value" fluid />
    </div>

    <!-- Mode descriptions -->
    <div v-if="model.mode === 'normal'" class="text-sm text-gray-500">
      {{ t('mode.normal_description') }}
    </div>
    <div v-else-if="model.mode === 'service'" class="text-sm text-gray-500">
      {{ t('mode.service_description') }}
    </div>
    <div v-else-if="model.mode === 'remote'" class="text-sm text-gray-500">
      {{ t('mode.remote_description') }}
    </div>

    <div v-if="normalMode" class="flex flex-col gap-2">
      <div class="flex items-center gap-2">
        <label for="rpc-listen-toggle">{{ t('mode.enable_rpc_tcp_listen') }}</label>
        <SelectButton id="rpc-listen-toggle" v-model="rpcListenEnabled" :options="rpcListenOptions" option-label="label"
          option-value="value" />
      </div>
      <div v-if="rpcListenEnabled" class="flex flex-col gap-2">
        <div class="flex items-center gap-2">
          <label for="rpc-listen-port">{{ t('mode.rpc_listen_port') }}</label>
          <InputText id="rpc-listen-port" v-model="rpcListenPort" class="flex-1" inputmode="numeric" />
        </div>
      </div>
    </div>

    <div v-if="serviceMode" class="flex flex-col gap-2">
      <div class="flex items-center gap-2">
        <label for="config-dir">{{ t('mode.config_dir') }}</label>
        <InputText id="config-dir" v-model="serviceMode.config_dir" class="flex-1" />
      </div>
      <div class="flex items-center gap-2">
        <label for="rpc-portal">{{ t('mode.rpc_portal') }}</label>
        <InputText id="rpc-portal" v-model="serviceMode.rpc_portal" class="flex-1" />
      </div>
      <div class="flex items-center gap-2">
        <label for="log-level">{{ t('mode.log_level') }}</label>
        <Select id="log-level" v-model="serviceMode.file_log_level"
          :options="['off', 'warn', 'info', 'debug', 'trace']" />
      </div>
      <div class="flex items-center gap-2">
        <label for="log-dir">{{ t('mode.log_dir') }}</label>
        <InputText id="log-dir" v-model="serviceMode.file_log_dir" class="flex-1" />
      </div>
      <div class="flex items-center gap-2 justify-between">
        <div class="flex items-center gap-2">
          <label>{{ t('mode.service_status') }}</label>
          <span :class="statusColorClass">{{ t(`mode.service_status_${serviceStatus.toLowerCase()}`) }}</span>
        </div>
        <div class="flex items-center gap-2">
          <Button :label="t('mode.stop_service')" icon="pi pi-stop-circle" v-if="serviceStatus === 'Running'"
            @click="emit('stop-service')" severity="warn" text />
          <Button :label="t('mode.uninstall_service')" icon="pi pi-trash" v-if="serviceStatus !== 'NotInstalled'"
            @click="emit('uninstall-service')" severity="danger" text />
        </div>
      </div>
    </div>

    <div v-if="remoteMode" class="flex flex-col gap-2">
      <div class="flex items-center gap-2">
        <label for="remote-addr">{{ t('mode.remote_rpc_address') }}</label>
        <InputText id="remote-addr" v-model="remoteMode.remote_rpc_address" class="flex-1" />
      </div>
    </div>
  </div>
</template>
