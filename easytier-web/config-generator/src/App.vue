<script setup lang="ts">
import { exec, moduleInfo } from 'kernelsu'
import { Config, I18nUtils, NetworkTypes } from 'easytier-frontend-lib'
import { Button, SelectButton, Textarea } from 'primevue'
import { computed, onMounted, ref, watch } from 'vue'
import initConfigWasm, {
  generate_config as generateTomlConfig,
  parse_config as parseTomlConfig,
} from './generated/config-wasm/easytier_config'

type ModuleStatus = 'running' | 'stopped' | 'restarting'

interface KernelSuWindow extends Window {
  ksu?: unknown
}

interface ModuleInfo {
  moduleDir?: unknown
}

let configWasmReady: ReturnType<typeof initConfigWasm> | undefined

function ensureConfigWasm(): ReturnType<typeof initConfigWasm> {
  return configWasmReady ??= initConfigWasm()
}

const isModuleWebUi = typeof (window as KernelSuWindow).ksu !== 'undefined'
const moduleDirectory = ref('')
const moduleStatus = ref<ModuleStatus>()
const commandArgsMode = ref(false)
const moduleReady = ref(!isModuleWebUi)
const moduleMessage = ref('')
const isSaving = ref(false)
const networkConfig = ref<NetworkTypes.NetworkConfig>(NetworkTypes.DEFAULT_NETWORK_CONFIG())
const tomlConfig = ref('')
const errorMessage = ref('')
const configCopied = ref(false)
function t(key: string, params: Record<string, unknown> = {}): string {
  return I18nUtils.i18n.global.t(key, params)
}

function errorDetail(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}
const copyButtonLabel = computed(() => t(configCopied.value ? 'config_copied' : 'copy_config'))
const actionLabel = computed(() => t(isModuleWebUi ? 'magisk_save_restart' : 'generate_config'))
const configActionDisabled = computed(() =>
  isModuleWebUi && (!moduleReady.value || commandArgsMode.value || isSaving.value),
)
const moduleStatusLabel = computed(() => {
  if (!moduleStatus.value)
    return t('magisk_status_loading')
  return t(`magisk_status_${moduleStatus.value}`)
})
type Language = 'cn' | 'en'
const languageOptions: { label: string, value: Language }[] = [
  { label: '中文', value: 'cn' },
  { label: 'EN', value: 'en' },
]
const currentLanguage = computed(() => I18nUtils.i18n.global.locale.value as Language)

watch(tomlConfig, () => {
  configCopied.value = false
})

function moduleDirFromBridge(): string {
  const info = JSON.parse(moduleInfo()) as ModuleInfo
  const moduleDir = info.moduleDir
  if (typeof moduleDir !== 'string' || !/^\/data\/adb\/modules\/[\w.-]+$/.test(moduleDir))
    throw new Error(t('magisk_invalid_module_directory'))
  return moduleDir
}

async function runModuleCommand(command: string): Promise<string> {
  const { errno, stdout, stderr } = await exec(`./webui.sh ${command}`, {
    cwd: moduleDirectory.value,
  })
  if (errno !== 0)
    throw new Error(stderr.trim() || stdout.trim() || `webui.sh exited with ${errno}`)
  return stdout
}

function encodeBase64(value: string): string {
  const bytes = new TextEncoder().encode(value)
  const chunks: string[] = []
  const chunkSize = 0x8000
  for (let offset = 0; offset < bytes.length; offset += chunkSize)
    chunks.push(String.fromCharCode(...bytes.subarray(offset, offset + chunkSize)))
  return btoa(chunks.join(''))
}

async function refreshModuleState(waitForRunning = false): Promise<'running' | 'stopped'> {
  const attempts = waitForRunning ? 18 : 1
  for (let attempt = 0; attempt < attempts; attempt++) {
    const status = (await runModuleCommand('status')).trim()
    if (status === 'running') {
      moduleStatus.value = 'running'
      return 'running'
    }
    moduleStatus.value = 'stopped'
    if (attempt + 1 < attempts)
      await new Promise(resolve => setTimeout(resolve, 1000))
  }
  return 'stopped'
}

async function loadModuleConfig(): Promise<void> {
  moduleDirectory.value = moduleDirFromBridge()
  await ensureConfigWasm()

  const [rawConfig, mode] = await Promise.all([
    runModuleCommand('read-config'),
    runModuleCommand('config-mode'),
  ])
  await refreshModuleState()
  networkConfig.value = NetworkTypes.normalizeNetworkConfig(
    JSON.parse(parseTomlConfig(rawConfig)) as NetworkTypes.NetworkConfig,
  )
  tomlConfig.value = rawConfig
  commandArgsMode.value = mode.trim() === 'command-args'
  moduleReady.value = true
}

function preferredLanguage(): Language {
  const savedLanguage = localStorage.getItem('lang')
  if (savedLanguage === 'cn' || savedLanguage === 'en')
    return savedLanguage
  return navigator.language.toLowerCase().startsWith('zh') ? 'cn' : 'en'
}

async function initialize(): Promise<void> {
  await I18nUtils.loadLanguageAsync(preferredLanguage())

  if (!isModuleWebUi)
    return

  try {
    await loadModuleConfig()
  }
  catch (error) {
    errorMessage.value = t('magisk_load_failed', { error: errorDetail(error) })
  }
}

onMounted(initialize)

function setLanguage(language: Language): void {
  if (language !== currentLanguage.value)
    void I18nUtils.loadLanguageAsync(language)
}

async function generateConfig(config: NetworkTypes.NetworkConfig): Promise<void> {
  try {
    errorMessage.value = ''
    moduleMessage.value = ''
    configCopied.value = false
    isSaving.value = isModuleWebUi
    const configJson = JSON.stringify(NetworkTypes.toBackendNetworkConfig(config))
    await ensureConfigWasm()
    const generatedConfig = generateTomlConfig(configJson)
    tomlConfig.value = generatedConfig

    if (isModuleWebUi) {
      moduleStatus.value = 'restarting'
      await runModuleCommand(`save-and-restart ${encodeBase64(generatedConfig)}`)
      const status = await refreshModuleState(true)
      moduleMessage.value = t(
        status === 'running'
          ? 'magisk_config_saved'
          : 'magisk_config_saved_restart_pending',
      )
    }
  }
  catch (error) {
    const detail = errorDetail(error)
    errorMessage.value = isModuleWebUi
      ? t('magisk_save_failed', { error: detail })
      : `${t('config_generation_failed')}: ${detail}`
  }
  finally {
    isSaving.value = false
  }
}

async function copyConfig(): Promise<void> {
  try {
    errorMessage.value = ''
    configCopied.value = false
    await navigator.clipboard.writeText(tomlConfig.value)
    configCopied.value = true
  }
  catch (error) {
    errorMessage.value = `${t('config_copy_failed')}: ${errorDetail(error)}`
  }
}
</script>

<template>
  <main class="config-generator">
    <section v-if="isModuleWebUi" class="module-status">
      <div>
        <h1>{{ t('magisk_module_configuration') }}</h1>
        <p :class="['status', moduleStatus]">
          {{ moduleStatusLabel }}
        </p>
      </div>
      <p v-if="commandArgsMode" class="module-warning">
        {{ t('magisk_command_args_warning') }}
      </p>
      <p v-if="moduleMessage" class="module-success">
        {{ moduleMessage }}
      </p>
    </section>
    <section class="config-panel">
      <SelectButton
        class="language-switch"
        :model-value="currentLanguage"
        :options="languageOptions"
        option-label="label"
        option-value="value"
        size="small"
        :allow-empty="false"
        :aria-label="t('exchange_language')"
        @update:model-value="setLanguage"
      />
      <Config
        v-model:cur-network="networkConfig"
        :action-label="actionLabel"
        :config-invalid="configActionDisabled"
        @run-network="generateConfig"
      />
    </section>
    <section :class="['output-panel', { 'module-output-panel': isModuleWebUi }]">
      <pre v-if="errorMessage" class="error-message">{{ errorMessage }}</pre>
      <Textarea
        v-model="tomlConfig"
        spellcheck="false"
        class="toml-config"
        :placeholder="t('config_generator_placeholder')"
        :readonly="isModuleWebUi"
      />
      <Button :label="copyButtonLabel" icon="pi pi-copy" :disabled="!tomlConfig" @click="copyConfig" />
    </section>
  </main>
</template>

<style scoped>
.config-generator {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 2rem;
  padding: 1.25rem;
}

.module-status {
  grid-column: 1 / -1;
  display: flex;
  align-items: center;
  gap: 1rem;
  flex-wrap: wrap;
  padding: 0.875rem 1rem;
  border: 1px solid var(--p-content-border-color);
  border-radius: var(--p-border-radius-md);
  background: var(--p-content-background);
}

.module-status > div {
  display: flex;
  align-items: baseline;
  gap: 0.75rem;
}

.module-status h1 {
  margin: 0;
  font-size: 1.125rem;
}

.status {
  margin: 0;
  font-weight: 600;
}

.status.running {
  color: var(--p-green-500);
}

.status.stopped {
  color: var(--p-red-500);
}

.status.restarting {
  color: var(--p-orange-500);
}

.module-warning,
.module-success {
  flex-basis: 100%;
  margin: 0;
  padding: 0.75rem;
  border-radius: var(--p-border-radius-sm);
}

.module-warning {
  color: var(--p-orange-700);
  background: var(--p-orange-50);
}

.module-success {
  color: var(--p-green-700);
  background: var(--p-green-50);
}

.config-panel {
  position: relative;
}

.language-switch {
  position: absolute;
  z-index: 2;
  top: 0.4rem;
  right: 0.75rem;
}

.config-panel,
.output-panel {
  min-width: 0;
}

.output-panel {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  height: calc(100vh - 2.5rem);
  height: calc(100dvh - 2.5rem);
}

.module-output-panel {
  height: calc(100vh - 8rem);
  height: calc(100dvh - 8rem);
}

.toml-config {
  width: 100%;
  flex: 1;
  resize: none;
  font-family: monospace;
}

.error-message {
  max-height: 10rem;
  overflow: auto;
  padding: 0.5rem;
  color: #b91c1c;
  background: #fee2e2;
  border-radius: 0.25rem;
}

@media (max-width: 768px) {
  .config-generator {
    grid-template-columns: 1fr;
    gap: 1.25rem;
    padding: 0.75rem;
  }
}
</style>
