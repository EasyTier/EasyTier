<script setup lang="ts">
import { Config, I18nUtils, NetworkTypes } from 'easytier-frontend-lib'
import { Button, SelectButton, Textarea } from 'primevue'
import { computed, onMounted, ref, watch } from 'vue'
import initConfigWasm, {
  generate_config as generateTomlConfig,
} from './generated/config-wasm/easytier_config'

let configWasmReady: ReturnType<typeof initConfigWasm> | undefined
const ensureConfigWasm = () => configWasmReady ??= initConfigWasm()

const networkConfig = ref<NetworkTypes.NetworkConfig>(NetworkTypes.DEFAULT_NETWORK_CONFIG())
const tomlConfig = ref('')
const errorMessage = ref('')
const configCopied = ref(false)
const t = (key: string) => I18nUtils.i18n.global.t(key)
const copyButtonLabel = computed(() => t(configCopied.value ? 'config_copied' : 'copy_config'))
type Language = 'cn' | 'en'
const languageOptions: { label: string, value: Language }[] = [
  { label: '中文', value: 'cn' },
  { label: 'EN', value: 'en' },
]
const currentLanguage = computed(() => I18nUtils.i18n.global.locale.value as Language)

watch(tomlConfig, () => {
  configCopied.value = false
})

onMounted(async () => {
  const savedLanguage = localStorage.getItem('lang')
  const language = savedLanguage === 'cn' || savedLanguage === 'en'
    ? savedLanguage
    : navigator.language.toLowerCase().startsWith('zh') ? 'cn' : 'en'
  await I18nUtils.loadLanguageAsync(language)
})

const setLanguage = (language: Language) => {
  if (language !== currentLanguage.value) {
    void I18nUtils.loadLanguageAsync(language)
  }
}

const generateConfig = async (config: NetworkTypes.NetworkConfig) => {
  try {
    errorMessage.value = ''
    tomlConfig.value = ''
    const configJson = JSON.stringify(NetworkTypes.toBackendNetworkConfig(config))
    await ensureConfigWasm()
    tomlConfig.value = generateTomlConfig(configJson)
  } catch (error) {
    errorMessage.value = t('config_generation_failed') + ': ' + (error instanceof Error ? error.message : String(error))
  }
}

const copyConfig = async () => {
  try {
    errorMessage.value = ''
    configCopied.value = false
    await navigator.clipboard.writeText(tomlConfig.value)
    configCopied.value = true
  } catch (error) {
    errorMessage.value = t('config_copy_failed') + ': ' + (error instanceof Error ? error.message : String(error))
  }
}
</script>

<template>
  <main class="config-generator">
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
      <Config :cur-network="networkConfig" :action-label="t('generate_config')" @run-network="generateConfig" />
    </section>
    <section class="output-panel">
      <pre v-if="errorMessage" class="error-message">{{ errorMessage }}</pre>
      <Textarea
        v-model="tomlConfig"
        spellcheck="false"
        class="toml-config"
        :placeholder="t('config_generator_placeholder')"
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
