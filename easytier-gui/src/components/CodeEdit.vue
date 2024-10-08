<script setup lang="ts">
import type { EditorConfiguration } from 'codemirror'
import type { CmComponentRef } from 'codemirror-editor-vue3'
// import { yaml } from '@codemirror/lang-yaml'
// import { oneDark } from '@codemirror/theme-one-dark'
import CodeMirror from 'codemirror-editor-vue3'
// import CodeMirror from 'vue-codemirror6'
import 'codemirror/mode/toml/toml.js'
import 'codemirror/theme/ayu-dark.css'
import '~/styles/codeMirror.css'

const props = defineProps<{
  modelValue: string
}>()
const emits = defineEmits<{
  'update:modelValue': [value: string]
}>()
const tRefresh = ref<NodeJS.Timeout | null>()

const modelValue = useVModel(props, 'modelValue', emits, {
  passive: true,
  defaultValue: props.modelValue,
})

const cmRef = ref<CmComponentRef>()
const cmOptions: EditorConfiguration = {
  mode: 'text/x-toml',
  theme: 'easytier-dark',
  lineWrapping: true,
}

onMounted(() => {
  tRefresh.value = setTimeout(() => {
    cmRef.value?.refresh()
  }, 100)
})

onUnmounted(() => {
  if (tRefresh.value)
    clearTimeout(tRefresh.value)
  cmRef.value?.destroy()
})
</script>

<template>
  <CodeMirror ref="cmRef" v-model:value="modelValue" :options="cmOptions" class="border rounded-md flex-1" />
  <!-- <CodeMirror
    v-model="code"
    basic
    :lang="yaml()"
    :extensions="[oneDark]"
  /> -->
</template>

<style lang="postcss" scoped></style>
