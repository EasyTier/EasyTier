<script setup lang="ts">
import { getCurrentWindow } from '@tauri-apps/api/window'
import pkg from '~/../package.json'

onBeforeMount(async () => {
  if (window.__TAURI_INTERNALS__) {
    await getCurrentWindow().setTitle(`Easytier GUI: v${pkg.version}`)
  }
})
</script>

<template>
  <Toast position="bottom-right" />
  <RouterView />
</template>
