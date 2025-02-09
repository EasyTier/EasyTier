<script setup lang="ts">
import { getCurrentWindow } from '@tauri-apps/api/window'
import pkg from '~/../package.json'

onBeforeMount(async () => {
  await getCurrentWindow().setTitle(`安防网控-v${pkg.version}`)
})
</script>

<template>
  <RouterView />
</template>
