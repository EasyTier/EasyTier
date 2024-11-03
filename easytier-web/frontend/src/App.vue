<script setup lang="ts">

import { Config, I18nUtils } from 'easytier-frontend-lib'
import { onMounted } from 'vue';

onMounted(async () => {
  await I18nUtils.loadLanguageAsync('cn')
});

</script>

<template>
  <span class="text-3xl"> fuck </span>
  <Config />
</template>

<style scoped>
.logo {
  height: 6em;
  padding: 1.5em;
  will-change: filter;
  transition: filter 300ms;
}

.logo:hover {
  filter: drop-shadow(0 0 2em #646cffaa);
}

.logo.vue:hover {
  filter: drop-shadow(0 0 2em #42b883aa);
}
</style>
