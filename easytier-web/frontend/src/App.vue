<script setup lang="ts">

import { Config, I18nUtils, NetworkTypes } from 'easytier-frontend-lib'
import { onMounted, ref } from 'vue';

onMounted(async () => {
  await I18nUtils.loadLanguageAsync('cn')
});

const curNetwork = ref(NetworkTypes.DEFAULT_NETWORK_CONFIG())

const runNetwork = async () => {
  alert('runNetwork')
}

</script>

<template>
  <span class="text-3xl"> fuck </span>
  <Config v-model:curNetwork="curNetwork" v-on:runNetwork="runNetwork" />
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
