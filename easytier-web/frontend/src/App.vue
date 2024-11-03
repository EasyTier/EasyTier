<script setup lang="ts">
import { HelloWorld, Config } from 'easytier-frontend-lib'
</script>

<template>
  <span class="text-3xl"> fuck </span>
  <HelloWorld msg="Vite + Vue" />
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
