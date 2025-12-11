<script setup lang="ts">
import { I18nUtils } from 'easytier-frontend-lib'
import { onMounted } from 'vue';
import { Toast, DynamicDialog } from 'primevue';

onMounted(async () => {
  await I18nUtils.loadLanguageAsync(localStorage.getItem('lang') || 'en')
});

</script>

<!-- https://flowbite.com/docs/components/sidebar/#sidebar-with-navbar -->

<template>
  <div id="app-shell">
    <Toast id="app-toast" position="bottom-right" />
    <DynamicDialog id="app-dialog-root" />
    <RouterView id="app-router-view" />
  </div>
</template>

<style scoped>
button {
  text-align: left;
  justify-content: left;
}
</style>
