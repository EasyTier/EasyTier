<script setup lang="ts">
import { getEasytierVersion } from '~/composables/network'

const { t } = useI18n()

const etVersion = ref('')

onMounted(async () => {
  etVersion.value = await getEasytierVersion()
})
</script>

<template>
  <Card>
    <template #title>
      Easytier - {{ t('about.version') }}: {{ etVersion }}
    </template>
    <template #content>
      <p class="mb-1">
        {{ t('about.description') }}
      </p>
    </template>
  </Card>
</template>

<style scoped lang="postcss">
</style>
