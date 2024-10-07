<script setup lang="ts">
import { FileInput } from 'lucide-vue-next'

const { t } = useI18n()
const appStore = useAppStore()
const { addInstanceFromFileDrawerVisible } = storeToRefs(appStore)
</script>

<template>
  <Drawer
    v-if="!platformIsMobile" v-model:open="addInstanceFromFileDrawerVisible"
    :should-scale-background="!platformIsMobile"
  >
    <DrawerContent class="w-full h-full bg-transparent backdrop-blur-sm outline-0 p-6 pt-0">
      <div class="mt-4 w-full h-full rounded-lg border-dashed border-4 flex space-x-4 items-center justify-center">
        <FileInput class="w-8 h-8" />
        <span>{{ t('component.drawerList.dropFile.title') }}</span>
      </div>
    </DrawerContent>
  </Drawer>
</template>

<style scoped lang="postcss">
</style>
