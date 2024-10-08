<script setup lang="ts">
import { Plus, Search } from 'lucide-vue-next'

const props = defineProps<{
  modelValue: string
}>()
const emits = defineEmits<{
  'update:modelValue': [value: string]
}>()
const { t } = useI18n()

const modelValue = useVModel(props, 'modelValue', emits, {
  passive: true,
  defaultValue: props.modelValue,
})

const appStore = useAppStore()
</script>

<template>
  <div class="bg-background/95 supports-[backdrop-filter]:bg-background/60 p-2 backdrop-blur">
    <div class="flex w-full items-center gap-1.5 relative">
      <Search class="text-muted-foreground absolute left-2 top-2.5 size-4" />
      <Input v-model="modelValue" :placeholder="t('page.index.search')" class="pl-8" />
      <Button variant="outline" size="icon" @click="appStore.setAddInstanceDialogVisible(true)">
        <Plus class="w-4 h-4" />
      </Button>
    </div>
  </div>
</template>

<style scoped lang="postcss"></style>
