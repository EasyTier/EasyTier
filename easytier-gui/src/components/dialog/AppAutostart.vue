<script setup lang="ts">
const { t } = useI18n()

const appStore = useAppStore()
const { appAutostartDialogVisible, autostart } = storeToRefs(appStore)
const instanceStore = useInstanceStore()
const { instances } = storeToRefs(instanceStore)

function toggleAutostart(payload: boolean) {
  appStore.setAutostart(payload)
}
</script>

<template>
  <Dialog v-model:open="appAutostartDialogVisible">
    <DialogContent class="h-auto w-2/3">
      <DialogHeader>
        <DialogTitle>{{ t('component.dialogList.appAutostart.title') }}</DialogTitle>
        <DialogDescription class="pt-4">
          <div class="space-y-4">
            <div class="flex items-center space-x-2">
              <Switch :checked="autostart.start" @update:checked="toggleAutostart" />
              <Label>{{ t('component.dialogList.appAutostart.switch') }}</Label>
            </div>
            <Select v-model="autostart.id">
              <SelectTrigger>
                <SelectValue :placeholder="t('component.dialogList.appAutostart.selectPlaceholder')" />
              </SelectTrigger>
              <SelectContent>
                <SelectGroup>
                  <SelectItem value="''">
                    不自动启用实例
                  </SelectItem>
                  <SelectLabel>{{ t('component.dialogList.appAutostart.instance') }}</SelectLabel>
                  <SelectItem v-for="instance in instances" :key="instance.id" :value="instance.id">
                    {{ instance.name }}
                  </SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>
          </div>
        </DialogDescription>
      </DialogHeader>
    </DialogContent>
  </Dialog>
</template>

<style scoped lang="postcss"></style>
