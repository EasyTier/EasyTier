<script setup lang="ts">
import { createConfigWithNameConfig, createConfigWithNameSchema } from '~/composables/config'

const { t } = useI18n()

const instanceStore = useInstanceStore()

const appStore = useAppStore()
const { addInstanceDialogVisible } = storeToRefs(appStore)

function submitInstanceFromDefault(data: any) {
  instanceStore.addInstance(generateInstanceWithDefaultConfig(data.instance_name))
  addInstanceDialogVisible.value = false
}
</script>

<template>
  <Dialog v-model:open="addInstanceDialogVisible">
    <DialogContent class="h-auto w-2/3">
      <DialogHeader>
        <DialogTitle>{{ t('component.dialogList.addInstance.title') }}</DialogTitle>
        <DialogDescription class="items-center">
          <I18nT keypath="component.dialogList.addInstance.tips.from">
            <template #source>
              <Badge variant="secondary" class="mx-2">
                {{ t('component.dialogList.addInstance.defaultTemplate') }}
              </Badge>
            </template>
          </I18nT>
        </DialogDescription>
      </DialogHeader>
      <div class="grid gap-4 p-2 overflow-y-auto">
        <AutoForm
          :schema="createConfigWithNameSchema" :field-config="createConfigWithNameConfig" class="space-y-4"
          @submit="submitInstanceFromDefault"
        >
          <div class="w-full flex justify-end">
            <Button type="submit">
              {{ t('component.dialogList.addInstance.submit') }}
            </Button>
          </div>
        </AutoForm>
      </div>
    </DialogContent>
  </Dialog>
</template>

<style scoped lang="postcss"></style>
