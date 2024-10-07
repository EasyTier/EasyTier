<script setup lang="ts">
const { t } = useI18n()

const appStore = useAppStore()
const { appCloseConfirmDialogVisible } = storeToRefs(appStore)
</script>

<template>
  <Dialog v-model:open="appCloseConfirmDialogVisible">
    <DialogContent>
      <DialogHeader>
        <DialogTitle>{{ t('component.dialogList.appCloseConfirm.title') }}</DialogTitle>
        <DialogDescription class="pt-4">
          {{ t('component.dialogList.appCloseConfirm.content') }}
        </DialogDescription>
      </DialogHeader>
      <DialogFooter class="">
        <Button variant="outline" @click="tauriCloseWindow()">
          {{ t('component.dialogList.appCloseConfirm.confirm') }}
        </Button>
        <Button @click="tauriMinimizeWindow()">
          {{ t('component.dialogList.appCloseConfirm.minimize') }}
        </Button>
      </DialogFooter>
    </DialogContent>
  </Dialog>
</template>

<style scoped lang="postcss"></style>
