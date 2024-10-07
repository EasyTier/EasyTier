<script setup lang="ts">
import { useToast } from '~/components/ui/toast/use-toast'

const { toast } = useToast()
const { t } = useI18n()
const appStore = useAppStore()
const { logLevel } = storeToRefs(appStore)
onBeforeMount(async () => {
  await listen()
  appStore.hideAllDialog()
  try {
    await checkAutostart()
  }
  catch (e) {
    toast({
      title: t('toast.error.operateInstance'),
      variant: 'destructive',
      description: h('div', { class: 'whitespace-pre-wrap', innerHTML: e }),
    })
  }

  await initMobileVpnService()
  await setLogLevel(logLevel.value)
  setTimeout(async () => {
    await setTrayMenu()
  }, 1000)
})

onUnmounted(async () => {
  await unlisten()
})
</script>

<template>
  <TooltipProvider :delay-duration="150">
    <div vaul-drawer-wrapper class="h-full">
      <RouterView />
    </div>
  </TooltipProvider>
  <Toaster />
  <DialogList />
  <DrawerList v-if="false" />
</template>
