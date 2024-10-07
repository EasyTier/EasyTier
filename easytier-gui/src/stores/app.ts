export const useAppStore = defineStore('appStore', () => {
  const addInstanceDialogVisible = ref(false)
  const addInstanceFromFileDrawerVisible = ref(false)

  const appCloseConfirmDialogVisible = ref(false)
  const appAutostartDialogVisible = ref(false)

  const autostart = ref<{
    id: string
    start: boolean
  }>({
    id: '',
    start: false,
  })

  const logLevel = ref<'off' | 'warn' | 'info' | 'debug' | 'trace'>('off')

  watch(
    logLevel,
    async (level) => {
      await setLogLevel(level)
    },
    { deep: true },
  )

  return {
    addInstanceDialogVisible,
    addInstanceFromFileDrawerVisible,
    appCloseConfirmDialogVisible,
    appAutostartDialogVisible,

    autostart,
    logLevel,

    setAddInstanceDialogVisible(visible: boolean) {
      addInstanceDialogVisible.value = visible
    },
    setAddInstanceFromFileDrawerVisible(visible: boolean) {
      addInstanceFromFileDrawerVisible.value = visible
    },
    hideAllDialog() {
      appCloseConfirmDialogVisible.value = false
      addInstanceDialogVisible.value = false
      appAutostartDialogVisible.value = false
    },
    setAppCloseConfirmDialogVisible(visible: boolean) {
      appCloseConfirmDialogVisible.value = visible
    },
    setAppAutostartDialogVisible(visible: boolean) {
      appAutostartDialogVisible.value = visible
    },
    setAutostart(value: boolean) {
      autostart.value.start = value
    },
    addAutostartId(id: string = '') {
      autostart.value.id = id
    },
  }
}, {
  persist: true,
})

if (import.meta.hot)
  import.meta.hot.accept(acceptHMRUpdate(useAppStore, import.meta.hot))
