const { width } = useWindowSize()

export const platformIsMobile = computedAsync(
  async () => {
    if (isTauri) {
      const { platform } = await import('@tauri-apps/plugin-os')

      const currentPlatform = platform()
      return currentPlatform === 'android' || currentPlatform === 'ios'
    }
    return false
  },
  false,
)
export const isMobile = computed(() => platformIsMobile.value || width.value < 768)
