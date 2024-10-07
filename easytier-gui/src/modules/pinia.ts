import piniaPluginPersistedstate from 'pinia-plugin-persistedstate'
import type { UseModule } from '~/types/modules'

export const install: UseModule = (app) => {
  const pinia = createPinia()
  pinia.use(piniaPluginPersistedstate)
  app.use(pinia)
}

export const index = 99
