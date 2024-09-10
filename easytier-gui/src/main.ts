import Aura from '@primevue/themes/aura'
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'

import { createRouter, createWebHistory } from 'vue-router/auto'
import { routes } from 'vue-router/auto-routes'
import App from '~/App.vue'
import { i18n, loadLanguageAsync } from '~/modules/i18n'

import { getAutoLaunchStatusAsync, loadAutoLaunchStatusAsync } from './modules/auto_launch'
import '~/styles.css'
import 'primeicons/primeicons.css'
import 'primeflex/primeflex.css'

if (import.meta.env.PROD) {
  document.addEventListener('keydown', (event) => {
    if (
      event.key === 'F5'
      || (event.ctrlKey && event.key === 'r')
      || (event.metaKey && event.key === 'r')
    ) {
      event.preventDefault()
    }
  })

  document.addEventListener('contextmenu', (event) => {
    event.preventDefault()
  })
}

async function main() {
  await loadLanguageAsync(localStorage.getItem('lang') || 'en')
  await loadAutoLaunchStatusAsync(getAutoLaunchStatusAsync())

  const app = createApp(App)

  const router = createRouter({
    history: createWebHistory(),
    routes,
  })

  app.use(router)
  app.use(createPinia())
  app.use(i18n, { useScope: 'global' })
  app.use(PrimeVue, {
    theme: {
      preset: Aura,
      options: {
        prefix: 'p',
        darkModeSelector: 'system',
        cssLayer: false,
      },
    },
  })
  app.use(ToastService)
  app.mount('#app')
}

main()
