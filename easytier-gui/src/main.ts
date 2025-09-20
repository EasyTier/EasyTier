import Aura from '@primeuix/themes/aura';
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'

import { createRouter, createWebHistory } from 'vue-router/auto'
import { routes } from 'vue-router/auto-routes'
import App from '~/App.vue'
import EasyTierFrontendLib, { I18nUtils } from 'easytier-frontend-lib'

import { getAutoLaunchStatusAsync, loadAutoLaunchStatusAsync } from './modules/auto_launch'
import '~/styles.css'
import 'easytier-frontend-lib/style.css'

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
  await I18nUtils.loadLanguageAsync(localStorage.getItem('lang') || 'en')
  await loadAutoLaunchStatusAsync(getAutoLaunchStatusAsync())

  const app = createApp(App)

  const router = createRouter({
    history: createWebHistory(),
    routes,
  })

  app.use(router)
  app.use(createPinia())
  app.use(EasyTierFrontendLib)
  // app.use(i18n, { useScope: 'global' })
  app.use(PrimeVue, {
    theme: {
      preset: Aura,
      options: {
        prefix: 'p',
        darkModeSelector: 'system',
        cssLayer: {
          name: 'primevue',
          order: 'tailwind-base, primevue, tailwind-utilities',
        },
      },
    },
  })
  app.use(ToastService as any)
  app.mount('#app')
}

main()
