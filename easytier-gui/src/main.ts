import { setupLayouts } from 'virtual:generated-layouts'
import { createRouter, createWebHistory } from 'vue-router/auto'

import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'
import App from '~/App.vue'

import '~/styles.css'
import 'primevue/resources/themes/aura-light-green/theme.css'
import 'primeicons/primeicons.css'
import 'primeflex/primeflex.css'
import { i18n, loadLanguageAsync } from '~/modules/i18n'

if (import.meta.env.PROD) {
  document.addEventListener('keydown', (event) => {
    if (
      event.key === 'F5'
      || (event.ctrlKey && event.key === 'r')
      || (event.metaKey && event.key === 'r')
    )
      event.preventDefault()
  })

  document.addEventListener('contextmenu', (event) => {
    event.preventDefault()
  })
}

async function main() {
  await loadLanguageAsync(localStorage.getItem('lang') || 'en')

  const app = createApp(App)

  const router = createRouter({
    history: createWebHistory(),
    extendRoutes: routes => setupLayouts(routes),
  })

  app.use(router)
  app.use(createPinia())
  app.use(i18n, { useScope: 'global' })
  app.use(PrimeVue)
  app.use(ToastService)
  app.mount('#app')
}

main()
