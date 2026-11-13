import { createApp } from 'vue'
import Aura from '@primeuix/themes/aura'
import EasytierFrontendLib from 'easytier-frontend-lib'
import 'easytier-frontend-lib/style.css'
import PrimeVue from 'primevue/config'
import App from './App.vue'

createApp(App)
  .use(PrimeVue, {
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
  .use(EasytierFrontendLib)
  .mount('#app')
