import { createApp } from 'vue'
import './style.css'
import 'easytier-frontend-lib/style.css'
import App from './App.vue'
import EasytierFrontendLib from 'easytier-frontend-lib'
import PrimeVue from 'primevue/config'
import Aura from '@primevue/themes/aura'
import ConfirmationService from 'primevue/confirmationservice';

createApp(App).use(PrimeVue,
    {
        theme: {
            preset: Aura,
            options: {
                prefix: 'p',
                darkModeSelector: 'system',
                cssLayer: {
                    name: 'primevue',
                    order: 'tailwind-base, primevue, tailwind-utilities'
                }
            }
        }
    }
).use(ConfirmationService).use(EasytierFrontendLib).mount('#app')
