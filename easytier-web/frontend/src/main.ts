import { createApp } from 'vue'
import './style.css'
import 'easytier-frontend-lib/style.css'
import App from './App.vue'
import EasytierFrontendLib from 'easytier-frontend-lib'
import PrimeVue from 'primevue/config'

createApp(App).use(PrimeVue).use(EasytierFrontendLib).mount('#app')
