import { createApp } from 'vue'
import './style.css'
import App from './App.vue'
import EasytierFrontendLib from 'easytier-frontend-lib'

import 'easytier-frontend-lib/style.css'

createApp(App).use(EasytierFrontendLib).mount('#app')
