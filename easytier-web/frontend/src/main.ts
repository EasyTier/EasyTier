import { createApp } from 'vue'
import 'easytier-frontend-lib/style.css'
import './style.css'
import './console.css'
import App from './App.vue'
import EasytierFrontendLib from 'easytier-frontend-lib'
import PrimeVue from 'primevue/config'
import ConsoleTheme from './theme';
import { initThemeMode } from './modules/theme';
import ConfirmationService from 'primevue/confirmationservice';
import { I18nUtils } from 'easytier-frontend-lib'

import { createRouter, createWebHashHistory } from 'vue-router'
import MainPage from './components/MainPage.vue'
import Login from './components/Login.vue'
import DeviceList from './components/DeviceList.vue'
import DeviceManagement from './components/DeviceManagement.vue'
import Dashboard from './components/Dashboard.vue'
import NetworkList from './components/NetworkList.vue'
import NetworkDetail from './components/NetworkDetail.vue'
import DialogService from 'primevue/dialogservice';
import ToastService from 'primevue/toastservice';

const routes = [
    {
        path: '/auth', children: [
            {
                name: 'login',
                path: '',
                component: Login,
                alias: 'login',
                props: { isRegistering: false }
            },
            {
                name: 'register',
                path: 'register',
                component: Login,
                props: { isRegistering: true }
            }
        ]
    },
    {
        path: '/h', component: MainPage, children: [
            {
                path: '',
                alias: 'dashboard',
                name: 'dashboard',
                component: Dashboard,
            },
            {
                path: 'deviceList',
                name: 'deviceList',
                component: DeviceList,
                children: [
                    {
                        path: 'device/:deviceId/:instanceId?',
                        name: 'deviceManagement',
                        component: DeviceManagement,
                    }
                ]
            },
            {
                path: 'networks',
                name: 'networkList',
                component: NetworkList,
            },
            {
                path: 'networks/:networkId',
                name: 'networkDetail',
                component: NetworkDetail,
            },
        ]
    },
    {
        path: '/:pathMatch(.*)*', name: 'notFound', redirect: { name: 'dashboard' }
    }
]

const router = createRouter({
    history: createWebHashHistory(),
    routes,
})

const app = createApp(App)

// Use i18n
app.use(I18nUtils.i18n)
// Apply the Web-specific PrimeVue theme first; register the shared
// component library without its built-in theme so our dark mode selector
// is the only one that takes effect.
app.use(PrimeVue,
    {
        theme: {
            preset: ConsoleTheme,
            options: {
                prefix: 'p',
                darkModeSelector: '.app-dark',
                cssLayer: {
                    name: 'primevue',
                    order: 'tailwind-base, primevue, tailwind-utilities'
                }
            }
        }
    }
).use(ToastService as any).use(DialogService as any).use(router).use(ConfirmationService as any)

app.use(EasytierFrontendLib, { skipPrimeVue: true })

initThemeMode()
app.mount('#app')
