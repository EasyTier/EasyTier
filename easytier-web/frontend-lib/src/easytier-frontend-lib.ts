// import HelloWorld from './components/HelloWorld.vue'
// import Config from './components/Config.vue'
// import * as NetworkTypes from './types/network'

// export default {
//     HelloWorld,
//     Config,
//     ...NetworkTypes,
// }

import type { App } from 'vue';
import { HelloWorld, Config } from "./components";
import { createI18n } from 'vue-i18n';
import Aura from '@primevue/themes/aura'
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'

import './style.css'
import 'primeicons/primeicons.css'
import 'primeflex/primeflex.css'

export const i18n = createI18n({
    legacy: false,
    locale: '',
    fallbackLocale: '',
    messages: {},
})

export default {
    install: (app: App) => {
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
        });
        app.use(ToastService);

        app.component('HelloWorld', HelloWorld);
        app.component('Config', Config);
    }
};

export { HelloWorld, Config };
