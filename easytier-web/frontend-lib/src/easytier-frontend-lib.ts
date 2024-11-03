// import HelloWorld from './components/HelloWorld.vue'
// import Config from './components/Config.vue'
// import * as NetworkTypes from './types/network'

// export default {
//     HelloWorld,
//     Config,
//     ...NetworkTypes,
// }

import type { App } from 'vue';
import { Config } from "./components";
import Aura from '@primevue/themes/aura'
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'

import './style.css'
import 'primeicons/primeicons.css'
import 'primeflex/primeflex.css'

import I18nUtils from './modules/i18n'

export default {
    install: (app: App) => {
        app.use(I18nUtils.i18n, { useScope: 'global' })
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

        app.component('Config', Config);
    }
};

export { Config, I18nUtils };
