import 'primeflex/primeflex.css'
import 'primeicons/primeicons.css'
import './style.css'

import type { App } from 'vue';
import { Config } from "./components";
import Aura from '@primevue/themes/aura'
import PrimeVue from 'primevue/config'
import ToastService from 'primevue/toastservice'

import I18nUtils from './modules/i18n'
import * as NetworkTypes from './types/network'

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

export { Config, I18nUtils, NetworkTypes };
