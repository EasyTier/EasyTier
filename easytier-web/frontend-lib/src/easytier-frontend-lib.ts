import './style.css'

import type { App } from 'vue';
import { Config, Status } from "./components";
import Aura from '@primevue/themes/aura'
import PrimeVue from 'primevue/config'

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
                    cssLayer: {
                        name: 'primevue',
                        order: 'tailwind-base, primevue, tailwind-utilities'
                    }
                },
            },
        });

        app.component('Config', Config);
        app.component('Status', Status);
    }
};

export { Config, Status, I18nUtils, NetworkTypes };
