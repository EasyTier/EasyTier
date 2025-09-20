import './style.css'

import type { App } from 'vue';
import { Config, Status, ConfigEditDialog } from "./components";
import Aura from '@primeuix/themes/aura';
import PrimeVue from 'primevue/config'

import I18nUtils from './modules/i18n'
import * as NetworkTypes from './types/network'
import HumanEvent from './components/HumanEvent.vue';

// do not use primevue tooltip, it has serious memory leak issue
// https://github.com/primefaces/primevue/issues/5856
// import Tooltip from 'primevue/tooltip';
import { vTooltip } from 'floating-vue';

import * as Api from './modules/api';
import * as Utils from './modules/utils';

export default {
    install: (app: App): void => {
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
            zIndex: {
                modal: 1100,        //dialog, drawer
                overlay: 1200,      //select, popover
                menu: 1300,         //overlay menus
                tooltip: 1400       //tooltip
            }
        });

        app.component('Config', Config);
        app.component('ConfigEditDialog', ConfigEditDialog);
        app.component('Status', Status);
        app.component('HumanEvent', HumanEvent);
        app.directive('tooltip', vTooltip as any);
    }
};

export { Config, ConfigEditDialog, Status, I18nUtils, NetworkTypes, Api, Utils };
