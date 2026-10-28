import './style.css'

import type { App } from 'vue';
import { Config, Status, ConfigEditDialog, RemoteManagement, UrlListInput } from "./components";
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

export interface FrontendLibOptions {
    /// Skip the built-in PrimeVue theme config so the host app can install
    /// its own (e.g. a class-based dark mode selector). The host must
    /// install PrimeVue itself when this is set.
    skipPrimeVue?: boolean;
}

const EasytierFrontendLib: { install: (app: App, options?: FrontendLibOptions) => void } = {
    install: (app: App, options: FrontendLibOptions = {}): void => {
        app.use(I18nUtils.i18n, { useScope: 'global' })
        if (!options.skipPrimeVue) {
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

            // The built-in theme keys PrimeVue dark mode off the OS, while the
            // lib's tailwind dark: utilities key off the .app-dark class. Keep
            // the class in sync with the OS so both mechanisms stay consistent
            // for hosts using the default theme.
            const colorScheme = window.matchMedia('(prefers-color-scheme: dark)');
            const applyOsColorScheme = () => {
                document.documentElement.classList.toggle('app-dark', colorScheme.matches);
            };
            applyOsColorScheme();
            colorScheme.addEventListener('change', applyOsColorScheme);
        }

        app.component('Config', Config);
        app.component('ConfigEditDialog', ConfigEditDialog);
        app.component('Status', Status);
        app.component('HumanEvent', HumanEvent);
        app.component('RemoteManagement', RemoteManagement);
        app.directive('tooltip', vTooltip as any);
    }
};

export default EasytierFrontendLib;

export { Config, ConfigEditDialog, RemoteManagement, Status, UrlListInput, I18nUtils, NetworkTypes, Api, Utils };
