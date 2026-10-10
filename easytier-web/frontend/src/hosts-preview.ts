import { createApp, ref, h } from 'vue'
import PrimeVue from 'primevue/config'
import Aura from '@primeuix/themes/aura'
import Config from '../../frontend-lib/src/components/Config.vue'
import { I18nUtils } from 'easytier-frontend-lib'
import { DEFAULT_NETWORK_CONFIG } from '../../frontend-lib/src/types/network'
import 'easytier-frontend-lib/style.css'
import './style.css'

const app = createApp({
  setup() {
    const curNetwork = ref<any>({ ...DEFAULT_NETWORK_CONFIG })
    return () =>
      h('div', { style: 'max-width:1100px;margin:24px auto;padding:0 16px;font-family:sans-serif;' }, [
        h(Config, {
          curNetwork: curNetwork.value,
          'onUpdate:curNetwork': (v: any) => (curNetwork.value = v),
          actionLabel: '运行网络',
          configInvalid: false,
        }),
      ])
  },
})

app.use(PrimeVue, {
  theme: {
    preset: Aura,
    options: {
      prefix: 'p',
      darkModeSelector: 'system',
      cssLayer: {
        name: 'primevue',
        order: 'tailwind-base, primevue, tailwind-utilities',
      },
    },
  },
})
app.use(I18nUtils.i18n, { useScope: 'global' })
app.mount('#app')
