import { createApp, ref, h } from 'vue'
import PrimeVue from 'primevue/config'
import Aura from '@primeuix/themes/aura'
import HostsEditor from '../../frontend-lib/src/components/HostsEditor.vue'
import { I18nUtils } from 'easytier-frontend-lib'
import 'easytier-frontend-lib/style.css'
import './style.css'

const app = createApp({
  setup() {
    const hosts = ref<any[]>([])
    return () =>
      h('div', { style: 'max-width:860px;margin:40px auto;padding:0 16px;font-family:sans-serif;' }, [
        h('h2', 'Hosts Editor 本地预览'),
        h(HostsEditor, { hosts: hosts.value, 'onUpdate:hosts': (v: any[]) => (hosts.value = v) }),
        h('h3', { style: 'margin-top:24px;' }, '当前 hosts 值（JSON）'),
        h(
          'pre',
          { style: 'background:#f5f5f5;padding:12px;border-radius:8px;font-size:12px;font-family:monospace;' },
          JSON.stringify(hosts.value, null, 2),
        ),
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
