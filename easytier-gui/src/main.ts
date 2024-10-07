import App from '~/App.vue'
import { loadModules } from '~/modules'
import '~/styles/index.css'

const app = createApp(App)

loadModules(app).mount('#app')
