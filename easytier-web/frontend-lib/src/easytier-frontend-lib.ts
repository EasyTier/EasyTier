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

export default {
    install: (app: App) => {
        app.component('HelloWorld', HelloWorld);
        app.component('HelloWorld', Config);
    }
};

export { HelloWorld, Config };
