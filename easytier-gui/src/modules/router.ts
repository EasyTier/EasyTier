import { setupLayouts } from 'virtual:generated-layouts'
import { createRouter, createWebHistory } from 'vue-router/auto'
import { routes } from 'vue-router/auto-routes'
import type { UseModule } from '~/types/modules'

export const install: UseModule = (app) => {
  const router = createRouter({
    history: createWebHistory(),
    routes: setupLayouts(routes),
  })

  router.beforeEach((_to, _from, next) => {
    next()
  })
  app.use(router)
}
