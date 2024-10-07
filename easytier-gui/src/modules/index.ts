import type { App } from 'vue'
import type { UseModule } from '~/types/modules'

export function loadModules(app: App<Element>): App<Element> {
  Object.values(import.meta.glob<{ install: UseModule, index?: number }>('~/modules/*.ts', { eager: true })).sort((a, b) => (b.index || 0) - (a.index || 0)).forEach(async i => i.install?.(app))
  return app
}
