import { InstallCodeMirror } from 'codemirror-editor-vue3'
import type { UseModule } from '~/types/modules'

export const install: UseModule = (app) => {
  app.use(InstallCodeMirror)
}
