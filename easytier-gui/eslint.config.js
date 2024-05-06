// @ts-check
import antfu from '@antfu/eslint-config'

export default antfu({
  formatters: true,
  ignores: [
    'dist',
    'node_modules',
    'src-tauri',
    'src/vite-env.d.ts',
    'src/typed-router.d.ts',
    'src/auto-imports.d.ts',
    'src/components.d.ts',
  ],
})
