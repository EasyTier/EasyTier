import antfu from '@antfu/eslint-config'

export default antfu({
  formatters: true,
  ignores: [
    'src-tauri/**',
    'src/**.d.ts',
  ],
})
