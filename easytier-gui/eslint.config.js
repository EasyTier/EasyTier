// @ts-check
import antfu from '@antfu/eslint-config'

export default antfu({
  formatters: true,
  rules: {
    'style/eol-last': ['error', 'always'],
  },
  ignores: [
    'src-tauri/**',
  ],
})
