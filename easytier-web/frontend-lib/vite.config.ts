import { resolve } from 'path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import dts from "vite-plugin-dts"

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue(), dts({
    tsconfigPath: './tsconfig.app.json',
  }),],
  build: {
    lib: {
      // Could also be a dictionary or array of multiple entry points
      entry: resolve(__dirname, 'src/index.ts'),
      name: 'easytier-frontend-lib',
      // the proper extensions will be added
      fileName: 'easytier-frontend-lib',
      formats: ["es", "umd", "cjs"],
    },
    rollupOptions: {
      input: {
        main: resolve(__dirname, "src/easytier-frontend-lib.ts")
      },
      // make sure to externalize deps that shouldn't be bundled
      // into your library
      external: ['vue'],
      output: {
        // Provide global variables to use in the UMD build
        // for externalized deps
        globals: {
          vue: 'Vue',
        },
        exports: "named"
      },
    },
  },
})
