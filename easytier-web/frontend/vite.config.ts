import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
// import { viteSingleFile } from "vite-plugin-singlefile"

const WEB_BASE_URL = process.env.WEB_BASE_URL || '';

// https://vite.dev/config/
export default defineConfig({
  base: WEB_BASE_URL,
  plugins: [vue(),/* viteSingleFile() */],
})
