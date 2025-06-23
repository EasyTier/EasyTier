import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import ViteYaml from '@modyfi/vite-plugin-yaml'
// import { viteSingleFile } from "vite-plugin-singlefile"

const WEB_BASE_URL = process.env.WEB_BASE_URL || '';
const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:11211';

// https://vite.dev/config/
export default defineConfig({
  base: WEB_BASE_URL,
  plugins: [vue(), ViteYaml(),/* viteSingleFile() */],
  server: {
    proxy: {
      "/api": {
        target: API_BASE_URL,
      },
      "/api_meta.js": {
        target: API_BASE_URL,
      },
    }
  }
})
