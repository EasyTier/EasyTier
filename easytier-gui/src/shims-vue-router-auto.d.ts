/// <reference types="unplugin-vue-router/client" />

declare module 'vue-router/auto' {
  export * from 'unplugin-vue-router';
  export { default } from 'unplugin-vue-router';
}

declare module 'vue-router/auto-routes' {
  export * from 'unplugin-vue-router/routes';
  export { default } from 'unplugin-vue-router/routes';
}
