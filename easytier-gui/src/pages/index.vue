<script setup lang="ts">

import { type } from '@tauri-apps/plugin-os'

import { appLogDir } from '@tauri-apps/api/path'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { exit } from '@tauri-apps/plugin-process'
import { I18nUtils, RemoteManagement } from "easytier-frontend-lib"
import type { MenuItem } from 'primevue/menuitem'
import { useTray } from '~/composables/tray'
import { GUIRemoteClient } from '~/modules/api'
import { getAutoLaunchStatusAsync as getAutoLaunchStatus, loadAutoLaunchStatusAsync } from '~/modules/auto_launch'
import { getDockVisibilityStatus, loadDockVisibilityAsync } from '~/modules/dock_visibility'

const { t, locale } = useI18n()
const aboutVisible = ref(false)

useTray(true)

const remoteClient = computed(() => new GUIRemoteClient());
const instanceId = ref<string | undefined>(undefined);

onMounted(async () => {
  window.setTimeout(async () => {
    await setTrayMenu([
      await MenuItemShow(t('tray.show')),
      await MenuItemExit(t('tray.exit')),
    ])
  }, 1000)
})

let current_log_level = 'off'

const log_menu = ref()
const log_menu_items_popup: Ref<MenuItem[]> = ref([
  ...['off', 'warn', 'info', 'debug', 'trace'].map(level => ({
    label: () => t(`logging_level_${level}`) + (current_log_level === level ? ' ✓' : ''),
    command: async () => {
      current_log_level = level
      await setLoggingLevel(level)
    },
  })),
  {
    separator: true,
  },
  {
    label: () => t('logging_open_dir'),
    icon: 'pi pi-folder-open',
    command: async () => {
      // console.log('open log dir', await appLogDir())
      await open(await appLogDir())
    },
  },
  {
    label: () => t('logging_copy_dir'),
    icon: 'pi pi-tablet',
    command: async () => {
      await writeText(await appLogDir())
    },
  },
])

function toggle_log_menu(event: any) {
  log_menu.value.toggle(event)
}

function getLabel(item: MenuItem) {
  return typeof item.label === 'function' ? item.label() : item.label
}

const setting_menu_items: Ref<MenuItem[]> = ref([
  {
    label: () => t('exchange_language'),
    icon: 'pi pi-language',
    command: async () => {
      await I18nUtils.loadLanguageAsync((locale.value === 'en' ? 'cn' : 'en'))
      await setTrayMenu([
        await MenuItemShow(t('tray.show')),
        await MenuItemExit(t('tray.exit')),
      ])
    },
  },
  {
    label: () => getAutoLaunchStatus() ? t('disable_auto_launch') : t('enable_auto_launch'),
    icon: 'pi pi-desktop',
    command: async () => {
      await loadAutoLaunchStatusAsync(!getAutoLaunchStatus())
    },
  },
  {
    label: () => getDockVisibilityStatus() ? t('hide_dock_icon') : t('show_dock_icon'),
    icon: 'pi pi-eye-slash',
    command: async () => {
      await loadDockVisibilityAsync(!getDockVisibilityStatus())
    },
    visible: () => type() === 'macos',
  },
  {
    key: 'logging_menu',
    label: () => t('logging'),
    icon: 'pi pi-file',
    items: [], // Keep this to show it's a parent menu
  },
  {
    label: () => t('about.title'),
    icon: 'pi pi-at',
    command: async () => {
      aboutVisible.value = true
    },
  },
  {
    label: () => t('exit'),
    icon: 'pi pi-power-off',
    command: async () => {
      await exit(1)
    },
  },
])

onMounted(async () => {
  if (type() === 'android') {
    try {
      await initMobileVpnService()
      console.error("easytier init vpn service done")
    } catch (e: any) {
      console.error("easytier init vpn service failed", e)
    }
  }
  const unlisten = await listenGlobalEvents()
  await sendConfigs()
  return () => {
    unlisten()
  }
})

</script>

<template>
  <div id="root" class="flex flex-col">
    <Dialog v-model:visible="aboutVisible" modal :header="t('about.title')" :style="{ width: '70%' }">
      <About />
    </Dialog>
    <Menu ref="log_menu" :model="log_menu_items_popup" :popup="true" />

    <RemoteManagement class="flex-1 overflow-y-auto" :api="remoteClient" v-bind:instance-id="instanceId" />

    <Menubar :model="setting_menu_items" breakpoint="560px">
      <template #item="{ item, props }">
        <a v-if="item.key === 'logging_menu'" v-bind="props.action" @click="toggle_log_menu">
          <span :class="item.icon" />
          <span class="p-menubar-item-label">{{ getLabel(item) }}</span>
          <span class="pi pi-angle-down p-menubar-item-icon text-[9px]"></span>
        </a>
        <a v-else v-bind="props.action">
          <span :class="item.icon" />
          <span class="p-menubar-item-label">{{ getLabel(item) }}</span>
        </a>
      </template>
    </Menubar>
  </div>
</template>

<style scoped lang="postcss">
#root {
  height: 100vh;
  width: 100vw;
}

.p-dropdown :deep(.p-dropdown-panel .p-dropdown-items .p-dropdown-item) {
  padding: 0 0.5rem;
}
</style>

<style>
body {
  height: 100vh;
  width: 100vw;
  padding: 0;
  margin: 0;
  overflow: hidden;
}

.p-menubar .p-menuitem {
  margin: 0;
}

.p-select-overlay {
  max-width: calc(100% - 2rem);
}

/*

.p-tabview-panel {
  height: 100%;
} */
</style>
