<script setup lang="ts">
import { appLogDir } from '@tauri-apps/api/path'

import { getCurrentWindow } from '@tauri-apps/api/window'
import { writeText } from '@tauri-apps/plugin-clipboard-manager'
import { type } from '@tauri-apps/plugin-os'
import { exit } from '@tauri-apps/plugin-process'
import { open } from '@tauri-apps/plugin-shell'
import TieredMenu from 'primevue/tieredmenu'
import { useToast } from 'primevue/usetoast'
import { NetworkTypes, Config, Status, Utils, I18nUtils, ConfigEditDialog } from 'easytier-frontend-lib'

import { isAutostart, setLoggingLevel } from '~/composables/network'
import { useTray } from '~/composables/tray'
import { getAutoLaunchStatusAsync as getAutoLaunchStatus, loadAutoLaunchStatusAsync } from '~/modules/auto_launch'
import { getDockVisibilityStatus, loadDockVisibilityAsync } from '~/modules/dock_visibility'

const { t, locale } = useI18n()
const visible = ref(false)
const aboutVisible = ref(false)
const tomlConfig = ref('')

useTray(true)

const items = ref([
  {
    label: () => activeStep.value == "2" ? t('show_config') : t('edit_config'),
    icon: 'pi pi-file-edit',
    command: async () => {
      try {
        const ret = await parseNetworkConfig(networkStore.curNetwork)
        tomlConfig.value = ret
      }
      catch (e: any) {
        tomlConfig.value = e
      }
      visible.value = true
    },
  },
  {
    label: () => t('del_cur_network'),
    icon: 'pi pi-times',
    command: async () => {
      networkStore.removeNetworkInstance(networkStore.curNetwork.instance_id)
      await retainNetworkInstance(networkStore.networkInstanceIds)
      networkStore.delCurNetwork()
    },
    disabled: () => networkStore.networkList.length <= 1,
  },
])

enum Severity {
  None = 'none',
  Success = 'success',
  Info = 'info',
  Warn = 'warn',
  Error = 'error',
}

const messageBarSeverity = ref(Severity.None)
const messageBarContent = ref('')
const toast = useToast()

const networkStore = useNetworkStore()

const curNetworkConfig = computed(() => {
  if (networkStore.curNetworkId) {
    // console.log('instanceId', props.instanceId)
    const c = networkStore.networkList.find(n => n.instance_id === networkStore.curNetworkId)
    if (c !== undefined)
      return c
  }

  return networkStore.curNetwork
})

const curNetworkInst = computed<NetworkTypes.NetworkInstance | null>(() => {
  let ret = networkStore.networkInstances.find(n => n.instance_id === curNetworkConfig.value.instance_id)
  console.log('curNetworkInst', ret)
  if (ret === undefined) {
    return null;
  } else {
    return ret;
  }
})

function addNewNetwork() {
  networkStore.addNewNetwork()
  networkStore.curNetwork = networkStore.lastNetwork
}

networkStore.$subscribe(async () => {
  networkStore.saveToLocalStorage()
  try {
    await parseNetworkConfig(networkStore.curNetwork)
    messageBarSeverity.value = Severity.None
  }
  catch (e: any) {
    messageBarContent.value = e
    messageBarSeverity.value = Severity.Error
  }
})

async function runNetworkCb(cfg: NetworkTypes.NetworkConfig, cb: () => void) {
  if (type() === 'android') {
    await prepareVpnService(cfg.instance_id)
    networkStore.clearNetworkInstances()
  }
  else {
    networkStore.removeNetworkInstance(cfg.instance_id)
  }

  await retainNetworkInstance(networkStore.networkInstanceIds)
  networkStore.addNetworkInstance(cfg.instance_id)

  try {
    await runNetworkInstance(cfg)
    networkStore.addAutoStartInstId(cfg.instance_id)
  }
  catch (e: any) {
    // console.error(e)
    toast.add({ severity: 'info', detail: e })
  }

  cb()
}

async function stopNetworkCb(cfg: NetworkTypes.NetworkConfig, cb: () => void) {
  // console.log('stopNetworkCb', cfg, cb)
  cb()
  networkStore.removeNetworkInstance(cfg.instance_id)
  await retainNetworkInstance(networkStore.networkInstanceIds)
  networkStore.removeAutoStartInstId(cfg.instance_id)
}

async function updateNetworkInfos() {
  networkStore.updateWithNetworkInfos(await collectNetworkInfos())
}

let intervalId = 0
onMounted(async () => {
  intervalId = window.setInterval(async () => {
    await updateNetworkInfos()
  }, 500)

  window.setTimeout(async () => {
    await setTrayMenu([
      await MenuItemShow(t('tray.show')),
      await MenuItemExit(t('tray.exit')),
    ])
  }, 1000)
})
onUnmounted(() => clearInterval(intervalId))

const activeStep = computed(() => {
  return networkStore.networkInstanceIds.includes(networkStore.curNetworkId) ? '2' : '1'
})

let current_log_level = 'off'

const setting_menu = ref()
const setting_menu_items = ref([
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
    label: () => t('logging'),
    icon: 'pi pi-file',
    items: (function () {
      const levels = ['off', 'warn', 'info', 'debug', 'trace']
      const items = []
      for (const level of levels) {
        items.push({
          label: () => t(`logging_level_${level}`) + (current_log_level === level ? ' ✓' : ''),
          command: async () => {
            current_log_level = level
            await setLoggingLevel(level)
          },
        })
      }
      items.push({
        separator: true,
      })
      items.push({
        label: () => t('logging_open_dir'),
        icon: 'pi pi-folder-open',
        command: async () => {
          // console.log('open log dir', await appLogDir())
          await open(await appLogDir())
        },
      })
      items.push({
        label: () => t('logging_copy_dir'),
        icon: 'pi pi-tablet',
        command: async () => {
          await writeText(await appLogDir())
        },
      })
      return items
    })(),
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

function toggle_setting_menu(event: any) {
  setting_menu.value.toggle(event)
}

onBeforeMount(async () => {
  networkStore.loadFromLocalStorage()
  if (type() !== 'android' && getAutoLaunchStatus() && await isAutostart()) {
    getCurrentWindow().hide()
    const autoStartIds = networkStore.autoStartInstIds
    for (const id of autoStartIds) {
      const cfg = networkStore.networkList.find((item: NetworkTypes.NetworkConfig) => item.instance_id === id)
      if (cfg) {
        networkStore.addNetworkInstance(cfg.instance_id)
        await runNetworkInstance(cfg)
      }
    }
  }
})

onMounted(async () => {
  if (type() === 'android') {
    try {
      await initMobileVpnService()
      console.error("easytier init vpn service done")
    } catch (e: any) {
      console.error("easytier init vpn service failed", e)
    }
  }
})

function isRunning(id: string) {
  return networkStore.networkInstanceIds.includes(id)
}

async function saveTomlConfig(tomlConfig: string) {
  const config = await generateNetworkConfig(tomlConfig)
  networkStore.replaceCurNetwork(config);
  toast.add({ severity: 'success', detail: t('config_saved'), life: 3000 })
  visible.value = false
}
</script>

<script lang="ts">
</script>

<template>
  <div id="root" class="flex flex-col">
    <ConfigEditDialog v-model:visible="visible" :cur-network="curNetworkConfig" :readonly="activeStep !== '1'"
      :save-config="saveTomlConfig" :generate-config="parseNetworkConfig" />

    <Dialog v-model:visible="aboutVisible" modal :header="t('about.title')" :style="{ width: '70%' }">
      <About />
    </Dialog>

    <div class="w-full">
      <div class="flex items-center gap-4 p-4 h-20">
        <!-- 网络按钮 -->
        <div class="flex shrink-0 items-center">
          <Button icon="pi pi-plus" severity="primary" :label="t('add_new_network')" class="hidden md:inline-flex"
            @click="addNewNetwork" />
          <Button icon="pi pi-plus" severity="primary" class="md:hidden px-6" @click="addNewNetwork" />
        </div>

        <!-- 网络选择 - 占据中间剩余空间 -->
        <Select v-model="networkStore.curNetwork" :options="networkStore.networkList" :highlight-on-select="false"
          :placeholder="t('select_network')" class="flex-1 h-full min-w-0">
          <template #value="slotProps">
            <div class="flex items-center content-center min-w-0">
              <div class="mr-4 flex-col min-w-0 flex-1">
                <span class="truncate block"> &nbsp; {{ slotProps.value.network_name }}</span>
              </div>
              <Tag class="my-auto leading-3 shrink-0"
                :severity="isRunning(slotProps.value.instance_id) ? 'success' : 'info'"
                :value="t(isRunning(slotProps.value.instance_id) ? 'network_running' : 'network_stopped')" />
            </div>
          </template>
          <template #option="slotProps">
            <div class="flex flex-col items-start content-center max-w-full">
              <div class="flex items-center min-w-0 w-full">
                <div class="mr-4 min-w-0 flex-1">
                  <span class="truncate block">{{ t('network_name') }}: {{ slotProps.option.network_name }}</span>
                </div>
                <Tag class="my-auto leading-3 shrink-0"
                  :severity="isRunning(slotProps.option.instance_id) ? 'success' : 'info'"
                  :value="t(isRunning(slotProps.option.instance_id) ? 'network_running' : 'network_stopped')" />
              </div>
              <div v-if="slotProps.option.networking_method !== NetworkTypes.NetworkingMethod.Standalone"
                class="max-w-full overflow-hidden text-ellipsis">
                {{ slotProps.option.networking_method === NetworkTypes.NetworkingMethod.Manual
                  ? slotProps.option.peer_urls.join(', ')
                  : slotProps.option.public_server_url }}
              </div>
              <div
                v-if="isRunning(slotProps.option.instance_id) && networkStore.instances[slotProps.option.instance_id].detail && (!!networkStore.instances[slotProps.option.instance_id].detail?.my_node_info.virtual_ipv4)">
                {{
                  Utils.ipv4InetToString(networkStore.instances[slotProps.option.instance_id].detail?.my_node_info.virtual_ipv4)
                }}
              </div>
            </div>
          </template>
        </Select>

        <!-- 设置按钮 -->
        <div class="flex items-center shrink-0">
          <Button icon="pi pi-cog" severity="secondary" aria-haspopup="true" :label="t('settings')"
            class="hidden md:inline-flex" aria-controls="overlay_setting_menu" @click="toggle_setting_menu" />
          <Button icon="pi pi-cog" severity="secondary" aria-haspopup="true" class="md:hidden px-6"
            aria-controls="overlay_setting_menu" @click="toggle_setting_menu" />
          <TieredMenu id="overlay_setting_menu" ref="setting_menu" :model="setting_menu_items" :popup="true" />
        </div>
      </div>
    </div>

    <Panel class="h-full overflow-y-auto">
      <Stepper :value="activeStep">
        <StepList value="1">
          <Step value="1">
            {{ t('config_network') }}
          </Step>
          <Step value="2">
            {{ t('running') }}
          </Step>
        </StepList>
        <StepPanels value="1">
          <StepPanel v-slot="{ activateCallback = (s: string) => { } } = {}" value="1">
            <Config :instance-id="networkStore.curNetworkId" :config-invalid="messageBarSeverity !== Severity.None"
              :cur-network="curNetworkConfig" @run-network="runNetworkCb($event, () => activateCallback('2'))" />
          </StepPanel>
          <StepPanel v-slot="{ activateCallback = (s: string) => { } } = {}" value="2">
            <div class="flex flex-col">
              <Status :cur-network-inst="curNetworkInst" />
            </div>
            <div class="flex pt-6 justify-center">
              <Button :label="t('stop_network')" severity="danger" icon="pi pi-arrow-left"
                @click="stopNetworkCb(networkStore.curNetwork, () => activateCallback('1'))" />
            </div>
          </StepPanel>
        </StepPanels>
      </Stepper>
    </Panel>

    <div>
      <Menubar :model="items" breakpoint="300px" />
      <InlineMessage v-if="messageBarSeverity !== Severity.None" class="absolute bottom-0 right-0" severity="error">
        {{ messageBarContent }}
      </InlineMessage>
    </div>
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
