<script setup lang="ts">
import { useToast } from 'primevue/usetoast'

import { exit } from '@tauri-apps/plugin-process';
import Config from '~/components/Config.vue'
import Status from '~/components/Status.vue'

import type { NetworkConfig } from '~/types/network'
import { loadLanguageAsync } from '~/modules/i18n'
import { getAutoLaunchStatusAsync as getAutoLaunchStatus, loadAutoLaunchStatusAsync } from '~/modules/auto_launch'
import { loadRunningInstanceIdsFromLocalStorage } from '~/stores/network'
import { setLoggingLevel } from '~/composables/network'
import TieredMenu from 'primevue/tieredmenu'
import { open } from '@tauri-apps/plugin-shell';
import { appLogDir } from '@tauri-apps/api/path'
import { writeText } from '@tauri-apps/plugin-clipboard-manager';
import { useTray } from '~/composables/tray';
import { type } from '@tauri-apps/plugin-os';
import { initMobileVpnService } from '~/composables/mobile_vpn';

const { t, locale } = useI18n()
const visible = ref(false)
const tomlConfig = ref('')

useTray(true)

const items = ref([
  {
    label: () => t('show_config'),
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

function addNewNetwork() {
  networkStore.addNewNetwork()
  networkStore.curNetwork = networkStore.lastNetwork
}

networkStore.$subscribe(async () => {
  networkStore.saveToLocalStorage()
  networkStore.saveRunningInstanceIdsToLocalStorage()
  try {
    await parseNetworkConfig(networkStore.curNetwork)
    messageBarSeverity.value = Severity.None
  }
  catch (e: any) {
    messageBarContent.value = e
    messageBarSeverity.value = Severity.Error
  }
})

async function runNetworkCb(cfg: NetworkConfig, cb: () => void) {
  await prepareVpnService()

  if (type() === 'android') {
    networkStore.clearNetworkInstances()
  } else {
    networkStore.removeNetworkInstance(cfg.instance_id)
  }

  await retainNetworkInstance(networkStore.networkInstanceIds)
  networkStore.addNetworkInstance(cfg.instance_id)

  try {
    await runNetworkInstance(cfg)
  }
  catch (e: any) {
    // console.error(e)
    toast.add({ severity: 'info', detail: e })
  }

  cb()
}

async function stopNetworkCb(cfg: NetworkConfig, cb: () => void) {
  // console.log('stopNetworkCb', cfg, cb)
  cb()
  networkStore.removeNetworkInstance(cfg.instance_id)
  await retainNetworkInstance(networkStore.networkInstanceIds)
}

async function updateNetworkInfos() {
  networkStore.updateWithNetworkInfos(await collectNetworkInfos())
}

let intervalId = 0
onMounted(async () => {
  intervalId = window.setInterval(async () => {
    await updateNetworkInfos()
  }, 500)
  await setTrayMenu([
    await MenuItemExit(t('tray.exit')),
    await MenuItemShow(t('tray.show'))
  ])
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
      await loadLanguageAsync((locale.value === 'en' ? 'cn' : 'en'))
      await setTrayMenu([
        await MenuItemExit(t('tray.exit')),
        await MenuItemShow(t('tray.show'))
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
    label: () => t('logging'),
    icon: 'pi pi-file',
    items: (function () {
      const levels = ['off', 'warn', 'info', 'debug', 'trace']
      let items = []
      for (let level of levels) {
        items.push({
          label: () => t("logging_level_" + level) + (current_log_level === level ? ' ✓' : ''),
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
          console.log("open log dir", await appLogDir())
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
    })()
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

onMounted(async () => {
  networkStore.loadFromLocalStorage()
  if (getAutoLaunchStatus()) {
    let prev_running_ids = loadRunningInstanceIdsFromLocalStorage()
    for (let id of prev_running_ids) {
      let cfg = networkStore.networkList.find((item) => item.instance_id === id)
      if (cfg) {
        networkStore.addNetworkInstance(cfg.instance_id)
        await runNetworkInstance(cfg)
      }
    }
  }
  await initMobileVpnService()
})

function isRunning(id: string) {
  return networkStore.networkInstanceIds.includes(id)
}

</script>

<script lang="ts">
</script>

<template>
  <div id="root" class="flex flex-column">
    <Dialog v-model:visible="visible" modal header="Config File" :style="{ width: '70%' }">
      <Panel>
        <ScrollPanel style="width: 100%; height: 300px">
          <pre>{{ tomlConfig }}</pre>
        </ScrollPanel>
      </Panel>
      <Divider />
      <div class="flex justify-content-end gap-2">
        <Button type="button" :label="t('close')" @click="visible = false" />
      </div>
    </Dialog>

    <div>
      <Toolbar>
        <template #start>
          <div class="flex align-items-center">
            <Button icon="pi pi-plus" severity="primary" :label="t('add_new_network')" @click="addNewNetwork" />
          </div>
        </template>

        <template #center>
          <div class="min-w-40">
            <Dropdown v-model="networkStore.curNetwork" :options="networkStore.networkList" :highlight-on-select="false"
              :placeholder="t('select_network')" class="w-full">
              <template #value="slotProps">
                <div class="flex items-start content-center">
                  <div class="mr-3">
                    <span>{{ slotProps.value.network_name }}</span>
                    <span
                      v-if="isRunning(slotProps.value.instance_id) && networkStore.instances[slotProps.value.instance_id].detail && (networkStore.instances[slotProps.value.instance_id].detail?.my_node_info.virtual_ipv4 !== '')"
                      class="ml-3">
                      {{ networkStore.instances[slotProps.value.instance_id].detail
                        ? networkStore.instances[slotProps.value.instance_id].detail?.my_node_info.virtual_ipv4 : '' }}
                    </span>
                  </div>
                  <Tag class="my-auto" :severity="isRunning(slotProps.value.instance_id) ? 'success' : 'info'"
                    :value="t(isRunning(slotProps.value.instance_id) ? 'network_running' : 'network_stopped')" />
                </div>
              </template>
              <template #option="slotProps">
                <div class="flex flex-col items-start content-center">
                  <div class="flex">
                    <div class="mr-3">
                      {{ t('network_name') }}: {{ slotProps.option.network_name }}
                    </div>
                    <Tag class="my-auto" :severity="isRunning(slotProps.option.instance_id) ? 'success' : 'info'"
                      :value="t(isRunning(slotProps.option.instance_id) ? 'network_running' : 'network_stopped')" />
                  </div>
                  <div>{{ slotProps.option.public_server_url }}</div>
                </div>
              </template>
            </Dropdown>
          </div>
        </template>

        <template #end>
          <Button icon="pi pi-cog" severity="secondary" aria-haspopup="true" :label="t('settings')"
            aria-controls="overlay_setting_menu" @click="toggle_setting_menu" />
          <TieredMenu id="overlay_setting_menu" ref="setting_menu" :model="setting_menu_items" :popup="true" />
        </template>
      </Toolbar>
    </div>

    <Panel class="h-full overflow-y-auto">
      <Stepper :value="activeStep">
        <StepList value="1">
          <Step value="1">{{ t('config_network') }}</Step>
          <Step value="2">{{ t('running') }}</Step>
        </StepList>
        <StepPanels value="1">
          <StepPanel v-slot="{ activateCallback = (s: string) => { } } = {}" value="1">
            <Config :instance-id="networkStore.curNetworkId" :config-invalid="messageBarSeverity !== Severity.None"
              @run-network="runNetworkCb($event, () => activateCallback('2'))" />
          </StepPanel>
          <StepPanel v-slot="{ activateCallback = (s: string) => { } } = {}" value="2">
            <div class="flex flex-column">
              <Status :instance-id="networkStore.curNetworkId" />
            </div>
            <div class="flex pt-4 justify-content-center">
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

/*

.p-tabview-panel {
  height: 100%;
} */
</style>
