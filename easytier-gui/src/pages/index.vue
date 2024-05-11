<script setup lang="ts">
import Stepper from 'primevue/stepper'
import StepperPanel from 'primevue/stepperpanel'

import { useToast } from 'primevue/usetoast'

import { exit } from '@tauri-apps/api/process'
import Config from '~/components/Config.vue'
import Status from '~/components/Status.vue'

import type { NetworkConfig } from '~/types/network'
import { loadLanguageAsync } from '~/modules/i18n'

const { t, locale } = useI18n()
const visible = ref(false)
const tomlConfig = ref('')

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
  try {
    await parseNetworkConfig(networkStore.curNetwork)
    messageBarSeverity.value = Severity.None
  }
  catch (e: any) {
    messageBarContent.value = e
    messageBarSeverity.value = Severity.Error
  }
})

async function runNetworkCb(cfg: NetworkConfig, cb: (e: MouseEvent) => void) {
  cb({} as MouseEvent)
  networkStore.removeNetworkInstance(cfg.instance_id)
  await retainNetworkInstance(networkStore.networkInstanceIds)
  networkStore.addNetworkInstance(cfg.instance_id)

  try {
    await runNetworkInstance(cfg)
  }
  catch (e: any) {
    // console.error(e)
    toast.add({ severity: 'info', detail: e })
  }
}

async function stopNetworkCb(cfg: NetworkConfig, cb: (e: MouseEvent) => void) {
  // console.log('stopNetworkCb', cfg, cb)
  cb({} as MouseEvent)
  networkStore.removeNetworkInstance(cfg.instance_id)
  await retainNetworkInstance(networkStore.networkInstanceIds)
}

async function updateNetworkInfos() {
  networkStore.updateWithNetworkInfos(await collectNetworkInfos())
}

let intervalId = 0
onMounted(() => {
  intervalId = window.setInterval(async () => {
    await updateNetworkInfos()
  }, 500)
})
onUnmounted(() => clearInterval(intervalId))

const curNetworkHasInstance = computed(() => {
  return networkStore.networkInstanceIds.includes(networkStore.curNetworkId)
})

const activeStep = computed(() => {
  return curNetworkHasInstance.value ? 1 : 0
})

const setting_menu = ref()
const setting_menu_items = ref([
  {
    label: () => t('settings'),
    items: [
      {
        label: () => t('exchange_language'),
        icon: 'pi pi-language',
        command: async () => {
          await loadLanguageAsync((locale.value === 'en' ? 'cn' : 'en'))
        },
      },
      {
        label: () => t('exit'),
        icon: 'pi pi-times',
        command: async () => {
          await exit(1)
        },
      },
    ],
  },
])

function toggle_setting_menu(event: any) {
  setting_menu.value.toggle(event)
}

onMounted(async () => {
  networkStore.loadFromLocalStorage()
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
        <Button type="button" :label="$t('close')" @click="visible = false" />
      </div>
    </Dialog>

    <div>
      <Toolbar>
        <template #start>
          <div class="flex align-items-center gap-2">
            <Button
              icon="pi pi-plus" class="mr-2" severity="primary" :label="$t('add_new_network')"
              @click="addNewNetwork"
            />
          </div>
        </template>

        <template #center>
          <div class="min-w-80 mr-20">
            <Dropdown
              v-model="networkStore.curNetwork" :options="networkStore.networkList" :highlight-on-select="false"
              :placeholder="$t('select_network')" class="w-full"
            >
              <template #value="slotProps">
                <div class="flex items-start content-center">
                  <div class="mr-3">
                    <span>{{ slotProps.value.network_name }}</span>
                    <span v-if="isRunning(slotProps.value.instance_id)" class="ml-3">
                      {{ slotProps.value.virtual_ipv4 }}
                    </span>
                  </div>
                  <Tag
                    class="my-auto" :severity="isRunning(slotProps.value.instance_id) ? 'success' : 'info'"
                    :value="$t(isRunning(slotProps.value.instance_id) ? 'network_running' : 'network_stopped')"
                  />
                </div>
              </template>
              <template #option="slotProps">
                <div class="flex flex-col items-start content-center">
                  <div class="flex">
                    <div class="mr-3">
                      {{ $t('network_name') }}: {{ slotProps.option.network_name }}
                    </div>
                    <Tag
                      class="my-auto" :severity="isRunning(slotProps.option.instance_id) ? 'success' : 'info'"
                      :value="$t(isRunning(slotProps.option.instance_id) ? 'network_running' : 'network_stopped')"
                    />
                  </div>
                  <div>{{ slotProps.option.public_server_url }}</div>
                </div>
              </template>
            </Dropdown>
          </div>
        </template>

        <template #end>
          <Button
            icon="pi pi-cog" class="mr-2" severity="secondary" aria-haspopup="true" :label="$t('settings')"
            aria-controls="overlay_setting_menu" @click="toggle_setting_menu"
          />
          <Menu id="overlay_setting_menu" ref="setting_menu" :model="setting_menu_items" :popup="true" />
        </template>
      </Toolbar>
    </div>

    <Stepper class="h-full overflow-y-auto" :active-step="activeStep">
      <StepperPanel :header="$t('config_network')" class="w">
        <template #content="{ nextCallback }">
          <Config
            :instance-id="networkStore.curNetworkId" :config-invalid="messageBarSeverity !== Severity.None"
            @run-network="runNetworkCb($event, nextCallback)"
          />
        </template>
      </StepperPanel>
      <StepperPanel :header="$t('running')">
        <template #content="{ prevCallback }">
          <div class="flex flex-column">
            <Status :instance-id="networkStore.curNetworkId" />
          </div>
          <div class="flex pt-4 justify-content-center">
            <Button
              :label="$t('stop_network')" severity="danger" icon="pi pi-arrow-left"
              @click="stopNetworkCb(networkStore.curNetwork, prevCallback)"
            />
          </div>
        </template>
      </StepperPanel>
    </Stepper>

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
