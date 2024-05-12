<script setup lang="ts">
import Stepper from 'primevue/stepper'
import StepperPanel from 'primevue/stepperpanel'

import { useToast } from 'primevue/usetoast'

import { exit } from '@tauri-apps/api/process'
import Config from '~/components/Config.vue'
import Status from '~/components/Status.vue'

import type { NetworkConfig, NetworkInstanceRunningInfo } from '~/types/network'
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

const runBtnDisabled = ref(false)

async function runNetworkCb(cfg: NetworkConfig, cb: (e: MouseEvent) => void) {
  if ((Object.keys(networkStore.networkAutoIpv4Ids).includes(networkStore.curNetworkId) && networkStore.networkInstanceIds.includes(networkStore.curNetworkId)))
    return
  runBtnDisabled.value = true
  if (cfg.virtual_ip_auto)
    cfg.virtual_ipv4 = await getAvailableIP(cfg)

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
  runBtnDisabled.value = false
}

async function stopNetworkCb(cfg: NetworkConfig, cb: (e: MouseEvent) => void) {
  // console.log('stopNetworkCb', cfg, cb)
  networkStore.removeNetworkInstance(cfg.instance_id)
  delete networkStore.networkAutoIpv4Ids[cfg.instance_id]
  await retainNetworkInstance(networkStore.networkInstanceIds)
  cb({} as MouseEvent)
}

async function updateNetworkInfos() {
  networkStore.updateWithNetworkInfos(await collectNetworkInfos())
}

async function getAvailableIP(cfg: NetworkConfig) {
  const t_cfg = JSON.parse(JSON.stringify(cfg))
  t_cfg.virtual_ipv4 = ''
  t_cfg.hostname = 'pseudo-dhcp'
  networkStore.networkAutoIpv4Ids[t_cfg.instance_id] = { ...t_cfg } as NetworkConfig
  networkStore.removeNetworkInstance(t_cfg.instance_id)
  await retainNetworkInstance(networkStore.networkInstanceIds)
  networkStore.addNetworkInstance(t_cfg.instance_id)
  try {
    await runNetworkInstance(t_cfg)
    // almost need 3000ms
    for (let num = 10; num >= 0; num--) {
      await new Promise(resolve => setTimeout(resolve, 500))
      const infos: Record<string, NetworkInstanceRunningInfo> = await collectNetworkInfos()
      const ip_set = new Set<string>()
      Object.values(infos).forEach((info) => {
        if (info.peer_route_pairs.length > 0) {
          info.peer_route_pairs.forEach((pair) => {
            ip_set.add(pair.route.ipv4_addr)
          })
        }
      })
      const ip_arr: string[] = Array.from(ip_set).filter(ip => ip !== '')
      // it is possible that some other nodes may not have obtained their ip
      if (ip_arr.length > 0) {
        const addr = ip_arr[0].split('.').map(Number)
        while (ip_arr.includes(addr.join('.'))) {
          if (addr[3] < 254) { addr[3] += 1 }
          else {
            addr[3] = 2
            if (addr[2] < 254) {
              addr[2] += 1
            }
            else {
              addr[2] = 2
              if (addr[1] < 254) {
                addr[1] += 1
              }
              else {
                addr[1] = 2
                if (addr[0] < 254)
                  addr[0] += 1
                else
                  addr[0] = 10
              }
            }
          }
        }
        t_cfg.virtual_ipv4 = addr.join('.')
        break
      }
    }
  }
  catch (e: any) {
    // console.error(e)
    toast.add({ severity: 'info', detail: e })
  }

  if (t_cfg.virtual_ipv4 === '')
    t_cfg.virtual_ipv4 = '10.25.2.2'

  networkStore.removeNetworkInstance(t_cfg.instance_id)
  delete networkStore.networkAutoIpv4Ids[t_cfg.instance_id]
  await retainNetworkInstance(networkStore.networkInstanceIds)

  return t_cfg.virtual_ipv4
}

let intervalId = 0
onMounted(() => {
  intervalId = window.setInterval(async () => {
    await updateNetworkInfos()
  }, 500)
})
onUnmounted(() => clearInterval(intervalId))

const activeStep = computed(() => {
  return (!Object.keys(networkStore.networkAutoIpv4Ids).includes(networkStore.curNetworkId) && networkStore.networkInstanceIds.includes(networkStore.curNetworkId)) ? 1 : 0
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

const networkConfigList = computed(() => {
  return networkStore.networkList.filter(c => !Object.keys(networkStore.networkAutoIpv4Ids).includes(c.instance_id))
})

function toggle_setting_menu(event: any) {
  setting_menu.value.toggle(event)
}

onMounted(async () => {
  networkStore.loadFromLocalStorage()
})

function isRunning(id: string) {
  return (!Object.keys(networkStore.networkAutoIpv4Ids).includes(id) && networkStore.networkInstanceIds.includes(id))
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
              v-model="networkStore.curNetwork" :options="networkConfigList" :highlight-on-select="false"
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
      <StepperPanel :header="$t('config_network')">
        <template #content="{ nextCallback }">
          <Config
            :instance-id="networkStore.curNetworkId"
            :config-invalid="messageBarSeverity !== Severity.None || runBtnDisabled"
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
