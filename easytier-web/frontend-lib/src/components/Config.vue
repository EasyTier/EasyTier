<script setup lang="ts">
import InputGroup from 'primevue/inputgroup'
import InputGroupAddon from 'primevue/inputgroupaddon'
import { SelectButton, Checkbox, InputText, InputNumber, AutoComplete, Panel, Divider, ToggleButton, Button } from 'primevue'
import { DEFAULT_NETWORK_CONFIG, NetworkConfig, NetworkingMethod } from '../types/network'
import { defineProps, defineEmits, ref, } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  configInvalid?: boolean
  instanceId?: string
  hostname?: string
}>()

defineEmits(['runNetwork'])

const curNetwork = defineModel('curNetwork', {
  type: Object as () => NetworkConfig,
  default: DEFAULT_NETWORK_CONFIG,
})

const { t } = useI18n()

const networking_methods = ref([
  { value: NetworkingMethod.PublicServer, label: () => t('public_server') },
  { value: NetworkingMethod.Manual, label: () => t('manual') },
  { value: NetworkingMethod.Standalone, label: () => t('standalone') },
])

const protos: { [proto: string]: number } = { tcp: 11010, udp: 11010, wg: 11011, ws: 11011, wss: 11012 }

function searchUrlSuggestions(e: { query: string }): string[] {
  const query = e.query
  const ret = []
  // if query match "^\w+:.*", then no proto prefix
  if (query.match(/^\w+:.*/)) {
    // if query is a valid url, then add to suggestions
    try {
      // eslint-disable-next-line no-new
      new URL(query)
      ret.push(query)
    }
    catch { }
  }
  else {
    for (const proto in protos) {
      let item = `${proto}://${query}`
      // if query match ":\d+$", then no port suffix
      if (!query.match(/:\d+$/)) {
        item += `:${protos[proto]}`
      }
      ret.push(item)
    }
  }

  return ret
}

const publicServerSuggestions = ref([''])

function searchPresetPublicServers(e: { query: string }) {
  const presetPublicServers = [
    'tcp://public.easytier.top:11010',
  ]

  const query = e.query
  // if query is sub string of presetPublicServers, add to suggestions
  let ret = presetPublicServers.filter(item => item.includes(query))
  // add additional suggestions
  if (query.length > 0) {
    ret = ret.concat(searchUrlSuggestions(e))
  }

  publicServerSuggestions.value = ret
}

const peerSuggestions = ref([''])

function searchPeerSuggestions(e: { query: string }) {
  peerSuggestions.value = searchUrlSuggestions(e)
}

const inetSuggestions = ref([''])

function searchInetSuggestions(e: { query: string }) {
  if (e.query.search('/') >= 0) {
    inetSuggestions.value = [e.query]
  } else {
    const ret = []
    for (let i = 0; i < 32; i++) {
      ret.push(`${e.query}/${i}`)
    }
    inetSuggestions.value = ret
  }
}

const listenerSuggestions = ref([''])

function searchListenerSuggestiong(e: { query: string }) {
  const ret = []

  for (const proto in protos) {
    let item = `${proto}://0.0.0.0:`
    // if query is a number, use it as port
    if (e.query.match(/^\d+$/)) {
      item += e.query
    }
    else {
      item += protos[proto]
    }

    if (item.includes(e.query)) {
      ret.push(item)
    }
  }

  if (ret.length === 0) {
    ret.push(e.query)
  }

  listenerSuggestions.value = ret
}

</script>

<template>
  <div class="flex flex-column h-full">
    <div class="flex flex-column">
      <div class="w-10/12 self-center ">
        <Panel :header="t('basic_settings')">
          <div class="flex flex-column gap-y-2">
            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <div class="flex align-items-center" for="virtual_ip">
                  <label class="mr-2"> {{ t('virtual_ipv4') }} </label>
                  <Checkbox v-model="curNetwork.dhcp" input-id="virtual_ip_auto" :binary="true" />

                  <label for="virtual_ip_auto" class="ml-2">
                    {{ t('virtual_ipv4_dhcp') }}
                  </label>
                </div>
                <InputGroup>
                  <InputText id="virtual_ip" v-model="curNetwork.virtual_ipv4" :disabled="curNetwork.dhcp"
                    aria-describedby="virtual_ipv4-help" />
                  <InputGroupAddon>
                    <span>/</span>
                  </InputGroupAddon>
                  <InputNumber v-model="curNetwork.network_length" :disabled="curNetwork.dhcp"
                    inputId="horizontal-buttons" showButtons :step="1" mode="decimal" :min="1" :max="32" fluid
                    class="max-w-20" />
                </InputGroup>
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="network_name">{{ t('network_name') }}</label>
                <InputText id="network_name" v-model="curNetwork.network_name" aria-describedby="network_name-help" />
              </div>
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="network_secret">{{ t('network_secret') }}</label>
                <InputText id="network_secret" v-model="curNetwork.network_secret"
                  aria-describedby="network_secret-help" />
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="nm">{{ t('networking_method') }}</label>
                <SelectButton v-model="curNetwork.networking_method" :options="networking_methods"
                  :option-label="(v) => v.label()" option-value="value" />
                <div class="items-center flex flex-row p-fluid gap-x-1">
                  <AutoComplete v-if="curNetwork.networking_method === NetworkingMethod.Manual" id="chips"
                    v-model="curNetwork.peer_urls" :placeholder="t('chips_placeholder', ['tcp://8.8.8.8:11010'])"
                    class="grow" multiple fluid :suggestions="peerSuggestions" @complete="searchPeerSuggestions" />

                  <AutoComplete v-if="curNetwork.networking_method === NetworkingMethod.PublicServer"
                    v-model="curNetwork.public_server_url" :suggestions="publicServerSuggestions"
                    :virtual-scroller-options="{ itemSize: 38 }" class="grow" dropdown :complete-on-focus="true"
                    @complete="searchPresetPublicServers" />
                </div>
              </div>
            </div>
          </div>
        </Panel>

        <Divider />

        <Panel :header="t('advanced_settings')" toggleable collapsed>
          <div class="flex flex-column gap-y-2">
            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <div class="flex align-items-center">
                  <Checkbox v-model="curNetwork.latency_first" input-id="use_latency_first" :binary="true" />
                  <label for="use_latency_first" class="ml-2"> {{ t('use_latency_first') }} </label>
                </div>
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="hostname">{{ t('hostname') }}</label>
                <InputText id="hostname" v-model="curNetwork.hostname" aria-describedby="hostname-help" :format="true"
                  :placeholder="t('hostname_placeholder', [props.hostname])" />
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap w-full">
              <div class="flex flex-column gap-2 grow p-fluid">
                <label for="username">{{ t('proxy_cidrs') }}</label>
                <AutoComplete id="subnet-proxy" v-model="curNetwork.proxy_cidrs"
                  :placeholder="t('chips_placeholder', ['10.0.0.0/24'])" class="w-full" multiple fluid
                  :suggestions="inetSuggestions" @complete="searchInetSuggestions" />
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap ">
              <div class="flex flex-column gap-2 grow">
                <label for="username">VPN Portal</label>
                <ToggleButton v-model="curNetwork.enable_vpn_portal" on-icon="pi pi-check" off-icon="pi pi-times"
                  :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                <div v-if="curNetwork.enable_vpn_portal" class="items-center flex flex-row gap-x-4">
                  <div class="min-w-64">
                    <InputGroup>
                      <InputText v-model="curNetwork.vpn_portal_client_network_addr"
                        :placeholder="t('vpn_portal_client_network')" />
                      <InputGroupAddon>
                        <span>/{{ curNetwork.vpn_portal_client_network_len }}</span>
                      </InputGroupAddon>
                    </InputGroup>

                    <InputNumber v-model="curNetwork.vpn_portal_listen_port" :allow-empty="false" :format="false"
                      :min="0" :max="65535" class="w-8" fluid />
                  </div>
                </div>
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 grow p-fluid">
                <label for="listener_urls">{{ t('listener_urls') }}</label>
                <AutoComplete id="listener_urls" v-model="curNetwork.listener_urls" :suggestions="listenerSuggestions"
                  class="w-full" dropdown :complete-on-focus="true"
                  :placeholder="t('chips_placeholder', ['tcp://1.1.1.1:11010'])" multiple
                  @complete="searchListenerSuggestiong" />
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="rpc_port">{{ t('rpc_port') }}</label>
                <InputNumber id="rpc_port" v-model="curNetwork.rpc_port" aria-describedby="rpc_port-help"
                  :format="false" :min="0" :max="65535" />
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="dev_name">{{ t('dev_name') }}</label>
                <InputText id="dev_name" v-model="curNetwork.dev_name" aria-describedby="dev_name-help" :format="true"
                  :placeholder="t('dev_name_placeholder')" />
              </div>
            </div>
          </div>
        </Panel>

        <div class="flex pt-4 justify-content-center">
          <Button :label="t('run_network')" icon="pi pi-arrow-right" icon-pos="right" :disabled="configInvalid"
            @click="$emit('runNetwork', curNetwork)" />
        </div>
      </div>
    </div>
  </div>
</template>
