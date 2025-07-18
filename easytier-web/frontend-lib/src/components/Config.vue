<script setup lang="ts">
import InputGroup from 'primevue/inputgroup'
import InputGroupAddon from 'primevue/inputgroupaddon'
import { SelectButton, Checkbox, InputText, InputNumber, AutoComplete, Panel, Divider, ToggleButton, Button, Password } from 'primevue'
import { DEFAULT_NETWORK_CONFIG, NetworkConfig, NetworkingMethod } from '../types/network'
import { defineProps, defineEmits, ref, } from 'vue'
import { useI18n } from 'vue-i18n'

const props = defineProps<{
  configInvalid?: boolean
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

function searchListenerSuggestions(e: { query: string }) {
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


const exitNodesSuggestions = ref([''])

function searchExitNodesSuggestions(e: { query: string }) {
  const ret = []
  ret.push(e.query)
  exitNodesSuggestions.value = ret
}

const whitelistSuggestions = ref([''])

function searchWhitelistSuggestions(e: { query: string }) {
  const ret = []
  ret.push(e.query)
  whitelistSuggestions.value = ret
}

interface BoolFlag {
  field: keyof NetworkConfig
  help: string
}

const bool_flags: BoolFlag[] = [
  { field: 'latency_first', help: 'latency_first_help' },
  { field: 'use_smoltcp', help: 'use_smoltcp_help' },
  { field: 'disable_ipv6', help: 'disable_ipv6_help' },
  { field: 'enable_kcp_proxy', help: 'enable_kcp_proxy_help' },
  { field: 'disable_kcp_input', help: 'disable_kcp_input_help' },
  { field: 'enable_quic_proxy', help: 'enable_quic_proxy_help' },
  { field: 'disable_quic_input', help: 'disable_quic_input_help' },
  { field: 'disable_p2p', help: 'disable_p2p_help' },
  { field: 'bind_device', help: 'bind_device_help' },
  { field: 'no_tun', help: 'no_tun_help' },
  { field: 'enable_exit_node', help: 'enable_exit_node_help' },
  { field: 'relay_all_peer_rpc', help: 'relay_all_peer_rpc_help' },
  { field: 'multi_thread', help: 'multi_thread_help' },
  { field: 'proxy_forward_by_system', help: 'proxy_forward_by_system_help' },
  { field: 'disable_encryption', help: 'disable_encryption_help' },
  { field: 'disable_udp_hole_punching', help: 'disable_udp_hole_punching_help' },
  { field: 'enable_magic_dns', help: 'enable_magic_dns_help' },
  { field: 'enable_private_mode', help: 'enable_private_mode_help' },
]

</script>

<template>
  <div class="frontend-lib">
    <div class="flex flex-col h-full">
      <div class="flex flex-col">
        <div class="w-11/12 self-center ">
          <Panel :header="t('basic_settings')">
            <div class="flex flex-col gap-y-2">
              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex items-center" for="virtual_ip">
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
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="network_name">{{ t('network_name') }}</label>
                  <InputText id="network_name" v-model="curNetwork.network_name" aria-describedby="network_name-help" />
                </div>
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="network_secret">{{ t('network_secret') }}</label>
                  <Password id="network_secret" v-model="curNetwork.network_secret"
                    aria-describedby="network_secret-help" toggleMask :feedback="false" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="nm">{{ t('networking_method') }}</label>
                  <SelectButton v-model="curNetwork.networking_method" :options="networking_methods"
                    :option-label="(v) => v.label()" option-value="value" />
                  <div class="items-center flex flex-row p-fluid gap-x-1">
                    <AutoComplete v-if="curNetwork.networking_method === NetworkingMethod.Manual" id="chips"
                      v-model="curNetwork.peer_urls" :placeholder="t('chips_placeholder', ['tcp://8.8.8.8:11010'])"
                      class="grow" multiple fluid :suggestions="peerSuggestions" @complete="searchPeerSuggestions" />

                    <AutoComplete v-if="curNetwork.networking_method === NetworkingMethod.PublicServer"
                      v-model="curNetwork.public_server_url" :suggestions="publicServerSuggestions"
                      class="grow" dropdown :complete-on-focus="false"
                      @complete="searchPresetPublicServers" />
                  </div>
                </div>
              </div>
            </div>
          </Panel>

          <Divider />

          <Panel :header="t('advanced_settings')" toggleable collapsed>
            <div class="flex flex-col gap-y-2">

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label> {{ t('flags_switch') }} </label>
                  <div class="flex flex-row flex-wrap">

                    <div class="basis-[20rem] flex items-center" v-for="flag in bool_flags">
                      <Checkbox v-model="curNetwork[flag.field]" :input-id="flag.field" :binary="true" />
                      <label :for="flag.field" class="ml-2"> {{ t(flag.field) }} </label>
                      <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t(flag.help)"></span>
                    </div>

                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="hostname">{{ t('hostname') }}</label>
                  <InputText id="hostname" v-model="curNetwork.hostname" aria-describedby="hostname-help" :format="true"
                    :placeholder="t('hostname_placeholder', [props.hostname])" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <label for="username">{{ t('proxy_cidrs') }}</label>
                  <AutoComplete id="subnet-proxy" v-model="curNetwork.proxy_cidrs"
                    :placeholder="t('chips_placeholder', ['10.0.0.0/24'])" class="w-full" multiple fluid
                    :suggestions="inetSuggestions" @complete="searchInetSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow">
                  <label for="username">VPN Portal</label>
                  <ToggleButton v-model="curNetwork.enable_vpn_portal" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_vpn_portal" class="items-center flex flex-row gap-x-4">
                    <div class="flex flex-row gap-x-9 flex-wrap w-full">
                      <div class="flex flex-col gap-2 basis-8/12 grow">
                        <InputGroup>
                          <InputText v-model="curNetwork.vpn_portal_client_network_addr"
                            :placeholder="t('vpn_portal_client_network')" />
                          <InputGroupAddon>
                            <span>/{{ curNetwork.vpn_portal_client_network_len }}</span>
                          </InputGroupAddon>
                        </InputGroup>
                      </div>
                      <div class="flex flex-col gap-2 basis-3/12 grow">
                        <InputNumber v-model="curNetwork.vpn_portal_listen_port" :allow-empty="false" :format="false"
                          :min="0" :max="65535" fluid />
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <label for="listener_urls">{{ t('listener_urls') }}</label>
                  <AutoComplete id="listener_urls" v-model="curNetwork.listener_urls" :suggestions="listenerSuggestions"
                    class="w-full" dropdown :complete-on-focus="true"
                    :placeholder="t('chips_placeholder', ['tcp://1.1.1.1:11010'])" multiple
                    @complete="searchListenerSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="rpc_port">{{ t('rpc_port') }}</label>
                  <InputNumber id="rpc_port" v-model="curNetwork.rpc_port" aria-describedby="rpc_port-help"
                    :format="false" :min="0" :max="65535" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <label for="">{{ t('rpc_portal_whitelists') }}</label>
                  <AutoComplete id="rpc_portal_whitelists" v-model="curNetwork.rpc_portal_whitelists"
                    :placeholder="t('chips_placeholder', ['127.0.0.0/8'])" class="w-full" multiple fluid
                    :suggestions="inetSuggestions" @complete="searchInetSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <label for="dev_name">{{ t('dev_name') }}</label>
                  <InputText id="dev_name" v-model="curNetwork.dev_name" aria-describedby="dev_name-help" :format="true"
                    :placeholder="t('dev_name_placeholder')" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex">
                    <label for="mtu">{{ t('mtu') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('mtu_help')"></span>
                  </div>
                  <InputNumber id="mtu" v-model="curNetwork.mtu" aria-describedby="mtu-help" :format="false"
                    :placeholder="t('mtu_placeholder')" :min="400" :max="1380" fluid />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap">
                <div class="flex flex-col gap-2 basis-5/12 grow">
                  <div class="flex">
                    <label for="relay_network_whitelist">{{ t('relay_network_whitelist') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center"
                      v-tooltip="t('relay_network_whitelist_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_relay_network_whitelist" on-icon="pi pi-check"
                    off-icon="pi pi-times" :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_relay_network_whitelist" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <AutoComplete id="relay_network_whitelist" v-model="curNetwork.relay_network_whitelist"
                        :placeholder="t('relay_network_whitelist')" class="w-full" multiple fluid
                        :suggestions="whitelistSuggestions" @complete="searchWhitelistSuggestions" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow">
                  <div class="flex">
                    <label for="routes">{{ t('manual_routes') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('manual_routes_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_manual_routes" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_manual_routes" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <AutoComplete id="routes" v-model="curNetwork.routes"
                        :placeholder="t('chips_placeholder', ['192.168.0.0/16'])" class="w-full" multiple fluid
                        :suggestions="inetSuggestions" @complete="searchInetSuggestions" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap ">
                <div class="flex flex-col gap-2 grow">
                  <div class="flex">
                    <label for="socks5_port">{{ t('socks5') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('socks5_help')"></span>
                  </div>
                  <ToggleButton v-model="curNetwork.enable_socks5" on-icon="pi pi-check" off-icon="pi pi-times"
                    :on-label="t('off_text')" :off-label="t('on_text')" class="w-48" />
                  <div v-if="curNetwork.enable_socks5" class="items-center flex flex-row gap-x-4">
                    <div class="min-w-64 w-full">
                      <InputNumber id="socks5_port" v-model="curNetwork.socks5_port" aria-describedby="rpc_port-help"
                        :format="false" :allow-empty="false" :min="0" :max="65535" class="w-full" />
                    </div>
                  </div>
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <div class="flex">
                    <label for="exit_nodes">{{ t('exit_nodes') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('exit_nodes_help')"></span>
                  </div>
                  <AutoComplete id="exit_nodes" v-model="curNetwork.exit_nodes"
                    :placeholder="t('chips_placeholder', ['192.168.8.8'])" class="w-full" multiple fluid
                    :suggestions="exitNodesSuggestions" @complete="searchExitNodesSuggestions" />
                </div>
              </div>

              <div class="flex flex-row gap-x-9 flex-wrap w-full">
                <div class="flex flex-col gap-2 grow p-fluid">
                  <div class="flex">
                    <label for="mapped_listeners">{{ t('mapped_listeners') }}</label>
                    <span class="pi pi-question-circle ml-2 self-center" v-tooltip="t('mapped_listeners_help')"></span>
                  </div>
                  <AutoComplete id="mapped_listeners" v-model="curNetwork.mapped_listeners"
                    :placeholder="t('chips_placeholder', ['tcp://123.123.123.123:11223'])" class="w-full" multiple fluid
                    :suggestions="peerSuggestions" @complete="searchPeerSuggestions" />
                </div>
              </div>

            </div>
          </Panel>

          <div class="flex pt-6 justify-center">
            <Button :label="t('run_network')" icon="pi pi-arrow-right" icon-pos="right" :disabled="configInvalid"
              @click="$emit('runNetwork', curNetwork)" />
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
