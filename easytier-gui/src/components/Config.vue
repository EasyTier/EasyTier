<script setup lang="ts">
import InputGroup from "primevue/inputgroup";
import InputGroupAddon from "primevue/inputgroupaddon";
import { ref, defineProps, computed } from "vue";
import { i18n, useNetworkStore, NetworkingMethod } from "../main";


const networking_methods = ref([
  { value: NetworkingMethod.PublicServer, label: i18n.global.t('public_server') },
  { value: NetworkingMethod.Manual, label: i18n.global.t('manual') },
  { value: NetworkingMethod.Standalone, label: i18n.global.t('standalone') },
]);

const props = defineProps<{
  configInvalid?: boolean,
  instanceId?: string,
}>()

defineEmits(["runNetwork"]);

const networkStore = useNetworkStore();
const curNetwork = computed(() => {
  if (props.instanceId) {
    console.log("instanceId", props.instanceId);
    const c = networkStore.networkList.find(n => n.instance_id == props.instanceId);
    if (c != undefined) {
      return c;
    }
  }

  return networkStore.curNetwork;
});

const presetPublicServers = [
  "tcp://easytier.public.kkrainbow.top:11010",
];

</script>

<template>
  <div class="flex flex-column h-full">
    <div class="flex flex-column">
      <div class="w-10/12 max-w-fit self-center ">
        <Panel header="Basic Settings">

          <div class="flex flex-column gap-y-2">

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="virtual_ip">{{ $t('virtual_ipv4') }}</label>
                <InputGroup>
                  <InputText id="virtual_ip" v-model="curNetwork.virtual_ipv4" aria-describedby="virtual_ipv4-help" />
                  <InputGroupAddon>
                    <span>/24</span>
                  </InputGroupAddon>
                </InputGroup>
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="network_name">{{ $t('network_name') }}</label>
                <InputText id="network_name" v-model="curNetwork.network_name" aria-describedby="network_name-help" />
              </div>
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="network_secret">{{ $t('network_secret') }}</label>
                <InputText id="network_secret" v-model="curNetwork.network_secret"
                  aria-describedby=" network_secret-help" />
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="nm">{{ $t('networking_method') }}</label>
                <div class="items-center flex flex-row p-fluid gap-x-1">
                  <Dropdown v-model="curNetwork.networking_method" :options="networking_methods" optionLabel="label"
                    optionValue="value" placeholder="Select Method" class="" />
                  <Chips id="chips" v-model="curNetwork.peer_urls"
                    :placeholder="$t('chips_placeholder', ['tcp://8.8.8.8:11010'])" separator=" " class="grow"
                    v-if="curNetwork.networking_method == NetworkingMethod.Manual" />

                  <Dropdown :editable="true" v-model="curNetwork.public_server_url" class="grow"
                    :options="presetPublicServers"
                    v-if="curNetwork.networking_method == NetworkingMethod.PublicServer" />
                </div>
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap w-full">
              <div class="flex flex-column gap-2 grow p-fluid">
                <label for="username">{{ $t('proxy_cidrs') }}</label>
                <Chips id="chips" v-model="curNetwork.proxy_cidrs"
                  :placeholder="$t('chips_placeholder', ['10.0.0.0/24'])" separator=" " class="w-full" />
              </div>
            </div>

            <div class="flex flex-row gap-x-9 flex-wrap ">
              <div class="flex flex-column gap-2 grow">
                <label for="username">VPN Portal</label>
                <div class="items-center flex flex-row gap-x-4">
                  <ToggleButton onIcon="pi pi-check" offIcon="pi pi-times" v-model="curNetwork.enable_vpn_portal"
                    :onLabel="$t('off_text')" :offLabel="$t('on_text')" />
                  <div class="grow" v-if="curNetwork.enable_vpn_portal">
                    <InputGroup>
                      <InputText :placeholder="$t('vpn_portal_client_network')"
                        v-model="curNetwork.vpn_portal_client_network_addr" />
                      <InputGroupAddon>
                        <span>/{{ curNetwork.vpn_portal_client_network_len }}</span>
                      </InputGroupAddon>
                    </InputGroup>
                  </div>
                  <InputNumber :placeholder="$t('vpn_portal_listen_port')" class="" v-if="curNetwork.enable_vpn_portal"
                    :format="false" v-model="curNetwork.vpn_portal_listne_port" :min="0" :max="65535" />
                </div>
              </div>
            </div>
          </div>

        </Panel>

        <Divider />

        <Panel :header="$t('advanced_settings')" toggleable>
          <div class="flex flex-column gap-y-2">
            <div class="flex flex-row gap-x-9 flex-wrap w-full">
              <div class="flex flex-column gap-2 grow p-fluid">
                <label for="listener_urls">{{ $t('listener_urls') }}</label>
                <Chips id="listener_urls" v-model="curNetwork.listener_urls"
                  :placeholder="$t('chips_placeholder', ['tcp://1.1.1.1:11010'])" separator=" " class="w-full" />
              </div>
            </div>


            <div class="flex flex-row gap-x-9 flex-wrap">
              <div class="flex flex-column gap-2 basis-5/12 grow">
                <label for="rpc_port">{{ $t('rpc_port') }}</label>
                <InputNumber id="rpc_port" v-model="curNetwork.rpc_port" aria-describedby="username-help"
                  :format="false" :min="0" :max="65535" />
              </div>
            </div>
          </div>
        </Panel>

        <Divider />


        <div class="flex pt-4 justify-content-center">
          <Button label="Run Network" icon="pi pi-arrow-right" iconPos="right" @click="$emit('runNetwork', curNetwork)"
            :disabled="configInvalid" />
        </div>
      </div>
    </div>
  </div>
</template>
