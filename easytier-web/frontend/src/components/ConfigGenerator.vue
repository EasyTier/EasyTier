<script setup lang="ts">
import { NetworkTypes } from 'easytier-frontend-lib';
import {computed, ref} from 'vue';
import { Api } from 'easytier-frontend-lib'
import {AutoComplete, Divider} from "primevue";
import {getInitialApiHost, cleanAndLoadApiHosts, saveApiHost} from "../modules/api-host"

const api = computed<Api.ApiClient>(() => new Api.ApiClient(apiHost.value));


const apiHost = ref<string>(getInitialApiHost())
const apiHostSuggestions = ref<Array<string>>([])
const apiHostSearch = async (event: { query: string }) => {
  apiHostSuggestions.value = [];
  let hosts = cleanAndLoadApiHosts();
  if (event.query) {
    apiHostSuggestions.value.push(event.query);
  }
  hosts.forEach((host) => {
    apiHostSuggestions.value.push(host.value);
  });
}

const newNetworkConfig = ref<NetworkTypes.NetworkConfig>(NetworkTypes.DEFAULT_NETWORK_CONFIG());
const toml_config = ref<string>("Press 'Run Network' to generate TOML configuration");

const generateConfig = (config: NetworkTypes.NetworkConfig) => {
  saveApiHost(apiHost.value)
  api.value?.generate_config({
        config: config
    }).then((res) => {
        if (res.error) {
            toml_config.value = res.error;
        } else if (res.toml_config) {
            toml_config.value = res.toml_config;
        } else {
            toml_config.value = "Api server returned an unexpected response";
        }
    });
};

</script>

<template>
    <div class="flex items-center justify-center m-5">
        <div class="sm:block md:flex w-full">
            <div class="sm:w-full md:w-1/2 p-4">
                <div class="flex flex-col">
                  <div class="w-11/12 self-center ">
                    <label>ApiHost</label>
                    <AutoComplete id="api-host" v-model="apiHost" dropdown :suggestions="apiHostSuggestions"
                                  @complete="apiHostSearch" class="w-full" />
                    <Divider />
                  </div>
                </div>
                <Config :cur-network="newNetworkConfig" @run-network="generateConfig" />
            </div>
            <div class="sm:w-full md:w-1/2 p-4 bg-gray-100">
                <pre class="whitespace-pre-wrap">{{ toml_config }}</pre>
            </div>
        </div>
    </div>
</template>
