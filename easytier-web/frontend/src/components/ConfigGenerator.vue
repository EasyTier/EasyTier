<script setup lang="ts">
import { NetworkTypes } from 'easytier-frontend-lib';
import { ref } from 'vue';
import { Api } from 'easytier-frontend-lib'

const defaultApiHost = 'https://config-server.easytier.cn'
const api = new Api.ApiClient(defaultApiHost);

const newNetworkConfig = ref<NetworkTypes.NetworkConfig>(NetworkTypes.DEFAULT_NETWORK_CONFIG());
const toml_config = ref<string>("Press 'Run Network' to generate TOML configuration");

const generateConfig = (config: NetworkTypes.NetworkConfig) => {
    api.generate_config({
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
                <Config :cur-network="newNetworkConfig" @run-network="generateConfig" />
            </div>
            <div class="sm:w-full md:w-1/2 p-4 bg-gray-100">
                <pre class="whitespace-pre-wrap">{{ toml_config }}</pre>
            </div>
        </div>
    </div>
</template>
