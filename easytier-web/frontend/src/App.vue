<script setup lang="ts">

import { Config, I18nUtils, NetworkTypes } from 'easytier-frontend-lib'
import { onMounted, ref } from 'vue';
import { Panel } from 'primevue';

onMounted(async () => {
  await I18nUtils.loadLanguageAsync('cn')
});

const curNetwork = ref(NetworkTypes.DEFAULT_NETWORK_CONFIG())

const runNetwork = async () => {
  alert('runNetwork' + curNetwork.value.network_name)
}

const abc = ref('fuckfjdlksajkfldsjlk')

</script>

<template>
  <div id="root" class="flex flex-column">
    <div class="h-full overflow-y-auto">
      <Panel header="fuck">
        <Config v-model:curNetwork="curNetwork" v-on:runNetwork="runNetwork" />
      </Panel>
    </div>
  </div>
</template>

<style scoped></style>
