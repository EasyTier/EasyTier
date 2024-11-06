<script setup lang="ts">

import { Config, I18nUtils, NetworkTypes } from 'easytier-frontend-lib'
import { onMounted, ref } from 'vue';
import Login from './components/Login.vue'
import MenuBar from './components/MenuBar.vue';

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
  <div id="root" class="">
    <div id="login">
      <MenuBar />
      <Login></Login>
    </div>

    <div class="h-full overflow-y-auto">
      <Config v-model:curNetwork="curNetwork" v-on:runNetwork="runNetwork" />
    </div>
  </div>
</template>

<style scoped></style>
