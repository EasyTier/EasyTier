<script setup lang="ts">
import {Toolbar, IftaLabel, Select, Button, ConfirmPopup, Dialog, useConfirm, useToast, Divider} from 'primevue';
import { NetworkTypes, Status, Utils, Api, } from 'easytier-frontend-lib';
import { watch, computed, onMounted, onUnmounted, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';

const props = defineProps<{
    api: Api.ApiClient;
    deviceList: Array<Utils.DeviceInfo> | undefined;
}>();

const emits = defineEmits(['update']);

const route = useRoute();
const router = useRouter();
const toast = useToast();

const deviceId = computed<string>(() => {
    return route.params.deviceId as string;
});

const instanceId = computed<string>(() => {
    return route.params.instanceId as string;
});

const deviceInfo = computed<Utils.DeviceInfo | undefined | null>(() => {
    return deviceId.value ? props.deviceList?.find((device) => device.machine_id === deviceId.value) : null;
});

const configFile = ref();

const curNetworkInfo = ref<NetworkTypes.NetworkInstance | null>(null);

const isEditing = ref(false);
const showCreateNetworkDialog = ref(false);
const newNetworkConfig = ref<NetworkTypes.NetworkConfig>(NetworkTypes.DEFAULT_NETWORK_CONFIG());

const listInstanceIdResponse = ref<Api.ListNetworkInstanceIdResponse | undefined>(undefined);

const instanceIdList = computed(() => {
    let insts = new Set(deviceInfo.value?.running_network_instances || []);
    let t = listInstanceIdResponse.value;
    if (t) {
        t.running_inst_ids.forEach((u) => insts.add(Utils.UuidToStr(u)));
        t.disabled_inst_ids.forEach((u) => insts.add(Utils.UuidToStr(u)));
    }
    let options = Array.from(insts).map((instance: string) => {
        return { uuid: instance };
    });
    return options;
});

const selectedInstanceId = computed({
    get() {
        return instanceIdList.value.find((instance) => instance.uuid === instanceId.value);
    },
    set(value: any) {
        console.log("set instanceId", value);
        router.push({ name: 'deviceManagement', params: { deviceId: deviceId.value, instanceId: value.uuid } });
    }
});

const needShowNetworkStatus = computed(() => {
    if (!selectedInstanceId.value) {
        // nothing selected
        return false;
    }
    if (networkIsDisabled.value) {
        // network is disabled
        return false;
    }
    return true;
})

const networkIsDisabled = computed(() => {
    if (!selectedInstanceId.value) {
        return false;
    }
    return listInstanceIdResponse.value?.disabled_inst_ids.map(Utils.UuidToStr).includes(selectedInstanceId.value?.uuid);
});

watch(selectedInstanceId, async (newVal, oldVal) => {
    if (newVal?.uuid !== oldVal?.uuid && networkIsDisabled.value) {
        await loadDisabledNetworkConfig();
    }
});

const disabledNetworkConfig = ref<NetworkTypes.NetworkConfig | undefined>(undefined);

const loadDisabledNetworkConfig = async () => {
    disabledNetworkConfig.value = undefined;

    if (!deviceId.value || !selectedInstanceId.value) {
        return;
    }

    let ret = await props.api?.get_network_config(deviceId.value, selectedInstanceId.value.uuid);
    disabledNetworkConfig.value = ret;
}

const updateNetworkState = async (disabled: boolean) => {
    if (!deviceId.value || !selectedInstanceId.value) {
        return;
    }

    await props.api?.update_device_instance_state(deviceId.value, selectedInstanceId.value.uuid, disabled);
    await loadNetworkInstanceIds();
}

const confirm = useConfirm();
const confirmDeleteNetwork = (event: any) => {
    confirm.require({
        target: event.currentTarget,
        message: 'Do you want to delete this network?',
        icon: 'pi pi-info-circle',
        rejectProps: {
            label: 'Cancel',
            severity: 'secondary',
            outlined: true
        },
        acceptProps: {
            label: 'Delete',
            severity: 'danger'
        },
        accept: async () => {
            try {
                await props.api?.delete_network(deviceId.value, instanceId.value);
            } catch (e) {
                console.error(e);
            }
            emits('update');
        },
        reject: () => {
            return;
        }
    });
};

// const verifyNetworkConfig = async (): Promise<ValidateConfigResponse | undefined> => {
//     let ret = await props.api?.validate_config(deviceId.value, newNetworkConfig.value);
//     console.log("verifyNetworkConfig", ret);
//     return ret;
// }

const createNewNetwork = async () => {
    try {
        if (isEditing.value) {
            await props.api?.delete_network(deviceId.value, instanceId.value);
        }
        let ret = await props.api?.run_network(deviceId.value, newNetworkConfig.value);
        console.debug("createNewNetwork", ret);
    } catch (e: any) {
        console.error(e);
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to create network, error: ' + JSON.stringify(e.response.data), life: 2000 });
        return;
    }
    emits('update');
    showCreateNetworkDialog.value = false;
}

const newNetwork = () => {
    newNetworkConfig.value = NetworkTypes.DEFAULT_NETWORK_CONFIG();
    newNetworkConfig.value.hostname = deviceInfo.value?.hostname;
    isEditing.value = false;
    showCreateNetworkDialog.value = true;
}

const editNetwork = async () => {
    if (!deviceId.value || !instanceId.value) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'No network instance selected', life: 2000 });
        return;
    }

    isEditing.value = true;

    try {
        let ret = await props.api?.get_network_config(deviceId.value, instanceId.value);
        console.debug("editNetwork", ret);
        newNetworkConfig.value = ret;
        showCreateNetworkDialog.value = true;
    } catch (e: any) {
        console.error(e);
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to edit network, error: ' + JSON.stringify(e.response.data), life: 2000 });
        return;
    }
}

const loadNetworkInstanceIds = async () => {
    if (!deviceId.value) {
        return;
    }

    listInstanceIdResponse.value = await props.api?.list_deivce_instance_ids(deviceId.value);
    console.debug("loadNetworkInstanceIds", listInstanceIdResponse.value);
}

const loadDeviceInfo = async () => {
    if (!deviceId.value || !instanceId.value) {
        return;
    }

    let ret = await props.api?.get_network_info(deviceId.value, instanceId.value);
    let device_info = ret[instanceId.value];

    curNetworkInfo.value = {
        instance_id: instanceId.value,
        running: device_info.running,
        error_msg: device_info.error_msg,
        detail: device_info,
    } as NetworkTypes.NetworkInstance;
}

const exportConfig = async () => {
  if (!deviceId.value || !instanceId.value) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'No network instance selected', life: 2000 });
    return;
  }

  try {
    let ret = await props.api?.get_network_config(deviceId.value, instanceId.value);
    delete ret.instance_id;
    exportJsonFile(JSON.stringify(ret, null, 2),instanceId.value +'.json');
  } catch (e: any) {
    console.error(e);
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to export network config, error: ' + JSON.stringify(e.response.data), life: 2000 });
    return;
  }
}

const importConfig = () => {
  configFile.value.click();
}

const handleFileUpload = (event: Event) => {
  const files = (event.target as HTMLInputElement).files;
  const file = files ? files[0] : null;
  if (file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        let str = e.target?.result?.toString();
        if(str){
          const config = JSON.parse(str);
          if(config === null || typeof config !== "object"){
            throw new Error();
          }
          Object.assign(newNetworkConfig.value, config);
          toast.add({ severity: 'success', summary: 'Import Success', detail: "Config file import success", life: 2000 });
        }
      } catch (error) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'Config file parse error.', life: 2000 });
      }
      configFile.value.value = null;
    }
    reader.readAsText(file);
  }
}

const exportJsonFile = (context: string, name: string) => {
  let url = window.URL.createObjectURL(new Blob([context], { type: 'application/json' }));
  let link = document.createElement('a');
  link.style.display = 'none';
  link.href = url;
  link.setAttribute('download', name);
  document.body.appendChild(link);
  link.click();

  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}

let periodFunc = new Utils.PeriodicTask(async () => {
    try {
        await Promise.all([loadNetworkInstanceIds(), loadDeviceInfo()]);
    } catch (e) {
        console.debug(e);
    }
}, 1000);

onMounted(async () => {
    periodFunc.start();
});

onUnmounted(() => {
    periodFunc.stop();
});

</script>

<template>
    <input type="file" @change="handleFileUpload" class="hidden" accept="application/json" ref="configFile"/>
    <ConfirmPopup></ConfirmPopup>
    <Dialog v-model:visible="showCreateNetworkDialog" modal :header="!isEditing ? 'Create New Network' : 'Edit Network'"
        :style="{ width: '55rem' }">
        <div class="flex flex-col">
          <div class="w-11/12 self-center ">
            <Button @click="importConfig" icon="pi pi-file-import" label="Import" iconPos="right" />
            <Divider />
          </div>
        </div>
        <Config :cur-network="newNetworkConfig" @run-network="createNewNetwork"></Config>
    </Dialog>

    <Toolbar>
        <template #start>
            <IftaLabel>
                <Select v-model="selectedInstanceId" :options="instanceIdList" optionLabel="uuid" inputId="dd-inst-id"
                    placeholder="Select Instance" />
                <label class="mr-3" for="dd-inst-id">Network</label>
            </IftaLabel>
        </template>

        <template #end>
            <div class="gap-x-3 flex">
                <Button @click="confirmDeleteNetwork($event)" icon="pi pi-minus" severity="danger" label="Delete"
                    iconPos="right" />
                <Button @click="exportConfig" icon="pi pi-file-export" severity="help" label="Export" iconPos="right" />
                <Button @click="editNetwork" icon="pi pi-pen-to-square" label="Edit" iconPos="right" severity="info" />
                <Button @click="newNetwork" icon="pi pi-plus" label="Create" iconPos="right" />
            </div>
        </template>
    </Toolbar>

    <Divider />

    <!-- For running network, show the status -->
    <div v-if="needShowNetworkStatus">
        <Status v-bind:cur-network-inst="curNetworkInfo" v-if="needShowNetworkStatus">
        </Status>
        <Divider />
        <div class="text-center">
          <Button @click="updateNetworkState(true)" label="Disable Network" severity="warn" />
        </div>
    </div>

    <!-- For disabled network, show the config -->
    <div v-if="networkIsDisabled">
        <Config :cur-network="disabledNetworkConfig" @run-network="updateNetworkState(false)"
            v-if="disabledNetworkConfig" />
        <div v-else>
            <div class="text-center text-xl"> Network is disabled, Loading config... </div>
        </div>
    </div>

    <div class="grid grid-cols-1 gap-4 place-content-center h-full" v-if="!selectedInstanceId">
        <div class="text-center text-xl"> Select or create a network instance to manage </div>
    </div>
</template>