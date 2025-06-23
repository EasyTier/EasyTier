<script setup lang="ts">
import { IftaLabel, Select, Button, ConfirmPopup, useConfirm, useToast, Divider, Menu } from 'primevue';
import { NetworkTypes, Status, Utils, Api, ConfigEditDialog } from 'easytier-frontend-lib';
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
const showConfigEditDialog = ref(false);
const isCreatingNetwork = ref(false); // Flag to indicate if we're in network creation mode
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

    if (disabled || !disabledNetworkConfig.value) {
        await props.api?.update_device_instance_state(deviceId.value, selectedInstanceId.value.uuid, disabled);
    } else if (disabledNetworkConfig.value) {
        await props.api?.delete_network(deviceId.value, disabledNetworkConfig.value.instance_id);
        await props.api?.run_network(deviceId.value, disabledNetworkConfig.value);
    }
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
    isCreatingNetwork.value = false; // Exit creation mode after successful network creation
}

const newNetwork = () => {
    newNetworkConfig.value = NetworkTypes.DEFAULT_NETWORK_CONFIG();
    newNetworkConfig.value.hostname = deviceInfo.value?.hostname;
    isEditing.value = false;
    // showCreateNetworkDialog.value = true; // Old dialog approach
    isCreatingNetwork.value = true; // Switch to creation mode instead
}

const cancelNetworkCreation = () => {
    isCreatingNetwork.value = false;
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
        // showCreateNetworkDialog.value = true; // Old dialog approach
        isCreatingNetwork.value = true; // Switch to creation mode instead
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
        let networkConfig = await props.api?.get_network_config(deviceId.value, instanceId.value);
        delete networkConfig.instance_id;
        let { toml_config: tomlConfig, error } = await props.api?.generate_config({
            config: networkConfig
        });
        if (error) {
            throw { response: { data: error } };
        }
        exportTomlFile(tomlConfig ?? '', instanceId.value + '.toml');
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
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (e) => {
        try {
            let tomlConfig = e.target?.result?.toString();
            if (!tomlConfig) return;
            const resp = await props.api?.parse_config({ toml_config: tomlConfig });
            if (resp.error) {
                throw resp.error;
            }

            const config = resp.config;
            if (!config) return;

            config.instance_id = newNetworkConfig.value?.instance_id ?? config?.instance_id;

            Object.assign(newNetworkConfig.value, resp.config);
            toast.add({ severity: 'success', summary: 'Import Success', detail: "Config file import success", life: 2000 });
        } catch (error) {
            toast.add({ severity: 'error', summary: 'Error', detail: 'Config file parse error: ' + error, life: 2000 });
        }
        configFile.value.value = null;
    }
    reader.readAsText(file);
}

const exportTomlFile = (context: string, name: string) => {
    let url = window.URL.createObjectURL(new Blob([context], { type: 'application/toml' }));
    let link = document.createElement('a');
    link.style.display = 'none';
    link.href = url;
    link.setAttribute('download', name);
    document.body.appendChild(link);
    link.click();

    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
}

const generateConfig = async (config: NetworkTypes.NetworkConfig): Promise<string> => {
    let { toml_config: tomlConfig, error } = await props.api?.generate_config({ config });
    if (error) {
        throw error;
    }
    return tomlConfig ?? '';
}

const saveConfig = async (tomlConfig: string): Promise<void> => {
    let resp = await props.api?.parse_config({ toml_config: tomlConfig });
    if (resp.error) {
        throw resp.error;
    };
    const config = resp.config;
    if (!config) {
        throw new Error("Parsed config is empty");
    }
    config.instance_id = disabledNetworkConfig.value?.instance_id ?? config?.instance_id;
    if (networkIsDisabled.value) {
        disabledNetworkConfig.value = config;
    } else {
        newNetworkConfig.value = config;
    }
}

// 响应式屏幕宽度
const screenWidth = ref(window.innerWidth);
const updateScreenWidth = () => {
    screenWidth.value = window.innerWidth;
};

// 菜单引用和菜单项
const menuRef = ref();
const actionMenu = ref([
    { 
        label: '编辑网络', 
        icon: 'pi pi-pencil',
        command: () => editNetwork() 
    },
    { 
        label: '导出配置', 
        icon: 'pi pi-download',
        command: () => exportConfig() 
    },
    { 
        label: '删除网络',
        icon: 'pi pi-trash',
        class: 'p-error',
        command: () => confirmDeleteNetwork(new Event('click')) 
    }
]);

let periodFunc = new Utils.PeriodicTask(async () => {
    try {
        await Promise.all([loadNetworkInstanceIds(), loadDeviceInfo()]);
    } catch (e) {
        console.debug(e);
    }
}, 1000);

onMounted(async () => {
    periodFunc.start();
    
    // 添加屏幕尺寸监听
    window.addEventListener('resize', updateScreenWidth);
});

onUnmounted(() => {
    periodFunc.stop();
    
    // 移除屏幕尺寸监听
    window.removeEventListener('resize', updateScreenWidth);
});

</script>

<template>
    <div class="device-management">
        <input type="file" @change="handleFileUpload" class="hidden" accept="application/toml" ref="configFile" />
        <ConfirmPopup></ConfirmPopup>

        <!-- 网络选择和操作按钮始终在同一行 -->
        <div class="network-header bg-surface-50 p-3 rounded-lg shadow-sm mb-1">
            <div class="flex flex-row justify-between items-center gap-2" style="align-items: center;">
                <!-- 网络选择 -->
                <div class="flex-1 min-w-0">
                    <IftaLabel class="w-full">
                        <Select v-model="selectedInstanceId" :options="instanceIdList" optionLabel="uuid" 
                            class="w-full" inputId="dd-inst-id" placeholder="Select Network"
                            :pt="{ root: { class: 'network-select-container' } }" />
                        <label class="network-label mr-2 font-medium" for="dd-inst-id">Network</label>
                    </IftaLabel>
                </div>
                
                <!-- 简化的按钮区域 - 无论屏幕大小都显示 -->
                <div class="flex gap-2 shrink-0 button-container items-center">
                    <!-- Create/Cancel button based on state -->
                    <Button v-if="!isCreatingNetwork" 
                        @click="newNetwork" 
                        icon="pi pi-plus" 
                        :label="screenWidth > 640 ? 'Create New' : undefined" 
                        :class="['create-button', screenWidth <= 640 ? 'p-button-icon-only' : '']"
                        :style="screenWidth <= 640 ? 'width: 3rem !important; height: 3rem !important; font-size: 1.2rem' : ''"
                        :tooltip="screenWidth <= 640 ? 'Create New Network' : undefined"
                        tooltipOptions="{ position: 'bottom' }"
                        severity="primary" />
                    
                    <Button v-else
                        @click="cancelNetworkCreation" 
                        icon="pi pi-times" 
                        :label="screenWidth > 640 ? 'Cancel' : undefined" 
                        :class="['cancel-button', screenWidth <= 640 ? 'p-button-icon-only' : '']"
                        :style="screenWidth <= 640 ? 'width: 3rem !important; height: 3rem !important; font-size: 1.2rem' : ''"
                        :tooltip="screenWidth <= 640 ? 'Cancel Creation' : undefined"
                        tooltipOptions="{ position: 'bottom' }"
                        severity="secondary" />
                    
                    <!-- More actions menu -->
                    <Menu ref="menuRef" :model="actionMenu" :popup="true" />
                    <Button v-if="!isCreatingNetwork && selectedInstanceId"
                        icon="pi pi-ellipsis-v" 
                        class="p-button-rounded flex items-center justify-center" 
                        severity="help"
                        style="width: 3rem !important; height: 3rem !important; font-size: 1.2rem"
                        @click="menuRef.toggle($event)"
                        :aria-label="'More Actions'"
                        :tooltip="'More Actions'"
                        tooltipOptions="{ position: 'bottom' }" />
                </div>
            </div>
        </div>

        <!-- Main Content Area -->
        <div class="network-content bg-surface-0 p-4 rounded-lg shadow-sm">
            <!-- Network Creation Form -->
            <div v-if="isCreatingNetwork" class="network-creation-container">
                <div class="network-creation-header flex items-center gap-2 mb-3">
                    <i class="pi pi-plus-circle text-primary text-xl"></i>
                    <h2 class="text-xl font-medium">{{ isEditing ? 'Edit Network' : 'Create New Network' }}</h2>
                </div>
                
                <div class="w-full flex gap-2 flex-wrap justify-start mb-3">
                    <Button @click="showConfigEditDialog = true" icon="pi pi-file-edit" 
                        label="Edit as File" iconPos="left" severity="secondary" />
                    <Button @click="importConfig" icon="pi pi-upload" 
                        label="Import Config" iconPos="left" severity="help" />
                </div>
                
                <Divider />
                
                <Config :cur-network="newNetworkConfig" @run-network="createNewNetwork"></Config>
            </div>

            <!-- Network Status (for running networks) -->
            <div v-else-if="needShowNetworkStatus" class="network-status-container">
                <div class="network-status-header flex items-center gap-2 mb-3">
                    <i class="pi pi-chart-line text-primary text-xl"></i>
                    <h2 class="text-xl font-medium">Network Status</h2>
                </div>
                
                <Status v-bind:cur-network-inst="curNetworkInfo" class="mb-4"></Status>
                
                <div class="text-center mt-4">
                    <Button @click="updateNetworkState(true)" label="Disable Network" 
                        severity="warning" icon="pi pi-power-off" iconPos="left" />
                </div>
            </div>

            <!-- Network Configuration (for disabled networks) -->
            <div v-else-if="networkIsDisabled" class="network-config-container">
                <div class="network-config-header flex items-center gap-2 mb-3">
                    <i class="pi pi-cog text-secondary text-xl"></i>
                    <h2 class="text-xl font-medium">Network Configuration</h2>
                </div>
                
                <div v-if="disabledNetworkConfig" class="mb-4">
                    <Config :cur-network="disabledNetworkConfig" @run-network="updateNetworkState(false)" />
                </div>
                <div v-else class="network-loading-placeholder text-center py-8">
                    <i class="pi pi-spin pi-spinner text-3xl text-primary mb-3"></i>
                    <div class="text-xl text-secondary">Loading network configuration...</div>
                </div>
            </div>

            <!-- Empty State -->
            <div v-else class="empty-state flex flex-col items-center py-12">
                <i class="pi pi-sitemap text-5xl text-secondary mb-4 opacity-50"></i>
                <div class="text-xl text-center font-medium mb-3">No Network Selected</div>
                <p class="text-secondary text-center mb-6 max-w-md">
                    Select an existing network instance or create a new one to manage network settings
                </p>
                <Button @click="newNetwork" label="Create Network" icon="pi pi-plus" iconPos="left" />
            </div>
        </div>
        
        <!-- Keep only the config edit dialogs -->
        <ConfigEditDialog v-if="networkIsDisabled" v-model:visible="showCreateNetworkDialog"
            :cur-network="disabledNetworkConfig" :generate-config="generateConfig" :save-config="saveConfig" />
            
        <ConfigEditDialog v-else v-model:visible="showConfigEditDialog" :cur-network="newNetworkConfig"
            :generate-config="generateConfig" :save-config="saveConfig" />
    </div>
</template>

<style scoped>
.device-management {
    height: 100%;
    display: flex;
    flex-direction: column;
}

.network-content {
    flex: 1;
    overflow-y: auto;
}

/* 按钮样式 */
.button-container {
    gap: 0.5rem;
}

.create-button {
    font-weight: 600;
    min-width: 3rem;
}

/* 菜单样式定制 */
:deep(.p-menu) {
    min-width: 12rem;
    box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.15);
    padding: 0.25rem;
}

:deep(.p-menu .p-menuitem) {
    border-radius: 0.25rem;
}

:deep(.p-menu .p-menuitem-link) {
    padding: 0.65rem 1rem;
    font-size: 0.9rem;
}

:deep(.p-menu .p-menuitem-icon) {
    margin-right: 0.75rem;
}

:deep(.p-menu .p-menuitem.p-error .p-menuitem-text,
      .p-menu .p-menuitem.p-error .p-menuitem-icon) {
    color: var(--red-500);
}

:deep(.p-menu .p-menuitem:hover.p-error .p-menuitem-link) {
    background-color: var(--red-50);
}

/* 按钮图标样式 */
:deep(.p-button-icon-only) {
    width: 2.5rem !important;
    padding: 0.5rem !important;
}

:deep(.p-button-icon-only .p-button-icon) {
    font-size: 1rem;
}

/* 网络选择相关样式 */
.network-label {
    white-space: nowrap;
}

:deep(.network-select-container) {
    max-width: 100%;
}

/* Dark mode adaptations */
:deep(.bg-surface-50) {
    background-color: var(--surface-50, #f8fafc);
}

:deep(.bg-surface-0) {
    background-color: var(--surface-card, #ffffff);
}

:deep(.text-primary) {
    color: var(--primary-color, #3b82f6);
}

:deep(.text-secondary) {
    color: var(--text-color-secondary, #64748b);
}

@media (prefers-color-scheme: dark) {
    :deep(.bg-surface-50) {
        background-color: var(--surface-ground, #0f172a);
    }
    
    :deep(.bg-surface-0) {
        background-color: var(--surface-card, #1e293b);
    }
}

/* Responsive design for mobile devices */
@media (max-width: 768px) {
    .network-header {
        padding: 0.75rem;
    }
    
    .network-content {
        padding: 0.75rem;
    }
    
    /* 在小屏幕上缩短网络标签文本 */
    .network-label {
        font-size: 0.9rem;
    }
}
</style>