<script setup lang="ts">
import { Button, ConfirmPopup, Divider, IftaLabel, Menu, Message, Select, Tag, useConfirm, useToast } from 'primevue';
import { computed, onMounted, onUnmounted, Ref, ref, watch } from 'vue';
import { useI18n } from 'vue-i18n';
import * as Api from '../modules/api';
import * as Utils from '../modules/utils';
import * as NetworkTypes from '../types/network';
import { type MenuItem } from 'primevue/menuitem';

const { t } = useI18n()

const props = defineProps<{
    api: Api.RemoteClient;
    newConfigGenerator?: () => NetworkTypes.NetworkConfig;
}>();

const instanceId = defineModel('instanceId', {
    type: String as () => string | undefined,
    required: false,
})

const emits = defineEmits(['update']);

const toast = useToast();

const configFile = ref();

const curNetworkInfo = ref<NetworkTypes.NetworkInstance | null>(null);

const showConfigEditDialog = ref(false);
const isEditingNetwork = ref(false); // Flag to indicate if we're in network editing mode
const currentNetworkConfig = ref<NetworkTypes.NetworkConfig | undefined>(undefined);

const listInstanceIdResponse = ref<Api.ListNetworkInstanceIdResponse | undefined>(undefined);

const isRunning = (instanceId: string) => {
    return listInstanceIdResponse.value?.running_inst_ids.map(Utils.UuidToStr).includes(instanceId);
}

const instanceIdList = computed(() => {
    let insts = new Set<string>();
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
        instanceId.value = value ? value.uuid : undefined;
    }
});
watch(selectedInstanceId, async (newVal, oldVal) => {
    if (newVal?.uuid !== oldVal?.uuid && (networkIsDisabled.value || isEditingNetwork.value)) {
        await loadCurrentNetworkConfig();
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
watch(networkIsDisabled, async (newVal, oldVal) => {
    if (newVal !== oldVal && newVal === true) {
        await loadCurrentNetworkConfig();
    }
});

const loadCurrentNetworkConfig = async () => {
    currentNetworkConfig.value = undefined;

    if (!selectedInstanceId.value) {
        return;
    }

    let ret = await props.api.get_network_config(selectedInstanceId.value.uuid);
    currentNetworkConfig.value = ret;
}

const updateNetworkState = async (disabled: boolean) => {
    if (!selectedInstanceId.value) {
        return;
    }

    if (disabled || !currentNetworkConfig.value) {
        await props.api.update_network_instance_state(selectedInstanceId.value.uuid, disabled);
    } else if (currentNetworkConfig.value) {
        await props.api.delete_network(currentNetworkConfig.value.instance_id);
        await props.api.run_network(currentNetworkConfig.value);
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
                await props.api.delete_network(instanceId.value!);
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

const saveAndRunNewNetwork = async () => {
    try {
        await props.api.delete_network(instanceId.value!);
        let ret = await props.api.run_network(currentNetworkConfig.value!!);
        console.debug("saveAndRunNewNetwork", ret);
        selectedInstanceId.value = { uuid: currentNetworkConfig.value!.instance_id };
    } catch (e: any) {
        console.error(e);
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to create network, error: ' + JSON.stringify(e.response.data), life: 2000 });
        return;
    }
    emits('update');
    // showCreateNetworkDialog.value = false;
    isEditingNetwork.value = false; // Exit creation mode after successful network creation
}

const saveNetworkConfig = async () => {
    if (!currentNetworkConfig.value) {
        return;
    }
    await props.api.save_config(currentNetworkConfig.value);
    toast.add({ severity: 'success', summary: t("web.common.success"), detail: t("web.device_management.config_saved"), life: 2000 });
}
const newNetwork = async () => {
    const newNetworkConfig = props.newConfigGenerator?.() ?? NetworkTypes.DEFAULT_NETWORK_CONFIG();
    await props.api.save_config(newNetworkConfig);
    selectedInstanceId.value = { uuid: newNetworkConfig.instance_id };
    currentNetworkConfig.value = newNetworkConfig;
    await loadNetworkInstanceIds();
}

const cancelEditNetwork = () => {
    isEditingNetwork.value = false;
}

const editNetwork = async () => {
    if (!instanceId.value) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'No network instance selected', life: 2000 });
        return;
    }

    try {
        let ret = await props.api.get_network_config(instanceId.value!);
        console.debug("editNetwork", ret);
        currentNetworkConfig.value = ret;
        isEditingNetwork.value = true; // Switch to editing mode instead
    } catch (e: any) {
        console.error(e);
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to edit network, error: ' + JSON.stringify(e.response.data), life: 2000 });
        return;
    }
}

const loadNetworkInstanceIds = async () => {
    listInstanceIdResponse.value = await props.api.list_network_instance_ids();
}

const loadCurrentNetworkInfo = async () => {
    if (!instanceId.value) {
        return;
    }

    let network_info = await props.api.get_network_info(instanceId.value);

    curNetworkInfo.value = {
        instance_id: instanceId.value,
        running: network_info?.running ?? false,
        error_msg: network_info?.error_msg ?? '',
        detail: network_info,
    } as NetworkTypes.NetworkInstance;
}

const exportConfig = async () => {
    if (!instanceId.value) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'No network instance selected', life: 2000 });
        return;
    }

    try {
        const { instance_id, ...networkConfig } = await props.api.get_network_config(instanceId.value!);
        let { toml_config: tomlConfig, error } = await props.api.generate_config(networkConfig as NetworkTypes.NetworkConfig);
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
            const resp = await props.api.parse_config(tomlConfig);
            if (resp.error) {
                throw resp.error;
            }

            const config = resp.config;
            if (!config) return;

            config.instance_id = currentNetworkConfig.value?.instance_id ?? config?.instance_id;
            currentNetworkConfig.value = config;
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
    let { toml_config: tomlConfig, error } = await props.api.generate_config(config);
    if (error) {
        throw error;
    }
    return tomlConfig ?? '';
}

const syncTomlConfig = async (tomlConfig: string): Promise<void> => {
    let resp = await props.api.parse_config(tomlConfig);
    if (resp.error) {
        throw resp.error;
    };
    const config = resp.config;
    if (!config) {
        throw new Error("Parsed config is empty");
    }
    config.instance_id = currentNetworkConfig.value?.instance_id ?? config?.instance_id;
    currentNetworkConfig.value = config;
}

// 响应式屏幕宽度
const screenWidth = ref(window.innerWidth);
const updateScreenWidth = () => {
    screenWidth.value = window.innerWidth;
};

// 菜单引用和菜单项
const menuRef = ref();
const actionMenu: Ref<MenuItem[]> = ref([
    {
        label: t('web.device_management.edit_network'),
        icon: 'pi pi-pencil',
        visible: () => !(networkIsDisabled.value ?? true),
        command: () => editNetwork()
    },
    {
        label: t('web.device_management.export_config'),
        icon: 'pi pi-download',
        command: () => exportConfig()
    },
    {
        label: t('web.device_management.delete_network'),
        icon: 'pi pi-trash',
        class: 'p-error',
        command: () => confirmDeleteNetwork(new Event('click'))
    }
]);

let periodFunc = new Utils.PeriodicTask(async () => {
    try {
        await Promise.all([loadNetworkInstanceIds(), loadCurrentNetworkInfo()]);
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
                        <Select v-model="selectedInstanceId" :options="instanceIdList" optionLabel="uuid" class="w-full"
                            inputId="dd-inst-id" :placeholder="t('web.device_management.select_network')"
                            :pt="{ root: { class: 'network-select-container' } }">
                            <template #value="slotProps">
                                <div v-if="slotProps.value" class="flex items-center content-center min-w-0">
                                    <div class="mr-4 flex-col min-w-0 flex-1">
                                        <span class="truncate block"> &nbsp; {{ slotProps.value.uuid }}</span>
                                    </div>
                                    <Tag class="my-auto leading-3 shrink-0"
                                        :severity="isRunning(slotProps.value.uuid) ? 'success' : 'info'"
                                        :value="t(isRunning(slotProps.value.uuid) ? 'network_running' : 'network_stopped')" />
                                </div>
                                <span v-else>
                                    {{ slotProps.placeholder }}
                                </span>
                            </template>
                            <template #option="slotProps">
                                <div class="flex items-center content-center min-w-0">
                                    <div class="mr-4 flex-col min-w-0 flex-1">
                                        <span class="truncate block"> &nbsp; {{ slotProps.option.uuid }}</span>
                                    </div>
                                    <Tag class="my-auto leading-3 shrink-0"
                                        :severity="isRunning(slotProps.option.uuid) ? 'success' : 'info'"
                                        :value="t(isRunning(slotProps.option.uuid) ? 'network_running' : 'network_stopped')" />
                                </div>
                            </template>
                        </Select>
                        <label class="network-label mr-2 font-medium" for="dd-inst-id">{{
                            t('web.device_management.network') }}</label>
                    </IftaLabel>
                </div>

                <!-- 简化的按钮区域 - 无论屏幕大小都显示 -->
                <div class="flex gap-2 shrink-0 button-container items-center">
                    <!-- Create/Cancel button based on state -->
                    <Button v-if="!isEditingNetwork" @click="newNetwork" icon="pi pi-plus"
                        :label="screenWidth > 640 ? t('web.device_management.create_new') : undefined"
                        :class="['create-button', screenWidth <= 640 ? 'p-button-icon-only' : '']"
                        :style="screenWidth <= 640 ? 'width: 3rem !important; height: 3rem !important; font-size: 1.2rem' : ''"
                        :tooltip="screenWidth <= 640 ? t('web.device_management.create_network') : undefined"
                        tooltipOptions="{ position: 'bottom' }" severity="primary" />

                    <Button v-else @click="cancelEditNetwork" icon="pi pi-times"
                        :label="screenWidth > 640 ? t('web.device_management.cancel_edit') : undefined"
                        :class="['cancel-button', screenWidth <= 640 ? 'p-button-icon-only' : '']"
                        :style="screenWidth <= 640 ? 'width: 3rem !important; height: 3rem !important; font-size: 1.2rem' : ''"
                        :tooltip="screenWidth <= 640 ? t('web.device_management.cancel_edit') : undefined"
                        tooltipOptions="{ position: 'bottom' }" severity="secondary" />

                    <!-- More actions menu -->
                    <Menu ref="menuRef" :model="actionMenu" :popup="true" />
                    <Button v-if="!isEditingNetwork && selectedInstanceId" icon="pi pi-ellipsis-v"
                        class="p-button-rounded flex items-center justify-center" severity="help"
                        style="width: 3rem !important; height: 3rem !important; font-size: 1.2rem"
                        @click="menuRef.toggle($event)" :aria-label="t('web.device_management.more_actions')"
                        :tooltip="t('web.device_management.more_actions')" tooltipOptions="{ position: 'bottom' }" />
                </div>
            </div>
        </div>

        <!-- Main Content Area -->
        <div class="network-content bg-surface-0 p-4 rounded-lg shadow-sm">
            <!-- Network Creation Form -->
            <div v-if="isEditingNetwork || networkIsDisabled" class="network-creation-container">
                <div class="network-creation-header flex items-center gap-2 mb-3">
                    <i class="pi pi-plus-circle text-primary text-xl"></i>
                    <h2 class="text-xl font-medium">{{ t('web.device_management.edit_network') }}</h2>
                </div>

                <div class="w-full flex gap-2 flex-wrap justify-start mb-3">
                    <Button @click="showConfigEditDialog = true" icon="pi pi-file-edit"
                        :label="t('web.device_management.edit_as_file')" iconPos="left" severity="secondary" />
                    <Button @click="importConfig" icon="pi pi-upload" :label="t('web.device_management.import_config')"
                        iconPos="left" severity="help" />
                    <Button v-if="networkIsDisabled" @click="saveNetworkConfig" icon="pi pi-save"
                        :label="t('web.device_management.save_config')" iconPos="left" severity="success" />
                </div>

                <Divider />

                <Config :cur-network="currentNetworkConfig" @run-network="saveAndRunNewNetwork"></Config>
            </div>

            <!-- Network Status (for running networks) -->
            <div v-else-if="needShowNetworkStatus" class="network-status-container">
                <div class="network-status-header flex items-center gap-2 mb-3">
                    <i class="pi pi-chart-line text-primary text-xl"></i>
                    <h2 class="text-xl font-medium">{{ t('web.device_management.network_status') }}</h2>
                </div>

                <Status v-if="(curNetworkInfo?.error_msg ?? '') === ''" v-bind:cur-network-inst="curNetworkInfo"
                    class="mb-4">
                </Status>
                <Message v-else severity="error" class="mb-4">{{ curNetworkInfo?.error_msg }}</Message>

                <div class="text-center mt-4">
                    <Button @click="updateNetworkState(true)" :label="t('web.device_management.disable_network')"
                        severity="warning" icon="pi pi-power-off" iconPos="left" />
                </div>
            </div>

            <!-- Empty State -->
            <div v-else class="empty-state flex flex-col items-center py-12">
                <i class="pi pi-sitemap text-5xl text-secondary mb-4 opacity-50"></i>
                <div class="text-xl text-center font-medium mb-3">{{ t('web.device_management.no_network_selected') }}
                </div>
                <p class="text-secondary text-center mb-6 max-w-md">
                    {{ t('web.device_management.select_existing_network_or_create_new') }}
                </p>
                <Button @click="newNetwork" :label="t('web.device_management.create_network')" icon="pi pi-plus"
                    iconPos="left" />
            </div>
        </div>

        <!-- Keep only the config edit dialogs -->
        <!-- <ConfigEditDialog v-if="networkIsDisabled" v-model:visible="showCreateNetworkDialog"
            :cur-network="currentNetworkConfig" :generate-config="generateConfig" :save-config="saveConfig" /> -->

        <ConfigEditDialog v-model:visible="showConfigEditDialog" :cur-network="currentNetworkConfig"
            :generate-config="generateConfig" :save-config="syncTomlConfig" />
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

