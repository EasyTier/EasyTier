<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { Button, Checkbox, Column, DataTable, Dialog, Drawer, InputText, SelectButton, Skeleton, useToast } from 'primevue';
import Tooltip from 'primevue/tooltip';
import { useRoute, useRouter } from 'vue-router';
import { Utils } from 'easytier-frontend-lib';
import DeviceDetails from './DeviceDetails.vue';
import { useI18n } from 'vue-i18n'
import ApiClient from '../modules/api';

const { t } = useI18n()

// 注册 Tooltip 指令
const vTooltip = Tooltip;

const props = defineProps({
    api: ApiClient,
    centralEnabled: Boolean,
});

const api = props.api;
const route = useRoute();
const router = useRouter();
const toast = useToast();

const deviceList = ref<Array<Utils.DeviceInfo> | undefined>(undefined);
const search = ref('');
const loadError = ref(false);
const refreshing = ref(false);
const expandedRows = ref({});

// 桌面端可在表格与卡片视图之间切换，选择持久化；移动端始终使用紧凑列表
const viewMode = ref<'table' | 'card'>(localStorage.getItem('deviceList.viewMode') === 'card' ? 'card' : 'table');
const viewModeOptions = [
    { value: 'table', icon: 'pi pi-table' },
    { value: 'card', icon: 'pi pi-th-large' },
];
const viewModeLabel = (value: string) => t(value === 'card' ? 'web.console.view_card' : 'web.console.view_table');
watch(viewMode, (mode) => localStorage.setItem('deviceList.viewMode', mode));

// Zero-device state is where users look for "how do I add one": surface
// the enrollment command right there.
const enrollInfo = ref<Awaited<ReturnType<ApiClient['get_console_info']>> | null>(null);
const enrollCommand = computed(() => {
    if (!enrollInfo.value) return '';
    const host = window.location.hostname;
    const { config_server_protocol: proto, config_server_port: port, username } = enrollInfo.value;
    return `easytier-core --config-server ${proto}://${host}:${port}/${username}`;
});

const copyEnrollCommand = async () => {
    try {
        await navigator.clipboard.writeText(enrollCommand.value);
        toast.add({ severity: 'success', summary: t('web.common.confirm'), life: 1500 });
    } catch (e) {
        console.error(e);
    }
};

const loadDevices = async () => {
    if (refreshing.value) return;
    refreshing.value = true;
    try {
        const resp = await api?.list_machines();
        deviceList.value = (resp || []).map(Utils.buildDeviceInfo);
        loadError.value = false;
    } catch (e) {
        loadError.value = true;
        console.error(e);
    } finally {
        refreshing.value = false;
    }
};

const periodFunc = new Utils.PeriodicTask(async () => {
    try {
        await loadDevices();
    } catch (e) {
        console.error(e);
    }
}, 1000);

onMounted(() => {
    periodFunc.start();
    api?.get_console_info().then(info => { enrollInfo.value = info; }).catch(() => {});
});

onUnmounted(() => {
    periodFunc.stop();
});

const selectedDeviceId = computed<string | undefined>(() => route.params.deviceId as string);

const deviceManageVisible = computed<boolean>({
    get: () => !!selectedDeviceId.value,
    set: (value) => {
        if (!value) {
            router.push({ name: 'deviceList', params: { deviceId: undefined } });
        }
    }
});

const selectedDeviceHostname = computed<string | undefined>(() => {
    const device = deviceList.value?.find((device) => device.machine_id === selectedDeviceId.value);
    return device ? deviceName(device) : undefined;
});

// 处理设备管理
const handleDeviceManagement = (device: Utils.DeviceInfo) => {
    const instanceId = device.running_network_instances?.[0];
    router.push({
        name: 'deviceManagement',
        params: {
            deviceId: device.machine_id,
            instanceId: instanceId
        }
    });
};

// 删除设备：若还是网络成员会连带移出并回收托管配置；可选同时拉黑
const deleteVisible = ref(false);
const deleting = ref(false);
const deleteTarget = ref<Utils.DeviceInfo | null>(null);
const deleteAlsoBlock = ref(true);

const handleDeleteDevice = (device: Utils.DeviceInfo) => {
    deleteTarget.value = device;
    deleteAlsoBlock.value = true;
    deleteVisible.value = true;
};

// 别名仅改变控制台内的显示名，不影响设备上报的主机名
const deviceName = (device: Utils.DeviceInfo) => device.alias || device.hostname || device.machine_id;

const aliasVisible = ref(false);
const aliasTarget = ref<Utils.DeviceInfo | null>(null);
const aliasInput = ref('');
const aliasSaving = ref(false);

const handleSetAlias = (device: Utils.DeviceInfo) => {
    aliasTarget.value = device;
    aliasInput.value = device.alias ?? '';
    aliasVisible.value = true;
};

const saveAlias = async () => {
    if (!aliasTarget.value || !api) return;
    const alias = aliasInput.value.trim();
    if (alias.length > 64) return;
    aliasSaving.value = true;
    try {
        await api.update_machine_alias(aliasTarget.value.machine_id, alias);
        aliasVisible.value = false;
        await loadDevices();
    } catch (e) {
        console.error(e);
        toast.add({ severity: 'error', summary: t('web.console.load_failed'), life: 3000 });
    } finally {
        aliasSaving.value = false;
    }
};

const confirmDeleteDevice = async () => {
    if (!deleteTarget.value) return;
    deleting.value = true;
    try {
        await api?.delete_machine(deleteTarget.value.machine_id, deleteAlsoBlock.value);
        deleteVisible.value = false;
        await loadDevices();
    } catch (e: any) {
        toast.add({ severity: 'error', summary: t('web.console.delete_device'), detail: e?.response?.data?.message ?? String(e), life: 5000 });
    } finally {
        deleting.value = false;
    }
};

// 搜索过滤 + 预排序：离线设备始终排在在线设备之后；列排序交给 DataTable
const sortedDeviceList = computed(() => {
    const query = search.value.trim().toLocaleLowerCase();
    return (deviceList.value ?? [])
        .filter(device => `${device.alias ?? ''} ${device.hostname ?? ''} ${device.public_ip ?? ''}`.toLocaleLowerCase().includes(query))
        .sort((a, b) => {
            const online = Number(b.online === true) - Number(a.online === true);
            if (online !== 0) return online;
            return (deviceName(a) ?? '').localeCompare(deviceName(b) ?? '');
        });
});

const locationText = (device: Utils.DeviceInfo) => {
    const parts = [device.location?.country, device.location?.region, device.location?.city].filter(Boolean);
    return parts.length ? parts.join(' · ') : t('web.device.unknown_location');
};
</script>

<template>
    <div class="console-page">
        <header class="page-heading">
            <div>
                <h1>{{ t('web.device.list') }}</h1>
            </div>
        </header>
        <section class="console-panel">
            <div class="list-toolbar">
                <span class="search-field"><i class="pi pi-search" aria-hidden="true" /><InputText v-model="search"
                        :placeholder="t('web.console.search_devices')"
                        :aria-label="t('web.console.search_devices')" /></span>
                <div class="flex items-center gap-3">
                    <span v-if="deviceList" class="table-count">{{ t('web.console.items', { count: sortedDeviceList.length }) }}</span>
                    <SelectButton v-model="viewMode" :options="viewModeOptions" optionValue="value"
                        :allow-empty="false" class="view-toggle">
                        <template #option="{ option }">
                            <i :class="option.icon" v-tooltip.top="viewModeLabel(option.value)"
                                :aria-label="viewModeLabel(option.value)"></i>
                        </template>
                    </SelectButton>
                    <Button icon="pi pi-refresh" text severity="secondary" :aria-label="t('web.console.refresh')"
                        :loading="refreshing" @click="loadDevices" />
                </div>
            </div>
            <div v-if="deviceList === undefined && !loadError" class="loading-rows">
                <Skeleton v-for="i in 4" :key="i" height="2rem" />
            </div>
            <div v-else-if="loadError" class="console-empty-state">
                <i class="pi pi-exclamation-triangle" aria-hidden="true"></i>
                <h2>{{ t('web.console.load_failed') }}</h2>
                <Button :label="t('web.console.retry')" icon="pi pi-refresh" @click="loadDevices" />
            </div>
            <div v-else-if="sortedDeviceList.length === 0" class="console-empty-state">
                <i class="pi pi-server" aria-hidden="true"></i>
                <h2>{{ search ? t('web.console.no_results') : t('web.console.devices_empty') }}</h2>
                <p v-if="!search">{{ t('web.console.devices_empty_hint') }}</p>
                <div v-if="!search && enrollCommand" class="flex items-center gap-2 justify-center mt-2 flex-wrap">
                    <code class="mono-value p-2 rounded" style="background: var(--console-ground); word-break: break-all">{{ enrollCommand }}</code>
                    <Button icon="pi pi-copy" severity="secondary" outlined size="small"
                        :aria-label="t('web.console.enroll_copy')" @click="copyEnrollCommand" />
                </div>
            </div>
            <template v-else>
                <DataTable v-if="viewMode === 'table'" :value="sortedDeviceList" class="console-table desktop-list" size="small"
                    v-model:expandedRows="expandedRows" dataKey="machine_id" scrollable
                    :paginator="sortedDeviceList.length > 20" :rows="20">
                    <Column expander style="width: 2.5rem" />
                    <Column field="hostname" :header="t('web.device.hostname')" sortable>
                        <template #body="{ data }">
                            <button class="entity-link" @click="handleDeviceManagement(data)">
                                <span class="status-dot" :class="data.online ? 'online' : 'offline'"></span>
                                <span class="min-w-0">
                                    <span class="preview-name">{{ deviceName(data) }}</span>
                                    <span v-if="data.alias && data.hostname" class="preview-secondary mono-value">{{ data.hostname }}</span>
                                </span>
                            </button>
                        </template>
                    </Column>
                    <Column :header="t('web.console.location')">
                        <template #body="{ data }">{{ locationText(data) }}</template>
                    </Column>
                    <Column field="running_network_count" :header="t('web.device.networks')" sortable style="width: 7rem" />
                    <Column field="easytier_version" :header="t('web.device.version')" sortable style="width: 7rem">
                        <template #body="{ data }"><span class="mono-value muted">v{{ (data.easytier_version || '?').split('-')[0] }}</span></template>
                    </Column>
                    <Column :header="t('web.device.last_seen')" style="width: 10rem">
                        <template #body="{ data }"><span v-if="!data.online && data.last_seen" class="muted">{{ data.last_seen.replace('T', ' ').slice(5, 16) }}</span><span v-else class="muted">—</span></template>
                    </Column>
                    <Column :header="t('web.console.manage')" style="width: 7rem">
                        <template #body="{ data }">
                            <div class="flex items-center gap-1">
                                <Button v-if="centralEnabled" v-tooltip.top="t('web.console.set_alias')" icon="pi pi-pencil" severity="secondary"
                                    text rounded :aria-label="t('web.console.set_alias')" @click="handleSetAlias(data)" />
                                <Button v-if="centralEnabled" v-tooltip.top="t('web.console.delete_device')" icon="pi pi-trash" severity="danger"
                                    text rounded :aria-label="t('web.console.delete_device')" @click="handleDeleteDevice(data)" />
                                <Button icon="pi pi-cog" severity="secondary" text rounded
                                    :aria-label="`${t('web.console.manage')} ${data.hostname}`"
                                    @click="handleDeviceManagement(data)" />
                            </div>
                        </template>
                    </Column>
                    <template #expansion="{ data }">
                        <DeviceDetails :device="data" containerClass="row-details-content" :compact="true" />
                    </template>
                </DataTable>
                <div v-if="viewMode === 'card'" class="device-card-grid">
                    <article v-for="device in sortedDeviceList" :key="device.machine_id" class="device-card"
                        :class="{ offline: !device.online }">
                        <div class="device-card-title">
                            <button class="entity-link" @click="handleDeviceManagement(device)">
                                <span class="status-dot" :class="device.online ? 'online' : 'offline'"></span>
                                <span class="min-w-0">
                                    <span class="preview-name">{{ deviceName(device) }}</span>
                                    <span v-if="device.alias && device.hostname" class="preview-secondary mono-value">{{ device.hostname }}</span>
                                </span>
                            </button>
                            <span class="mono-value muted shrink-0">v{{ (device.easytier_version || '?').split('-')[0] }}</span>
                        </div>
                        <p class="preview-secondary">{{ locationText(device) }}</p>
                        <div class="device-card-actions">
                            <span class="muted"><i class="pi pi-sitemap" aria-hidden="true"></i> {{ device.running_network_count }} {{ t('web.console.instances') }}</span>
                            <div class="flex items-center gap-1">
                                <Button v-if="centralEnabled" v-tooltip.top="t('web.console.set_alias')" icon="pi pi-pencil" severity="secondary"
                                    text rounded class="w-8 h-8" :aria-label="t('web.console.set_alias')" @click="handleSetAlias(device)" />
                                <Button v-if="centralEnabled" v-tooltip.top="t('web.console.delete_device')" icon="pi pi-trash" severity="danger"
                                    text rounded class="w-8 h-8" :aria-label="t('web.console.delete_device')" @click="handleDeleteDevice(device)" />
                                <Button icon="pi pi-cog" severity="secondary" text rounded class="w-8 h-8"
                                    :aria-label="`${t('web.console.manage')} ${device.hostname}`"
                                    @click="handleDeviceManagement(device)" />
                            </div>
                        </div>
                    </article>
                </div>
                <div class="mobile-list">
                    <article v-for="device in sortedDeviceList" :key="device.machine_id" class="mobile-list-item">
                        <div class="flex items-center justify-between gap-3">
                            <button class="entity-link" @click="handleDeviceManagement(device)">
                                <span class="status-dot" :class="device.online ? 'online' : 'offline'"></span>
                                <span class="preview-name">{{ deviceName(device) }}</span>
                            </button>
                            <span class="mono-value muted">v{{ (device.easytier_version || '?').split('-')[0] }}</span>
                        </div>
                        <p class="preview-secondary">{{ locationText(device) }} · {{ device.running_network_count }} {{ t('web.console.instances') }}</p>
                        <details>
                            <summary>{{ t('web.console.details') }}</summary>
                            <DeviceDetails :device="device" :compact="true" />
                        </details>
                    </article>
                </div>
            </template>
        </section>

        <!-- 设置别名对话框 -->
        <Dialog v-model:visible="aliasVisible" modal :header="t('web.console.alias_dialog_title')" :style="{ width: '26rem' }">
            <div class="flex flex-col gap-3">
                <div class="text-sm muted">{{ t('web.console.alias_hint') }}</div>
                <InputText v-model="aliasInput" id="device-alias-input" :maxlength="64" autocomplete="off"
                    :placeholder="aliasTarget?.hostname" @keydown.enter="saveAlias" />
                <div class="text-xs muted text-right">{{ aliasInput.trim().length }}/64</div>
            </div>
            <template #footer>
                <Button :label="t('web.common.cancel')" severity="secondary" @click="aliasVisible = false" />
                <Button :label="t('web.common.confirm')" icon="pi pi-check" :loading="aliasSaving" @click="saveAlias" />
            </template>
        </Dialog>

        <!-- 删除确认对话框 -->
        <Dialog v-model:visible="deleteVisible" modal :header="t('web.console.delete_device')" :style="{ width: '26rem' }">
            <div class="flex flex-col gap-3">
                <div>{{ t('web.console.delete_device_confirm', { device: deleteTarget?.hostname || deleteTarget?.machine_id }) }}</div>
                <div class="flex items-center gap-2">
                    <Checkbox inputId="delete-also-block" v-model="deleteAlsoBlock" :binary="true" />
                    <label for="delete-also-block">{{ t('web.console.block_device') }}</label>
                </div>
                <div class="text-xs text-500">{{ deleteAlsoBlock ? t('web.console.block_device_hint') : t('web.console.no_block_device_hint') }}</div>
            </div>
            <template #footer>
                <Button :label="t('web.common.cancel')" icon="pi pi-times" text severity="secondary" @click="deleteVisible = false" />
                <Button :label="t('web.common.confirm')" icon="pi pi-check" :loading="deleting" severity="danger" @click="confirmDeleteDevice" />
            </template>
        </Dialog>

        <Drawer v-model:visible="deviceManageVisible" position="right" class="console-device-drawer" :baseZIndex="1000">
            <template #header>
                <div class="drawer-heading flex items-baseline gap-3 min-w-0">
                    <h2 class="truncate">{{ selectedDeviceHostname }}</h2>
                    <p class="mono-value truncate">{{ selectedDeviceId }}</p>
                </div>
            </template>
            <RouterView v-slot="{ Component }">
                <component :is="Component" :api="api" :deviceList="deviceList" @update="loadDevices" />
            </RouterView>
        </Drawer>
    </div>
</template>

<style scoped>
.device-card-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
    gap: 16px;
    padding: 18px;
}

.device-card {
    background: var(--console-panel);
    border: 1px solid var(--console-border);
    border-radius: 8px;
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 8px;
}

.device-card.offline {
    opacity: .72;
}

.device-card-title {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    min-width: 0;
}

.device-card-actions {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-top: 4px;
    padding-top: 10px;
    border-top: 1px solid var(--console-border);
}
</style>
