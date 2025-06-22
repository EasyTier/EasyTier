<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { Button, Column, DataTable, Drawer, ProgressSpinner, useToast } from 'primevue';
import { useRoute, useRouter } from 'vue-router';
import { Api, Utils } from 'easytier-frontend-lib';

const props = defineProps({
    api: Api.ApiClient,
});

const api = props.api;

const deviceList = ref<Array<Utils.DeviceInfo> | undefined>(undefined);

const selectedDeviceId = computed<string | undefined>(() => route.params.deviceId as string);

const route = useRoute();
const router = useRouter();
const toast = useToast();

// 展开的设备ID集合（用于移动端卡片）
const expandedDevices = ref<Set<string>>(new Set());

// 悬停展开的行ID（用于桌面端表格）
const hoveredRowId = ref<string | null>(null);

const loadDevices = async () => {
    const resp = await api?.list_machines();
    let devices: Array<Utils.DeviceInfo> = [];
    for (const device of (resp || [])) {
        devices.push({
            hostname: device.info?.hostname,
            public_ip: device.client_url,
            running_network_instances: device.info?.running_network_instances.map((instance: any) => Utils.UuidToStr(instance)),
            running_network_count: device.info?.running_network_instances.length,
            report_time: new Date(device.info?.report_time).toLocaleString(),
            easytier_version: device.info?.easytier_version,
            machine_id: Utils.UuidToStr(device.info?.machine_id),
        });
    }
    console.debug("device list", deviceList.value);
    deviceList.value = devices;
};

const periodFunc = new Utils.PeriodicTask(async () => {
    try {
        await loadDevices();
    } catch (e) {
        toast.add({ severity: 'error', summary: 'Load Device List Failed', detail: e, life: 2000 });
        console.error(e);
    }
}, 1000);

onMounted(async () => {
    periodFunc.start();
});

onUnmounted(() => {
    periodFunc.stop();
});

const deviceManageVisible = computed<boolean>({
    get: () => !!selectedDeviceId.value,
    set: (value) => {
        if (!value) {
            router.push({ name: 'deviceList', params: { deviceId: undefined } });
        }
    }
});

const selectedDeviceHostname = computed<string | undefined>(() => {
    return deviceList.value?.find((device) => device.machine_id === selectedDeviceId.value)?.hostname;
});

// 处理设备管理
const handleDeviceManagement = (device: Utils.DeviceInfo) => {
    const instanceId = device.running_network_instances?.[0];
    if (!instanceId) {
        toast.add({ 
            severity: 'warn', 
            summary: 'No Network Instance', 
            detail: 'This device has no running network instances to manage.', 
            life: 3000 
        });
        return;
    }
    
    router.push({ 
        name: 'deviceManagement', 
        params: { 
            deviceId: device.machine_id, 
            instanceId: instanceId
        } 
    });
};

// 切换设备展开状态（移动端）
const toggleDeviceExpansion = (deviceId: string) => {
    if (expandedDevices.value.has(deviceId)) {
        expandedDevices.value.delete(deviceId);
    } else {
        expandedDevices.value.add(deviceId);
    }
};

// 检查设备是否已展开（移动端）
const isDeviceExpanded = (deviceId: string) => {
    return expandedDevices.value.has(deviceId);
};

// 获取悬停的设备信息
const hoveredDevice = computed(() => {
    if (!hoveredRowId.value || !deviceList.value) return null;
    return deviceList.value.find(device => device.machine_id === hoveredRowId.value);
});

</script>

<style scoped>
/* 响应式表格样式 */
.table-view {
    font-size: 0.875rem;
}

.table-view .p-datatable-wrapper {
    overflow-x: auto;
}

.table-view .p-datatable-table {
    min-width: 100%;
}

.table-view .p-column-header {
    padding: 0.5rem 0.25rem;
}

.table-view .p-datatable-tbody > tr > td {
    padding: 0.5rem 0.25rem;
}

/* 悬停行样式 */
.hoverable-row {
    transition: background-color 0.2s ease;
    cursor: pointer;
}

.hoverable-row:hover {
    background-color: #f3f4f6 !important;
}

/* 展开详情行样式 */
.expand-row {
    background-color: #f8fafc;
    border-top: 1px solid #e2e8f0;
    animation: slideDown 0.3s ease-out;
}

@keyframes slideDown {
    from {
        opacity: 0;
        max-height: 0;
    }
    to {
        opacity: 1;
        max-height: 200px;
    }
}

.expand-row-content {
    padding: 1rem;
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
}

.expand-detail-item {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.expand-detail-label {
    font-weight: 600;
    color: #374151;
    font-size: 0.875rem;
}

.expand-detail-value {
    color: #6b7280;
    font-size: 0.875rem;
}

/* 移动端卡片样式 */
.mobile-card {
    border: 1px solid #e5e7eb;
    border-radius: 0.5rem;
    margin-bottom: 0.5rem;
    background: white;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
}

.mobile-card-header {
    padding: 1rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid #e5e7eb;
}

.mobile-card-details {
    background: #f9fafb;
    border-top: 1px solid #e5e7eb;
    padding: 1rem;
}

.mobile-card-details .detail-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0;
    border-bottom: 1px solid #e2e8f0;
}

.mobile-card-details .detail-item:last-child {
    border-bottom: none;
}

.mobile-card-details .detail-label {
    font-weight: 600;
    color: #374151;
    min-width: 120px;
}

.mobile-card-details .detail-value {
    color: #6b7280;
    text-align: right;
    flex: 1;
    margin-left: 1rem;
}

/* 展开按钮样式 */
.expand-button {
    transition: transform 0.2s ease;
}

.expand-button.expanded {
    transform: rotate(180deg);
}

/* 确保设置按钮在小屏幕上可见 */
.settings-column {
    position: sticky;
    right: 0;
    background: white;
    z-index: 10;
}

@media (max-width: 768px) {
    .settings-column {
        background: white;
        border-left: 1px solid #e5e7eb;
    }
}

/* 悬停详情面板样式 */
.hover-details-panel {
    background: #f8fafc;
    border: 1px solid #e2e8f0;
    border-radius: 0.5rem;
    padding: 1rem;
    margin-top: 1rem;
    animation: fadeIn 0.3s ease-out;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
}

@keyframes fadeIn {
    from {
        opacity: 0;
        transform: translateY(-10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* 悬停触发器样式 */
.hover-trigger {
    cursor: pointer;
    transition: background-color 0.2s ease;
}

.hover-trigger:hover {
    background-color: #f3f4f6;
    border-radius: 0.25rem;
    padding: 0.25rem;
    margin: -0.25rem;
}
</style>

<template>
    <div v-if="deviceList === undefined" class="w-full flex justify-center">
        <ProgressSpinner />
    </div>

    <div v-if="deviceList !== undefined">
        <!-- 标题 -->
        <div class="text-xl font-bold mb-4">Device List</div>

        <!-- 桌面端表格视图 (md及以上屏幕) -->
        <div class="hidden md:block">
            <DataTable 
                :value="deviceList" 
                class="table-view"
                :metaKeySelection="true" 
                sortField="hostname"
                :sortOrder="-1"
                :scrollable="true"
                scrollDirection="horizontal"
                :showGridlines="true"
                stripedRows
            >
                <!-- 主机名 -->
                <Column 
                    field="hostname" 
                    header="Hostname" 
                    sortable 
                    :style="{ minWidth: '150px' }"
                >
                    <template #body="{ data }">
                        <div 
                            class="font-medium truncate hover-trigger" 
                            :title="data.hostname"
                            @mouseenter="hoveredRowId = data.machine_id"
                            @mouseleave="hoveredRowId = null"
                        >
                            {{ data.hostname }}
                        </div>
                    </template>
                </Column>

                <!-- 公共IP -->
                <Column 
                    field="public_ip" 
                    header="Public IP" 
                    :style="{ minWidth: '120px' }"
                >
                    <template #body="{ data }">
                        <div 
                            class="truncate hover-trigger" 
                            :title="data.public_ip"
                            @mouseenter="hoveredRowId = data.machine_id"
                            @mouseleave="hoveredRowId = null"
                        >
                            {{ data.public_ip }}
                        </div>
                    </template>
                </Column>

                <!-- 运行网络数量 -->
                <Column 
                    field="running_network_count" 
                    header="Networks" 
                    sortable 
                    :style="{ minWidth: '100px', textAlign: 'center' }"
                >
                    <template #body="{ data }">
                        <div 
                            class="text-center hover-trigger"
                            @mouseenter="hoveredRowId = data.machine_id"
                            @mouseleave="hoveredRowId = null"
                        >
                            <span class="inline-flex items-center justify-center w-6 h-6 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                                {{ data.running_network_count }}
                            </span>
                        </div>
                    </template>
                </Column>

                <!-- 报告时间 -->
                <Column 
                    field="report_time" 
                    header="Last Report" 
                    sortable 
                    :style="{ minWidth: '160px' }"
                >
                    <template #body="{ data }">
                        <div 
                            class="text-sm text-gray-600 truncate hover-trigger" 
                            :title="data.report_time"
                            @mouseenter="hoveredRowId = data.machine_id"
                            @mouseleave="hoveredRowId = null"
                        >
                            {{ data.report_time }}
                        </div>
                    </template>
                </Column>

                <!-- EasyTier版本 -->
                <Column 
                    field="easytier_version" 
                    header="Version" 
                    sortable 
                    :style="{ minWidth: '120px' }"
                >
                    <template #body="{ data }">
                        <div 
                            class="text-sm text-gray-500 truncate hover-trigger" 
                            :title="data.easytier_version"
                            @mouseenter="hoveredRowId = data.machine_id"
                            @mouseleave="hoveredRowId = null"
                        >
                            {{ data.easytier_version }}
                        </div>
                    </template>
                </Column>

                <!-- 设置按钮 -->
                <Column 
                    class="settings-column"
                    :style="{ minWidth: '60px', width: '60px' }"
                >
                    <template #header>
                        <span class="sr-only">Actions</span>
                    </template>
                    <template #body="{ data }">
                        <Button 
                            icon="pi pi-cog"
                            @click="handleDeviceManagement(data)"
                            severity="secondary" 
                            rounded
                            size="small"
                            class="w-8 h-8"
                            :title="`Manage ${data.hostname}`"
                        />
                    </template>
                </Column>

                <template #footer>
                    <div class="flex justify-end">
                        <Button icon="pi pi-refresh" label="Reload" severity="info" @click="loadDevices" />
                    </div>
                </template>
            </DataTable>
            
            <!-- 悬停展开的详细信息面板 -->
            <div v-if="hoveredDevice" class="hover-details-panel">
                <div class="expand-row-content">
                    <div class="expand-detail-item">
                        <span class="expand-detail-label">Hostname:</span>
                        <span class="expand-detail-value">{{ hoveredDevice.hostname }}</span>
                    </div>
                    <div class="expand-detail-item">
                        <span class="expand-detail-label">Public IP:</span>
                        <span class="expand-detail-value">{{ hoveredDevice.public_ip }}</span>
                    </div>
                    <div class="expand-detail-item">
                        <span class="expand-detail-label">Running Networks:</span>
                        <span class="expand-detail-value">{{ hoveredDevice.running_network_count }}</span>
                    </div>
                    <div class="expand-detail-item">
                        <span class="expand-detail-label">Last Report:</span>
                        <span class="expand-detail-value">{{ hoveredDevice.report_time }}</span>
                    </div>
                    <div class="expand-detail-item">
                        <span class="expand-detail-label">EasyTier Version:</span>
                        <span class="expand-detail-value">{{ hoveredDevice.easytier_version }}</span>
                    </div>
                    <div class="expand-detail-item">
                        <span class="expand-detail-label">Machine ID:</span>
                        <span class="expand-detail-value text-xs font-mono">{{ hoveredDevice.machine_id }}</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- 移动端卡片视图 (sm及以下屏幕) -->
        <div class="md:hidden">
            <div class="space-y-3">
                <div 
                    v-for="device in deviceList" 
                    :key="device.machine_id"
                    class="mobile-card"
                >
                    <!-- 卡片头部 -->
                    <div class="mobile-card-header">
                        <div class="flex-1">
                            <div class="font-semibold text-gray-900">{{ device.hostname }}</div>
                            <div class="text-sm text-gray-500 mt-1">{{ device.public_ip }}</div>
                        </div>
                        <div class="flex items-center space-x-2">
                            <!-- 网络数量徽章 -->
                            <span class="inline-flex items-center justify-center w-6 h-6 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                                {{ device.running_network_count }}
                            </span>
                            
                            <!-- 展开按钮 -->
                            <Button 
                                :icon="isDeviceExpanded(device.machine_id) ? 'pi pi-chevron-up' : 'pi pi-chevron-down'"
                                @click="toggleDeviceExpansion(device.machine_id)"
                                severity="secondary" 
                                rounded
                                size="small"
                                class="w-8 h-8 expand-button"
                                :class="{ expanded: isDeviceExpanded(device.machine_id) }"
                                :title="isDeviceExpanded(device.machine_id) ? '收起详情' : '展开详情'"
                            />
                            
                            <!-- 设置按钮 -->
                            <Button 
                                icon="pi pi-cog"
                                @click="handleDeviceManagement(device)"
                                severity="secondary" 
                                rounded
                                size="small"
                                class="w-8 h-8"
                                :title="`Manage ${device.hostname}`"
                            />
                        </div>
                    </div>
                    
                    <!-- 展开的详细信息 -->
                    <div v-if="isDeviceExpanded(device.machine_id)" class="mobile-card-details">
                        <div class="space-y-3">
                            <div class="detail-item">
                                <span class="detail-label">Hostname:</span>
                                <span class="detail-value">{{ device.hostname }}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Public IP:</span>
                                <span class="detail-value">{{ device.public_ip }}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Running Networks:</span>
                                <span class="detail-value">{{ device.running_network_count }}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Last Report:</span>
                                <span class="detail-value">{{ device.report_time }}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">EasyTier Version:</span>
                                <span class="detail-value">{{ device.easytier_version }}</span>
                            </div>
                            <div class="detail-item">
                                <span class="detail-label">Machine ID:</span>
                                <span class="detail-value text-xs font-mono">{{ device.machine_id }}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- 移动端底部按钮 -->
            <div class="flex justify-end mt-4">
                <Button icon="pi pi-refresh" label="Reload" severity="info" @click="loadDevices" />
            </div>
        </div>
    </div>

    <Drawer v-model:visible="deviceManageVisible" :header="`Manage ${selectedDeviceHostname}`" position="right"
        :baseZIndex=1000 class="w-3/5 min-w-96">
        <RouterView v-slot="{ Component }">
            <component :is="Component" :api="api" :deviceList="deviceList" @update="loadDevices" />
        </RouterView>
    </Drawer>
</template>
