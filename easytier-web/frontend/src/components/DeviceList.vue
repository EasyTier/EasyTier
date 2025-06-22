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
    router.push({ 
        name: 'deviceManagement', 
        params: { 
            deviceId: device.machine_id, 
            instanceId: device.running_network_instances[0] 
        } 
    });
};

</script>

<style scoped>
/* 响应式表格样式 */
@media (max-width: 768px) {
    .mobile-table {
        font-size: 0.875rem;
    }
    
    .mobile-table .p-datatable-wrapper {
        overflow-x: auto;
    }
    
    .mobile-table .p-datatable-table {
        min-width: 100%;
    }
    
    .mobile-table .p-column-header {
        padding: 0.5rem 0.25rem;
    }
    
    .mobile-table .p-datatable-tbody > tr > td {
        padding: 0.5rem 0.25rem;
    }
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
</style>

<template>
    <div v-if="deviceList === undefined" class="w-full flex justify-center">
        <ProgressSpinner />
    </div>

    <DataTable 
        :value="deviceList" 
        class="mobile-table"
        :metaKeySelection="true" 
        sortField="hostname"
        :sortOrder="-1" 
        v-if="deviceList !== undefined"
        :scrollable="true"
        scrollDirection="horizontal"
        :showGridlines="true"
        stripedRows
    >
        <template #header>
            <div class="text-xl font-bold">Device List</div>
        </template>

        <!-- 主机名 - 始终显示 -->
        <Column 
            field="hostname" 
            header="Hostname" 
            sortable 
            class="min-w-32 max-w-48"
            :style="{ minWidth: '120px', maxWidth: '200px' }"
        >
            <template #body="{ data }">
                <div class="font-medium truncate" :title="data.hostname">
                    {{ data.hostname }}
                </div>
            </template>
        </Column>

        <!-- 公共IP - 在中等屏幕以上显示 -->
        <Column 
            field="public_ip" 
            header="Public IP" 
            class="hidden md:table-cell"
            :style="{ minWidth: '120px' }"
        >
            <template #body="{ data }">
                <div class="truncate" :title="data.public_ip">
                    {{ data.public_ip }}
                </div>
            </template>
        </Column>

        <!-- 运行网络数量 - 始终显示但简化 -->
        <Column 
            field="running_network_count" 
            header="Networks" 
            sortable 
            class="min-w-20"
            :style="{ minWidth: '80px', textAlign: 'center' }"
        >
            <template #body="{ data }">
                <div class="text-center">
                    <span class="inline-flex items-center justify-center w-6 h-6 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                        {{ data.running_network_count }}
                    </span>
                </div>
            </template>
        </Column>

        <!-- 报告时间 - 在中等屏幕以上显示 -->
        <Column 
            field="report_time" 
            header="Last Report" 
            sortable 
            class="hidden lg:table-cell"
            :style="{ minWidth: '140px' }"
        >
            <template #body="{ data }">
                <div class="text-sm text-gray-600 truncate" :title="data.report_time">
                    {{ data.report_time }}
                </div>
            </template>
        </Column>

        <!-- EasyTier版本 - 在大屏幕显示 -->
        <Column 
            field="easytier_version" 
            header="Version" 
            sortable 
            class="hidden xl:table-cell"
            :style="{ minWidth: '100px' }"
        >
            <template #body="{ data }">
                <div class="text-sm text-gray-500 truncate" :title="data.easytier_version">
                    {{ data.easytier_version }}
                </div>
            </template>
        </Column>

        <!-- 设置按钮 - 始终显示，固定在右侧 -->
        <Column 
            class="settings-column min-w-16"
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

    <Drawer v-model:visible="deviceManageVisible" :header="`Manage ${selectedDeviceHostname}`" position="right"
        :baseZIndex=1000 class="w-3/5 min-w-96">
        <RouterView v-slot="{ Component }">
            <component :is="Component" :api="api" :deviceList="deviceList" @update="loadDevices" />
        </RouterView>
    </Drawer>
</template>
