<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { Button, Column, DataTable, Drawer, ProgressSpinner, useToast, InputSwitch, Popover } from 'primevue';
import Tooltip from 'primevue/tooltip';
import { useRoute, useRouter } from 'vue-router';
import { Api, Utils } from 'easytier-frontend-lib';
import DeviceDetails from './DeviceDetails.vue';

declare const window: Window & typeof globalThis;

// 注册 Tooltip 指令
const vTooltip = Tooltip;

const props = defineProps({
    api: Api.ApiClient,
});

const detailPopover = ref();
const selectedDevice = ref<Utils.DeviceInfo | null>(null);
const showDetailedView = ref(false);

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
    // 初始化屏幕尺寸相关变量
    handleResize();
    window.addEventListener('resize', handleResize);
});

onUnmounted(() => {
    periodFunc.stop();
    window.removeEventListener('resize', handleResize);
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
    router.push({ 
        name: 'deviceManagement', 
        params: { 
            deviceId: device.machine_id, 
            instanceId: instanceId
        } 
    });
};

// 显示设备详情
const showDeviceDetails = (device: Utils.DeviceInfo, event: Event) => {
    selectedDevice.value = device;
    detailPopover.value.toggle(event);
};







// 检查是否为桌面设备
const isDesktop = ref(false);
// 检查是否为多卡片视图（一行可以放置多个卡片）
const isMultiCardView = ref(false);

// 保存resize事件处理函数的引用，以便正确移除
const handleResize = () => {
    isDesktop.value = window.innerWidth >= 768;
    // 当容器宽度足够放置两个或更多卡片时，视为多卡片视图
    isMultiCardView.value = window.innerWidth >= 650;
};

</script>

<style scoped>
/* 卡片容器 */
.card-container {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
    gap: 1rem;
    width: 100%;
    position: relative; /* 确保子元素的绝对定位相对于此容器 */
}

/* 设备卡片样式 */
.device-card {
    border: 1px solid #e5e7eb;
    border-radius: 0.5rem;
    background: white;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
    transition: transform 0.2s ease, box-shadow 0.2s ease;
    display: flex;
    flex-direction: column;
    position: relative;
}

.device-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
}

.card-header {
    padding: 0.75rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: relative;
}



.device-details-popover {
    min-width: 300px;
    max-width: 400px;
    padding: 0.5rem;
}

/* Popover 样式 */
:deep(.device-popover.p-popover) {
    min-width: 320px;
    border-radius: 0.5rem;
    box-shadow: var(--card-shadow, 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05));
    border: 1px solid var(--surface-border, #e5e7eb);
    overflow: hidden;
}

:deep(.device-popover .p-popover-content) {
    padding: 0;
    background-color: var(--surface-card, #ffffff);
    color: var(--text-color, #334155);
}

:deep(.device-popover .p-popover-arrow) {
    background-color: var(--surface-card, #ffffff);
    border-color: var(--surface-border, #e5e7eb);
}

:deep(.device-popover .p-popover-header) {
    background-color: var(--surface-section, #f8fafc);
    border-bottom: 1px solid var(--surface-border, #e2e8f0);
}

:deep(.device-popover .p-popover-header-close) {
    color: var(--text-color-secondary, #64748b);
}

:deep(.device-popover .p-popover-header-close:hover) {
    background-color: var(--surface-hover, rgba(0, 0, 0, 0.04));
    color: var(--text-color, #334155);
    border-radius: 50%;
}

.popover-header {
    display: flex;
    align-items: center;
    background-color: var(--surface-section, #f8fafc);
    padding: 0.75rem 1rem;
    border-bottom: 1px solid var(--surface-border, #e2e8f0);
    color: var(--text-color, #334155);
}

/* 卡片内详情样式 */
.card-details {
    background-color: var(--surface-ground, #f9fafb);
}

/* 卡片内详情内容的特定样式 */
:deep(.card-details-content) {
    padding: 0.25rem;
}

:deep(.card-details-content .detail-item) {
    padding: 0.5rem;
    margin-bottom: 0.25rem;
    border-radius: 0.375rem;
}

:deep(.card-details-content .detail-label) {
    font-size: 0.7rem;
}

:deep(.card-details-content .detail-value) {
    font-size: 0.8rem;
}

/* 确保卡片在暗黑模式下有足够的对比度 */
:deep(.device-card) {
    background-color: var(--surface-card, white);
    border-color: var(--surface-border, #e5e7eb);
}

:deep(.card-header) {
    color: var(--text-color, #1f2937);
}

.card-title {
    color: var(--text-color, #1f2937);
}

.card-subtitle {
    color: var(--text-color-secondary, #64748b);
}

/* Popover 详情内容的特定样式 */
:deep(.popover-details-content) {
    padding: 0.5rem;
    max-width: 350px;
}

:deep(.popover-details-content .detail-item) {
    padding: 0.75rem;
    margin-bottom: 0.5rem;
    border-radius: 0.5rem;
}

:deep(.popover-details-content .detail-label) {
    font-size: 0.875rem;
}

:deep(.popover-details-content .detail-value) {
    font-size: 0.9rem;
}



/* 移动端卡片样式 */
@media (max-width: 768px) {
    .card-container {
        grid-template-columns: 1fr;
    }
}

/* 动画效果 */
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

.fade-in {
    animation: fadeIn 0.3s ease-out;
}
</style>

<template>
    <div v-if="deviceList === undefined" class="w-full flex justify-center">
        <ProgressSpinner />
    </div>

    <div v-if="deviceList !== undefined">
        <!-- 标题和控制区 -->
        <div class="flex justify-between items-center mb-4">
            <div class="text-xl font-bold">Device List</div>
            <div class="flex items-center gap-2">
                <label for="detailed-view" class="text-sm">显示详情</label>
                <InputSwitch id="detailed-view" v-model="showDetailedView" />
            </div>
        </div>

        <!-- 卡片视图 (适用于所有屏幕尺寸) -->
        <div class="card-container">
            <div 
                v-for="device in deviceList" 
                :key="device.machine_id"
                class="device-card"

            >
                <!-- 卡片头部 -->
                <div class="card-header">
                    <div class="flex-1 overflow-hidden">
                        <div class="font-semibold truncate card-title" :title="device.hostname">{{ device.hostname }}</div>
                        <div class="text-sm mt-1 truncate card-subtitle" :title="device.public_ip">{{ device.public_ip }}</div>
                    </div>
                    <div class="flex items-center space-x-2">
                        <!-- 网络数量徽章 -->
                        <span class="inline-flex items-center justify-center w-6 h-6 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                            {{ device.running_network_count }}
                        </span>
                        
                        <!-- 详情按钮 -->
                        <Button 
                            v-tooltip.focus="'查看设备详情'"
                            icon="pi pi-info-circle" 
                            severity="info" 
                            text
                            rounded
                            size="small"
                            class="w-8 h-8"
                            v-if="!showDetailedView"
                            @click="showDeviceDetails(device, $event)"
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
                
                <!-- 详情区域 - 当开启详情显示时展示 -->
                <div v-if="showDetailedView" class="card-details border-t border-gray-200 fade-in">
                    <DeviceDetails :device="device" containerClass="card-details-content" />
                </div>

            </div>
        </div>
        
        <!-- 底部按钮 -->
        <div class="flex justify-end mt-4">
            <!-- 刷新按钮 -->
            <Button icon="pi pi-refresh" label="Reload" severity="info" @click="loadDevices" />
        </div>
    </div>

    <!-- 全局设备详情 Popover -->
    <Popover 
        ref="detailPopover"
        :showCloseIcon="true"
        :closeOnEscape="true"
        :autoHide="false"
        appendTo="body"
        class="device-popover"
    >
        <template v-if="selectedDevice">
            <div class="popover-header">
                <i class="pi pi-info-circle mr-2"></i>
                <span class="font-bold">设备详情</span>
            </div>
            <div class="device-details-popover">
                <DeviceDetails :device="selectedDevice" containerClass="popover-details-content" />
            </div>
        </template>
    </Popover>

    <Drawer v-model:visible="deviceManageVisible" :header="`Manage ${selectedDeviceHostname}`" position="right"
        :baseZIndex=1000 class="w-3/5 min-w-96">
        <RouterView v-slot="{ Component }">
            <component :is="Component" :api="api" :deviceList="deviceList" @update="loadDevices" />
        </RouterView>
    </Drawer>
</template>
