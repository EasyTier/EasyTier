<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { Button, Drawer, ProgressSpinner, useToast, InputSwitch, Popover, Dropdown } from 'primevue';
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

// 抽屉布局相关
const drawerWidth = computed(() => {
    return isDesktop.value ? 'w-3/5 min-w-96' : 'w-full';
});

const drawerPosition = computed(() => {
    return isDesktop.value ? 'right' : 'bottom';
});

const drawerHeight = computed(() => {
    return isDesktop.value ? undefined : '100%';
});

// 排序相关
const sortOptions = ref([
    { name: '主机名', value: 'hostname', icon: 'pi pi-home' },
    { name: '版本', value: 'version', icon: 'pi pi-tag' },
    { name: '网络数量', value: 'networks', icon: 'pi pi-sitemap' }
]);
const selectedSortOption = ref(sortOptions.value[0]);
// 排序方向 (true为升序，false为降序)
const ascending = ref(true);

// 切换排序方向
const toggleSortDirection = () => {
    ascending.value = !ascending.value;
};

// 排序函数
const sortDevices = (devices: Array<Utils.DeviceInfo> | undefined) => {
    if (!devices) return [];

    const sortField = selectedSortOption.value.value;
    const direction = ascending.value ? 1 : -1;

    return [...devices].sort((a, b) => {
        let result = 0;

        switch (sortField) {
            case 'hostname':
                result = a.hostname.localeCompare(b.hostname);
                break;
            case 'version':
                result = a.easytier_version.localeCompare(b.easytier_version);
                break;
            case 'networks':
                result = a.running_network_count - b.running_network_count;
                break;
        }

        return result * direction;
    });
};

// 排序后的设备列表
const sortedDeviceList = computed(() => {
    return sortDevices(deviceList.value);
});

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
    position: relative;
    /* 确保子元素的绝对定位相对于此容器 */
}

/* 设备卡片样式 */
.device-card {
    border: 1px solid var(--surface-border, #e5e7eb);
    border-radius: 0.5rem;
    background: var(--surface-card, white);
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1);
    transition: transform 0.2s ease, box-shadow 0.2s ease, background-color 0.3s ease;
    display: flex;
    flex-direction: column;
    position: relative;
    overflow: hidden;
}

.device-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
}

.card-header {
    padding: 0.75rem;
    display: flex;
    flex-direction: column;
    position: relative;
    color: var(--text-color, #1f2937);
}



.device-details-popover {
    min-width: 280px;
    max-width: 350px;
    padding: 0.3rem;
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

@media (prefers-color-scheme: dark) {
    :deep(.device-popover.p-popover) {
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.5), 0 4px 6px -2px rgba(0, 0, 0, 0.25);
        border-color: var(--surface-border, #334155);
    }

    :deep(.device-popover .p-popover-content) {
        background-color: var(--surface-card, #1e293b);
        color: var(--text-color, #f1f5f9);
    }

    :deep(.device-popover .p-popover-arrow) {
        background-color: var(--surface-card, #1e293b);
        border-color: var(--surface-border, #334155);
    }

    :deep(.device-popover .p-popover-header) {
        background-color: var(--surface-section, #0f172a);
        border-bottom: 1px solid var(--surface-border, #1e293b);
    }

    :deep(.device-popover .p-popover-header-close) {
        color: var(--text-color-secondary, #94a3b8);
    }

    :deep(.device-popover .p-popover-header-close:hover) {
        background-color: var(--surface-hover, rgba(255, 255, 255, 0.1));
        color: var(--text-color, #f1f5f9);
    }

    .popover-header {
        background-color: var(--surface-section, #0f172a);
        color: var(--text-color, #f1f5f9);
        border-bottom: 1px solid var(--surface-border, #334155);
    }
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
    padding: 0.15rem 0.1rem;
}

/* 卡片中的紧凑详情内容 */
:deep(.card-details-content) {
    padding: 0.15rem 0.1rem;
}

:deep(.card-details-content .detail-label) {
    font-size: 0.9rem;
}

:deep(.card-details-content .detail-value) {
    font-size: 0.85rem;
}

@media (prefers-color-scheme: dark) {
    :deep(.card-details-content .detail-item) {
        border-bottom: 1px solid var(--surface-border, #334155);
    }

    :deep(.card-details-content .detail-item:last-child) {
        border-bottom: none;
    }

    :deep(.card-details-content .detail-item:hover) {
        background-color: var(--surface-hover, rgba(30, 41, 59, 0.4));
    }

    :deep(.card-details-content .detail-label) {
        color: var(--text-color, #e2e8f0);
    }

    :deep(.card-details-content .detail-value) {
        color: var(--text-color-secondary, #cbd5e1);
    }
}

@media (prefers-color-scheme: dark) {
    :deep(.card-details-content .detail-item) {
        border-bottom: 1px solid var(--surface-border, #334155);
    }

    :deep(.card-details-content .detail-item:last-child) {
        border-bottom: none;
    }

    :deep(.card-details-content .detail-item:hover) {
        background-color: var(--surface-hover, rgba(30, 41, 59, 0.4));
    }

    :deep(.card-details-content .detail-label) {
        color: var(--text-color, #e2e8f0);
    }

    :deep(.card-details-content .detail-value) {
        color: var(--text-color-secondary, #cbd5e1);
    }
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

.version-badge {
    background-color: var(--primary-color, #3b82f6);
    color: #ffffff;
    padding: 0.1rem 0.4rem;
    border-radius: 0.75rem;
    font-weight: 500;
    letter-spacing: 0.02em;
    font-size: 0.65rem;
}

.sort-controls {
    background-color: var(--surface-card);
    border-radius: 0.5rem;
    padding: 0.25rem 0.5rem;
    box-shadow: var(--card-shadow, 0 1px 3px rgba(0, 0, 0, 0.05));
    transition: all 0.2s;
}

.sort-controls:hover {
    box-shadow: var(--card-shadow, 0 2px 5px rgba(0, 0, 0, 0.1));
}

.sort-label {
    font-weight: 500;
    color: var(--text-color-secondary);
}

.sort-dropdown {
    min-width: 6rem;
    max-width: 9rem;
}

.sort-icon {
    font-size: 0.8rem;
}

.sort-direction-btn {
    font-size: 1rem;
    width: 2.5rem !important;
    height: 2.5rem !important;
}

/* 暗黑模式样式适配 */
@media (prefers-color-scheme: dark) {
    .sort-controls {
        background-color: var(--surface-card, #1e293b);
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
    }

    .sort-controls:hover {
        box-shadow: 0 2px 5px rgba(0, 0, 0, 0.25);
    }

    :deep(.device-card) {
        background-color: var(--surface-card, #1e293b);
        border-color: var(--surface-border, #334155);
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.3);
    }

    :deep(.card-header) {
        color: var(--text-color, #f1f5f9);
    }

    .card-title {
        color: var(--text-color, #f1f5f9);
    }

    .card-subtitle {
        color: var(--text-color-secondary, #cbd5e1);
    }

    .version-badge {
        background-color: var(--primary-color, #4f46e5);
    }

    :deep(.card-details) {
        background-color: var(--surface-ground, #0f172a);
        border-top: 1px solid var(--surface-border, #334155);
    }
}

/* Popover 详情内容的特定样式 */
:deep(.popover-details-content) {
    padding: 0.25rem 0.2rem;
    max-width: 320px;
}

/* Popover 中的紧凑详情内容 */
:deep(.popover-details-content) {
    padding: 0.25rem 0.2rem;
    max-width: 320px;
}

:deep(.popover-details-content .detail-label) {
    font-size: 0.8rem;
}

:deep(.popover-details-content .detail-value) {
    font-size: 0.8rem;
}

:deep(.popover-details-content .machine-id-value) {
    font-size: 0.7rem;
}

@media (prefers-color-scheme: dark) {
    :deep(.popover-details-content .detail-item) {
        border-bottom: 1px solid var(--surface-border, #334155);
    }

    :deep(.popover-details-content .detail-item:last-child) {
        border-bottom: none;
    }

    :deep(.popover-details-content .detail-item:hover) {
        background-color: var(--surface-hover, rgba(30, 41, 59, 0.4));
    }

    :deep(.popover-details-content .detail-label) {
        color: var(--text-color, #e2e8f0);
    }

    :deep(.popover-details-content .detail-value) {
        color: var(--text-color-secondary, #cbd5e1);
    }
}

@media (prefers-color-scheme: dark) {
    :deep(.popover-details-content .detail-item) {
        border-bottom: 1px solid var(--surface-border, #334155);
    }

    :deep(.popover-details-content .detail-item:last-child) {
        border-bottom: none;
    }

    :deep(.popover-details-content .detail-item:hover) {
        background-color: var(--surface-hover, rgba(30, 41, 59, 0.4));
    }

    :deep(.popover-details-content .detail-label) {
        color: var(--text-color, #e2e8f0);
    }

    :deep(.popover-details-content .detail-value) {
        color: var(--text-color-secondary, #cbd5e1);
    }
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

/* 抽屉响应式样式 */
:deep(.p-drawer) {
    transition: all 0.3s ease;
}

:deep(.p-drawer.p-drawer-bottom) {
    border-top-left-radius: 1rem;
    border-top-right-radius: 1rem;
    box-shadow: 0 -4px 6px -1px rgba(0, 0, 0, 0.1);
}

:deep(.p-drawer.p-drawer-bottom .p-drawer-header) {
    padding-top: 1rem;
    border-top-left-radius: 1rem;
    border-top-right-radius: 1rem;
}

:deep(.p-drawer.p-drawer-bottom .p-drawer-content) {
    padding-bottom: 2rem;
    border-top-left-radius: 1rem;
    border-top-right-radius: 1rem;
}

/* 底部抽屉的拖动指示器 */
:deep(.p-drawer.p-drawer-bottom .p-drawer-header::before) {
    content: "";
    position: absolute;
    top: 0.5rem;
    left: 50%;
    transform: translateX(-50%);
    width: 4rem;
    height: 4px;
    background-color: var(--surface-border);
    border-radius: 2px;
    opacity: 0.8;
}

@media (prefers-color-scheme: dark) {
    :deep(.p-drawer.p-drawer-bottom) {
        box-shadow: 0 -4px 12px -1px rgba(0, 0, 0, 0.3);
    }
}

.drawer-fab-close-btn {
    /* 适配移动和桌面端，防止被内容遮挡 */
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.18);
    transition: box-shadow 0.2s;
}

.drawer-fab-close-btn:hover {
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.22);
}

/* 排序控件在小屏幕下单独一行 */
.sort-controls-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

@media (max-width: 640px) {
    .sort-controls-row {
        flex-direction: column;
        align-items: stretch;
        gap: 0.5rem;
        width: 100%;
        margin-top: 0.5rem;
    }

    .sort-controls {
        width: 100%;
        justify-content: flex-start;
    }
}
</style>

<template>
    <div v-if="deviceList === undefined" class="w-full flex justify-center">
        <ProgressSpinner />
    </div>

    <div v-if="deviceList !== undefined">
        <!-- 标题和控制区 -->
        <div class="flex justify-between items-center mb-4">
            <div class="flex items-center gap-4">
                <div class="text-xl font-bold">
                    <h1>Device List</h1>
                </div>
            </div>
            <div class="flex items-center gap-2">
                <label for="detailed-view" class="text-sm">显示详情</label>
                <InputSwitch id="detailed-view" v-model="showDetailedView" />
            </div>
        </div>

        <div class="sort-controls-row flex items-center mb-4">
            <div class="flex items-center sort-controls">
                <label for="sort-by" class="text-sm mr-2 sort-label">排序</label>
                <Dropdown id="sort-by" v-model="selectedSortOption" :options="sortOptions" optionLabel="name"
                    class="sort-dropdown text-sm" panelClass="text-sm">
                    <template #value="slotProps">
                        <div class="flex items-center gap-1">
                            <i :class="[slotProps.value.icon, 'sort-icon']"></i>
                            <span>{{ slotProps.value.name }}</span>
                        </div>
                    </template>
                    <template #option="slotProps">
                        <div class="flex items-center gap-2">
                            <i :class="[slotProps.option.icon, 'sort-icon']"></i>
                            <span>{{ slotProps.option.name }}</span>
                        </div>
                    </template>
                </Dropdown>
                <Button :icon="ascending ? 'pi pi-sort-amount-up' : 'pi pi-sort-amount-down'" severity="secondary" text
                    rounded class="sort-direction-btn ml-1" v-tooltip.top="ascending ? '当前升序，点击切换为降序' : '当前降序，点击切换为升序'"
                    @click="toggleSortDirection" />
            </div>
        </div>

        <!-- 卡片视图 (适用于所有屏幕尺寸) -->
        <div class="card-container">
            <div v-for="device in sortedDeviceList" :key="device.machine_id" class="device-card">
                <!-- 卡片头部 -->
                <div class="card-header">
                    <!-- 上部区域：设备名称和版本徽章 -->
                    <div class="flex justify-between items-center mb-2">
                        <!-- 设备名称 -->
                        <div class="font-semibold truncate card-title" :title="device.hostname">{{ device.hostname }}
                        </div>

                        <!-- 版本徽章 -->
                        <div class="text-xs version-badge" v-tooltip="`EasyTier ${device.easytier_version}`">
                            v{{ device.easytier_version.split('-')[0] }}
                        </div>
                    </div>

                    <!-- 下部区域：IP地址和操作按钮 -->
                    <div class="flex justify-between items-center">
                        <!-- IP地址 -->
                        <div class="text-sm truncate card-subtitle max-w-[60%]" :title="device.public_ip">
                            {{ device.public_ip }}
                        </div>

                        <!-- 操作按钮组 -->
                        <div class="flex items-center space-x-2">
                            <!-- 网络数量徽章 -->
                            <span v-tooltip="'网络数量'"
                                class="inline-flex items-center justify-center w-6 h-6 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                                {{ device.running_network_count }}
                            </span>

                            <!-- 详情按钮 -->
                            <Button v-tooltip="'查看设备详情'" icon="pi pi-info-circle" severity="info" text rounded
                                class="w-9 h-9" v-if="!showDetailedView" @click="showDeviceDetails(device, $event)" />

                            <!-- 设置按钮 -->
                            <Button icon="pi pi-cog" @click="handleDeviceManagement(device)" severity="secondary"
                                rounded class="w-9 h-9" :title="`Manage ${device.hostname}`" />
                        </div>
                    </div>
                </div>


                <!-- 详情区域 - 当开启详情显示时展示 -->
                <div v-if="showDetailedView" class="card-details border-t border-gray-200 fade-in">
                    <DeviceDetails :device="device" containerClass="card-details-content" :compact="true" />
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
    <Popover ref="detailPopover" :showCloseIcon="true" :closeOnEscape="true" :autoHide="false" appendTo="body"
        class="device-popover">
        <template v-if="selectedDevice">
            <div class="popover-header">
                <i class="pi pi-info-circle mr-2"></i>
                <span class="font-bold">设备详情</span>
            </div>
            <div class="device-details-popover">
                <DeviceDetails :device="selectedDevice" containerClass="popover-details-content" :compact="true" />
            </div>
        </template>
    </Popover>

    <Drawer v-model:visible="deviceManageVisible" :position="drawerPosition"
        :header="`Manage ${selectedDeviceHostname}`" :baseZIndex=1000 class="" :class="drawerWidth"
        :style="{ height: drawerHeight }">
        <template #container="{ closeCallback }">
            <div style="position: relative; height: 100%;" class="device-manage-drawer">
                <RouterView v-slot="{ Component }">
                    <component :is="Component" :api="api" :deviceList="deviceList" @update="loadDevices" />
                </RouterView>
                <Button icon="pi pi-times" rounded severity="danger"
                    class="fixed z-50 right-6 bottom-6 shadow-lg drawer-fab-close-btn"
                    style="width: 3.2rem; height: 3.2rem; font-size: 1.5rem;" @click="closeCallback" />
            </div>
        </template>
    </Drawer>
</template>
