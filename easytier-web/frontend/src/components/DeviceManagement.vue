<script setup lang="ts">
import { NetworkTypes, Utils, Api, RemoteManagement } from 'easytier-frontend-lib';
import { computed } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import ApiClient from '../modules/api';


const props = defineProps<{
    api: ApiClient;
    deviceList: Array<Utils.DeviceInfo> | undefined;
}>();

const emits = defineEmits(['update']);

const route = useRoute();
const router = useRouter();

const deviceId = computed<string>(() => {
    return route.params.deviceId as string;
});

const instanceId = computed<string>(() => {
    return route.params.instanceId as string;
});

const deviceInfo = computed<Utils.DeviceInfo | undefined | null>(() => {
    return deviceId.value ? props.deviceList?.find((device) => device.machine_id === deviceId.value) : null;
});

const selectedInstanceId = computed({
    get() {
        return instanceId.value;
    },
    set(value: string) {
        console.log("selectedInstanceId", value);
        router.push({ name: 'deviceManagement', params: { deviceId: deviceId.value, instanceId: value } });
    }
});

const remoteClient = computed<Api.RemoteClient>(() => props.api.get_remote_client(deviceId.value));

const newConfigGenerator = () => {
    const config = NetworkTypes.DEFAULT_NETWORK_CONFIG();
    config.hostname = deviceInfo.value?.hostname;
    return config;
}

</script>

<template>
    <RemoteManagement :api="remoteClient" v-model:instance-id="selectedInstanceId"
        :new-config-generator="newConfigGenerator" />
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