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

</script>

<style scoped></style>

<template>
    <div v-if="deviceList === undefined" class="w-full flex justify-center">
        <ProgressSpinner />
    </div>

    <DataTable :value="deviceList" tableStyle="min-width: 50rem" :metaKeySelection="true" sortField="hostname"
        :sortOrder="-1" v-if="deviceList !== undefined">
        <template #header>
            <div class="text-xl font-bold">Device List</div>
        </template>

        <Column field="hostname" header="Hostname" sortable style="width: 180px"></Column>
        <Column field="public_ip" header="Public IP" style="width: 150px"></Column>
        <Column field="running_network_count" header="Running Network Count" sortable style="width: 150px"></Column>
        <Column field="report_time" header="Report Time" sortable style="width: 150px"></Column>
        <Column field="easytier_version" header="EasyTier Version" sortable style="width: 150px"></Column>
        <Column class="w-24 !text-end">
            <template #body="{ data }">
                <Button icon="pi pi-cog"
                    @click="router.push({ name: 'deviceManagement', params: { deviceId: data.machine_id, instanceId: data.running_network_instances[0] } })"
                    severity="secondary" rounded></Button>
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
