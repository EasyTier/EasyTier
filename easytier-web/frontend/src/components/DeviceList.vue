<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import ApiClient from '../modules/api';
import { Status, NetworkTypes } from 'easytier-frontend-lib'
import { Button, Column, DataTable, Drawer, Toolbar, IftaLabel, Select } from 'primevue';

function toHexString(uint64: bigint, padding = 9): string {
    let hexString = uint64.toString(16);
    while (hexString.length < padding) {
        hexString = '0' + hexString;
    }
    return hexString;
}

function uint32ToUuid(part1: number, part2: number, part3: number, part4: number): string {
    // 将两个 uint64 转换为 16 进制字符串
    const part1Hex = toHexString(BigInt(part1), 8);
    const part2Hex = toHexString(BigInt(part2), 8);
    const part3Hex = toHexString(BigInt(part3), 8);
    const part4Hex = toHexString(BigInt(part4), 8);

    // 构造 UUID 格式字符串
    const uuid = `${part1Hex.substring(0, 8)}-${part2Hex.substring(0, 4)}-${part2Hex.substring(4, 8)}-${part3Hex.substring(0, 4)}-${part3Hex.substring(4, 8)}${part4Hex.substring(0, 12)}`;

    return uuid;
}

interface UUID {
    part1: number;
    part2: number;
    part3: number;
    part4: number;
}

function UuidToStr(uuid: UUID): string {
    return uint32ToUuid(uuid.part1, uuid.part2, uuid.part3, uuid.part4);
}

const props = defineProps({
    api: ApiClient,
});

const api = props.api;

interface DeviceList {
    hostname: string;
    public_ip: string;
    running_network_count: number;
    report_time: string;
    easytier_version: string;
    running_network_instances?: Array<string>;
    machine_id: string;
}

const selectedDevice = ref<DeviceList | null>(null);
const deviceList = ref<Array<DeviceList>>([]);
const instanceIdList = computed(() => {
    let insts = selectedDevice.value?.running_network_instances || [];
    let options = insts.map((instance: string) => {
        return { uuid: instance };
    });
    console.log("options", options);
    return options;
});
const selectedInstanceId = ref<string | null>(null);
const curNetworkInfo = ref<NetworkTypes.NetworkInstance | null>(null);

const loadDevices = async () => {
    const resp = await api?.list_machines();
    console.log(resp);
    let devices: Array<DeviceList> = [];
    for (const device of (resp || [])) {
        devices.push({
            hostname: device.info?.hostname,
            public_ip: device.client_url,
            running_network_instances: device.info?.running_network_instances.map((instance: any) => UuidToStr(instance)),
            running_network_count: device.info?.running_network_instances.length,
            report_time: device.info?.report_time,
            easytier_version: device.info?.easytier_version,
            machine_id: UuidToStr(device.info?.machine_id),
        });
    }
    deviceList.value = devices;
    console.log(deviceList.value);
};

const loadDeviceInfo = async () => {
    console.log("loadDeviceInfo");
    let machine_id = selectedDevice.value?.machine_id;
    let inst_id = selectedInstanceId.value?.uuid;
    console.log("machine_id", machine_id, "inst_id", inst_id);
    if (!machine_id || !inst_id) {
        return;
    }

    let ret = await api?.get_network_info(machine_id, inst_id);
    let device_info = ret[inst_id]
    console.log("network info", device_info);

    curNetworkInfo.value = {
        instance_id: inst_id,
        running: device_info.running,
        error_msg: device_info.error_msg,
        detail: device_info,
    } as NetworkTypes.NetworkInstance;
}

onMounted(async () => {
    await loadDevices();
    setInterval(loadDeviceInfo, 1000);
});

const visibleRight = ref(false);

</script>

<style scoped></style>

<template>
    <DataTable :value="deviceList" tableStyle="min-width: 50rem" @rowSelect="visibleRight = true"
        @rowUnselect="visibleRight = false" selectionMode="single" v-model:selection="selectedDevice" :metaKeySelection="true">
        <template #header>
            <div class="text-xl font-bold">Device List</div>
        </template>
        <Column field="hostname" header="Hostname" sortable style="width: 180px"></Column>
        <Column field="public_ip" header="Public IP" style="width: 150px"></Column>
        <Column field="running_network_count" header="Running Network Count" sortable style="width: 150px"></Column>
        <Column field="report_time" header="Report Time" sortable style="width: 150px"></Column>
        <Column field="easytier_version" header="EasyTier Version" sortable style="width: 150px"></Column>
        <template #footer>
            <div class="flex justify-start">
                <Button icon="pi pi-refresh" label="Reload" severity="warn" @click="loadDevices" />
            </div>
        </template>
    </DataTable>

    <Drawer v-model:visible="visibleRight" header="Right Drawer" position="right" class="w-1/3">
        <Toolbar>
            <template #start>
                <IftaLabel>
                    <Select v-model="selectedInstanceId" :options="instanceIdList" optionLabel="uuid" inputId="dd-inst-id"
                        placeholder="Select Instance" />
                    <label class="mr-3" for="dd-inst-id">Network</label>
                </IftaLabel>
            </template>

            <template #end>
                <Button>Create New Network</Button>
            </template>
        </Toolbar>

        <Status v-bind:cur-network-inst="curNetworkInfo">

        </Status>
    </Drawer>
</template>
