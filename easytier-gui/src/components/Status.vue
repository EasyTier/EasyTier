<script setup lang="ts">

import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useNetworkStore } from '../main';

const networkStore = useNetworkStore();

const props = defineProps<{
    instanceId?: string,
}>()

const curNetwork = computed(() => {
    if (props.instanceId) {
        console.log("instanceId", props.instanceId);
        const c = networkStore.networkList.find(n => n.instance_id == props.instanceId);
        if (c != undefined) {
            return c;
        }
    }

    return networkStore.curNetwork;
});

let curNetworkInst = computed(() => {
    return networkStore.networkInstances.find(n => n.instance_id == curNetwork.value.instance_id);
});

let peerRouteInfos = computed(() => {
    if (curNetworkInst.value) {
        return curNetworkInst.value.detail.peer_route_pairs;
    }
    return [];
});

let routeCost = (info: any) => {
    if (info.route) {
        const cost = info.route.cost;
        return cost == 1 ? "p2p" : `relay(${cost})`
    }
    return '?';
};

function resolveObjPath(path: string, obj = self, separator = '.') {
    var properties = Array.isArray(path) ? path : path.split(separator)
    return properties.reduce((prev, curr) => prev?.[curr], obj)
}

let statsCommon = (info: any, field: string) => {
    if (!info.peer) {
        return undefined;
    }
    let conns = info.peer.conns;
    return conns.reduce((acc: number, conn: any) => {
        return acc + resolveObjPath(field, conn);
    }, 0);
};

function humanFileSize(bytes: number, si = false, dp = 1) {
    const thresh = si ? 1000 : 1024;

    if (Math.abs(bytes) < thresh) {
        return bytes + ' B';
    }

    const units = si
        ? ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
        : ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB'];
    let u = -1;
    const r = 10 ** dp;

    do {
        bytes /= thresh;
        ++u;
    } while (Math.round(Math.abs(bytes) * r) / r >= thresh && u < units.length - 1);


    return bytes.toFixed(dp) + ' ' + units[u];
}

let latencyMs = (info: any) => {
    let lat_us_sum = statsCommon(info, 'stats.latency_us');
    return lat_us_sum ? `${lat_us_sum / 1000 / info.peer.conns.length}ms` : '';
};

let txBytes = (info: any) => {
    let tx = statsCommon(info, 'stats.tx_bytes');
    return tx ? humanFileSize(tx) : '';
}

let rxBytes = (info: any) => {
    let rx = statsCommon(info, 'stats.rx_bytes');
    return rx ? humanFileSize(rx) : '';
}

let lossRate = (info: any) => {
    let lossRate = statsCommon(info, 'loss_rate');
    return lossRate != undefined ? `${Math.round(lossRate * 100)}%` : '';
}

const myNodeInfo = computed(() => {
    if (!curNetworkInst.value) {
        return {};
    }
    return curNetworkInst.value.detail?.my_node_info;
});

interface Chip {
    label: string;
    icon: string;
}

let myNodeInfoChips = computed(() => {
    if (!curNetworkInst.value) {
        return [];
    }

    let chips: Array<Chip> = [];
    let my_node_info = curNetworkInst.value.detail?.my_node_info;
    if (!my_node_info) {
        return chips;
    }

    // local ipv4s
    let local_ipv4s = my_node_info.ips?.interface_ipv4s;
    for (let [idx, ip] of local_ipv4s?.entries()) {
        chips.push({
            label: `Local IPv4 ${idx}: ${ip}`,
            icon: '',
        } as Chip);
    }

    // local ipv6s
    let local_ipv6s = my_node_info.ips?.interface_ipv6s;
    for (let [idx, ip] of local_ipv6s?.entries()) {
        chips.push({
            label: `Local IPv6 ${idx}: ${ip}`,
            icon: '',
        } as Chip);
    }

    // public ip
    let public_ip = my_node_info.ips?.public_ipv4;
    if (public_ip) {
        chips.push({
            label: `Public IP: ${public_ip}`,
            icon: '',
        } as Chip);
    }


    // listeners:
    let listeners = my_node_info.listeners;
    for (let [idx, listener] of listeners?.entries()) {
        chips.push({
            label: `Listener ${idx}: ${listener}`,
            icon: '',
        } as Chip);
    }

    // udp nat type
    enum NatType {
        // has NAT; but own a single public IP, port is not changed
        Unknown = 0,
        OpenInternet = 1,
        NoPAT = 2,
        FullCone = 3,
        Restricted = 4,
        PortRestricted = 5,
        Symmetric = 6,
        SymUdpFirewall = 7,
    };
    let udpNatType: NatType = my_node_info.stun_info?.udp_nat_type;
    if (udpNatType != undefined) {
        let udpNatTypeStrMap = {
            [NatType.Unknown]: 'Unknown',
            [NatType.OpenInternet]: 'Open Internet',
            [NatType.NoPAT]: 'No PAT',
            [NatType.FullCone]: 'Full Cone',
            [NatType.Restricted]: 'Restricted',
            [NatType.PortRestricted]: 'Port Restricted',
            [NatType.Symmetric]: 'Symmetric',
            [NatType.SymUdpFirewall]: 'Symmetric UDP Firewall',
        };

        chips.push({
            label: `UDP NAT Type: ${udpNatTypeStrMap[udpNatType]}`,
            icon: '',
        } as Chip);

    }

    return chips;
});

const globalSumCommon = (field: string) => {
    let sum = 0;
    if (!peerRouteInfos.value) {
        return sum;
    }
    for (let info of peerRouteInfos.value) {
        let tx = statsCommon(info, field);
        if (tx) {
            sum += tx;
        }
    }
    return sum;
};

const txGlobalSum = () => {
    return globalSumCommon('stats.tx_bytes');
};

const rxGlobalSum = () => {
    return globalSumCommon('stats.rx_bytes');
}


const peerCount = computed(() => {
    if (!peerRouteInfos.value) {
        return 0;
    }
    return peerRouteInfos.value.length;
});

// calculate tx/rx rate every 2 seconds
let rateIntervalId = 0;
let rateInterval = 2000;
let prevTxSum = 0;
let prevRxSum = 0;
let txRate = ref('0');
let rxRate = ref('0');
onMounted(() => {
    rateIntervalId = setInterval(() => {
        let curTxSum = txGlobalSum();
        txRate.value = humanFileSize((curTxSum - prevTxSum) / (rateInterval / 1000));
        prevTxSum = curTxSum;

        let curRxSum = rxGlobalSum();
        rxRate.value = humanFileSize((curRxSum - prevRxSum) / (rateInterval / 1000));
        prevRxSum = curRxSum;
    }, rateInterval);
});

onUnmounted(() => {
    clearInterval(rateIntervalId);
});

const dialogVisible = ref(false);
const dialogContent = ref('');

const showVpnPortalConfig = () => {
    let my_node_info = myNodeInfo.value;
    if (!my_node_info) {
        return;
    }
    const url = "https://www.wireguardconfig.com/qrcode";
    dialogContent.value = `${my_node_info.vpn_portal_cfg}\n\n # can generate QR code: ${url}`;
    dialogVisible.value = true;
}

const showEventLogs = () => {
    let detail = curNetworkInst.value?.detail;
    if (!detail) {
        return;
    }
    dialogContent.value = detail.events;
    dialogVisible.value = true;
}

</script>

<template>
    <div>
        <Dialog v-model:visible="dialogVisible" modal header="Dialog" :style="{ width: '70%' }">
            <Panel>
                <ScrollPanel style="width: 100%; height: 400px">
                    <pre>{{ dialogContent }}</pre>
                </ScrollPanel>
            </Panel>
            <Divider />
            <div class="flex justify-content-end gap-2">
                <Button type="button" label="Close" @click="dialogVisible = false"></Button>
            </div>
        </Dialog>

        <Card v-if="curNetworkInst?.error_msg">
            <template #title>Run Network Error</template>
            <template #content>
                <div class="flex flex-column gap-y-5">
                    <div class="text-red-500">
                        {{ curNetworkInst.error_msg }}
                    </div>
                </div>
            </template>
        </Card>

        <Card v-if="!curNetworkInst?.error_msg">
            <template #title>{{ $t('my_node_info') }}</template>
            <template #content>
                <div class="flex w-full flex-column gap-y-5">
                    <div class="m-0 flex flex-row justify-center gap-x-5">
                        <div class="rounded-full w-36 h-36 flex flex-column align-items-center pt-4"
                            style="border: 1px solid green">
                            <div class="font-bold">
                                {{ $t('peer_count') }}
                            </div>
                            <div class="text-5xl mt-1">{{ peerCount }}</div>
                        </div>

                        <div class="rounded-full w-36 h-36 flex flex-column align-items-center pt-4"
                            style="border: 1px solid purple">
                            <div class="font-bold">
                                {{ $t('upload') }}
                            </div>
                            <div class="text-xl mt-2">{{ txRate }}/s</div>
                        </div>

                        <div class="rounded-full w-36 h-36 flex flex-column align-items-center pt-4"
                            style="border: 1px solid fuchsia">
                            <div class="font-bold">
                                {{ $t('download') }}
                            </div>
                            <div class="text-xl mt-2">{{ rxRate }}/s</div>
                        </div>
                    </div>

                    <div class="flex flex-row align-items-center flex-wrap w-full">
                        <Chip v-for="chip in myNodeInfoChips" :label="chip.label" :icon="chip.icon" class="mr-2 mt-2">
                        </Chip>
                    </div>

                    <div class="m-0 flex flex-row justify-center gap-x-5 text-sm" v-if="myNodeInfo">
                        <Button severity="info" :label="$t('show_vpn_portal_config')" @click="showVpnPortalConfig" />
                        <Button severity="info" :label="$t('show_event_log')" @click="showEventLogs" />
                    </div>
                </div>
            </template>
        </Card>

        <Divider />

        <Card v-if="!curNetworkInst?.error_msg">
            <template #title>{{ $t('peer_info') }}</template>
            <template #content>
                <DataTable :value="peerRouteInfos" tableStyle="min-width: 50rem">
                    <Column field="route.ipv4_addr" :header="$t('virtual_ipv4')"></Column>
                    <Column field="route.hostname" :header="$t('hostname')"></Column>
                    <Column :field="routeCost" :header="$t('route_cost')"></Column>
                    <Column :field="latencyMs" :header="$t('latency')"></Column>
                    <Column :field="txBytes" :header="$t('upload_bytes')"></Column>
                    <Column :field="rxBytes" :header="$t('download_bytes')"></Column>
                    <Column :field="lossRate" :header="$t('loss_rate')"></Column>
                </DataTable>
            </template>
        </Card>

    </div>
</template>