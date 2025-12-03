<script setup lang="ts">
import { Card, useToast } from 'primevue';
import { computed, onMounted, onUnmounted, ref, watch } from 'vue';
import { Utils } from 'easytier-frontend-lib';
import ApiClient, { Summary, ServerStats, SystemStats, NetStats, ProcessInfo } from '../modules/api';
import * as echarts from 'echarts';
import { useBackgroundSettings } from '../modules/backgroundSettings';

const props = defineProps({
    api: ApiClient,
});

const toast = useToast();

const summary = ref<Summary | undefined>(undefined);
const serverStats = ref<ServerStats | undefined>(undefined);
const systemStats = ref<SystemStats | undefined>(undefined);
const netStats = ref<NetStats | undefined>(undefined);
const processInfo = ref<ProcessInfo | undefined>(undefined);

const loadSummary = async () => {
    const resp = await props.api?.get_summary();
    summary.value = resp;
};

const loadServerStats = async () => {
    const resp = await props.api?.get_server_stats();
    serverStats.value = resp;
};

const loadSystemStats = async () => {
    const resp = await props.api?.get_system_stats();
    systemStats.value = resp;
    if (resp) {
        const timeLabel = new Date(resp.timestamp * 1000).toLocaleTimeString();
        labels.value.push(timeLabel);
        cpuSeries.value.push(Number(resp.cpu_percent.toFixed(2)));
        memSeries.value.push(Number(resp.mem_percent.toFixed(2)));
        if (labels.value.length > maxPoints) {
            labels.value.shift();
            cpuSeries.value.shift();
            memSeries.value.shift();
        }
        updateChart();
    }
};

const loadNetStats = async () => {
    const resp = await props.api?.get_net_stats();
    netStats.value = resp;
    if (resp) {
        const timeLabel = new Date(resp.timestamp * 1000).toLocaleTimeString();
        netLabels.value.push(timeLabel);
        rxSeries.value.push(Number(resp.rx_mbps.toFixed(3)));
        txSeries.value.push(Number(resp.tx_mbps.toFixed(3)));
        if (netLabels.value.length > maxPoints) {
            netLabels.value.shift();
            rxSeries.value.shift();
            txSeries.value.shift();
        }
        updateNetChart();
    }
};

const loadProcessInfo = async () => {
    const resp = await props.api?.get_process_info();
    processInfo.value = resp;
};

const summaryTask = new Utils.PeriodicTask(async () => {
    try {
        await loadSummary();
    } catch (e) {
        toast.add({ severity: 'error', summary: 'Load Summary Failed', detail: e, life: 2000 });
        console.error(e);
    }
}, 5000);

const statsTask = new Utils.PeriodicTask(async () => {
    try {
        await loadServerStats();
    } catch (e) {
        toast.add({ severity: 'error', summary: 'Load Server Stats Failed', detail: e, life: 2000 });
        console.error(e);
    }
}, 5000);

const sysTask = new Utils.PeriodicTask(async () => {
    try {
        await loadSystemStats();
    } catch (e) {
        toast.add({ severity: 'error', summary: 'Load System Stats Failed', detail: e, life: 2000 });
        console.error(e);
    }
}, 5000);

const netTask = new Utils.PeriodicTask(async () => {
    try {
        await loadNetStats();
    } catch (e) {
        toast.add({ severity: 'error', summary: 'Load Net Stats Failed', detail: e, life: 2000 });
        console.error(e);
    }
}, 5000);

const procTask = new Utils.PeriodicTask(async () => {
    try {
        await loadProcessInfo();
    } catch (e) {
        toast.add({ severity: 'error', summary: 'Load Process Info Failed', detail: e, life: 2000 });
        console.error(e);
    }
}, 5000);

onMounted(async () => {
    summaryTask.start();
    statsTask.start();
    sysTask.start();
    netTask.start();
    procTask.start();
    await loadSummary();
    await loadServerStats();
    await loadSystemStats();
    await loadNetStats();
    await loadProcessInfo();
    initChart();
    initNetChart();
});

onUnmounted(() => {
    summaryTask.stop();
    statsTask.stop();
    sysTask.stop();
    netTask.stop();
    procTask.stop();
    if (chart.value) {
        chart.value.dispose();
    }
    if (netChart.value) {
        netChart.value.dispose();
    }
});

const deviceCount = computed<number | undefined>(
    () => {
        return summary.value?.device_count;
    },
);

const configInfo = computed(() => ({
    port: serverStats.value?.config_server_port,
    protocol: serverStats.value?.config_server_protocol,
    connections: serverStats.value?.config_active_connections,
}));

const apiInfo = computed(() => ({
    port: serverStats.value?.api_server_port,
    connections: serverStats.value?.api_active_requests,
}));

const { state: bgState } = useBackgroundSettings();
const chromeOpacity = computed(() => Math.min((bgState.mainOpacity ?? 0) + 0.25, 1));

const chartRef = ref<HTMLDivElement | null>(null);
const chart = ref<echarts.ECharts | null>(null);
const labels = ref<string[]>([]);
const cpuSeries = ref<number[]>([]);
const memSeries = ref<number[]>([]);
const maxPoints = 120; // 10 minutes at 5s interval

const initChart = () => {
    if (!chartRef.value) return;
    chart.value = echarts.init(chartRef.value);
    applyCanvasStyle(chartRef.value);
    updateChart();
};

const updateChart = () => {
    if (!chart.value) return;
    chart.value.setOption({
        textStyle: { fontFamily: 'Times New Roman', fontWeight: 'bold' },
        tooltip: { trigger: 'axis' },
        legend: { data: ['CPU (%)', 'Memory (%)'] },
        grid: { left: '3%', right: '6%', bottom: '10%', containLabel: true },
        xAxis: {
            type: 'category',
            data: labels.value,
            boundaryGap: false,
        },
        yAxis: [
            {
                type: 'value',
                name: 'CPU (%)',
                min: 0,
                max: 100,
            },
            {
                type: 'value',
                name: 'Memory (%)',
                min: 0,
                max: 100,
                position: 'right',
            },
        ],
        series: [
            {
                name: 'CPU (%)',
                type: 'line',
                data: cpuSeries.value,
                showSymbol: false,
                smooth: true,
                lineStyle: { color: '#ef4444' },
            },
            {
                name: 'Memory (%)',
                type: 'line',
                data: memSeries.value,
                yAxisIndex: 1,
                showSymbol: false,
                smooth: true,
                lineStyle: { color: '#3b82f6' },
            },
        ],
    });
};

watch(labels, () => updateChart());
watch(cpuSeries, () => updateChart());
watch(memSeries, () => updateChart());

const netChartRef = ref<HTMLDivElement | null>(null);
const netChart = ref<echarts.ECharts | null>(null);
const netLabels = ref<string[]>([]);
const rxSeries = ref<number[]>([]);
const txSeries = ref<number[]>([]);

const initNetChart = () => {
    if (!netChartRef.value) return;
    netChart.value = echarts.init(netChartRef.value);
    applyCanvasStyle(netChartRef.value);
    updateNetChart();
};

const updateNetChart = () => {
    if (!netChart.value) return;
    netChart.value.setOption({
        textStyle: { fontFamily: 'Times New Roman', fontWeight: 'bold' },
        tooltip: { trigger: 'axis' },
        legend: { data: ['Downlink (Mbps)', 'Uplink (Mbps)'] },
        grid: { left: '3%', right: '6%', bottom: '10%', containLabel: true },
        xAxis: {
            type: 'category',
            data: netLabels.value,
            boundaryGap: false,
        },
        yAxis: [
            {
                type: 'value',
                min: 0,
                name: 'Mbps',
            },
        ],
        series: [
            {
                name: 'Downlink (Mbps)',
                type: 'line',
                data: rxSeries.value,
                showSymbol: false,
                smooth: true,
                lineStyle: { color: 'rgb(174,121,255)' },
            },
            {
                name: 'Uplink (Mbps)',
                type: 'line',
                data: txSeries.value,
                showSymbol: false,
                smooth: true,
                lineStyle: { color: 'rgb(0,194,250)' },
            },
        ],
    });
};

watch(netLabels, () => updateNetChart());
watch(rxSeries, () => updateNetChart());
watch(txSeries, () => updateNetChart());

const applyCanvasStyle = (container: HTMLElement) => {
    const canvas = container.querySelector('canvas[data-zr-dom-id]');
    if (canvas instanceof HTMLCanvasElement) {
        canvas.style.opacity = `${chromeOpacity.value}`;
        canvas.style.fontFamily = 'Times New Roman';
        canvas.style.fontWeight = 'bold';
    }
};

</script>

<template>
    <div class="grid grid-cols-3 gap-4">
        <Card class="h-full">
            <template #title>Device Count</template>
            <template #content>
                <div class="w-full flex justify-center text-7xl font-bold text-green-800 mt-4">
                    {{ deviceCount }}
                </div>
            </template>
        </Card>
        <Card class="h-full">
            <template #title>Config Server</template>
            <template #content>
                <div class="space-y-2">
                    <div class="text-lg">Port: {{ configInfo.port }} ({{ configInfo.protocol }})</div>
                    <div class="w-full flex justify-center text-7xl font-bold text-green-800 mt-4">
                        {{ configInfo.connections }}
                    </div>
                </div>
            </template>
        </Card>
        <Card class="h-full">
            <template #title>API Server</template>
            <template #content>
                <div class="space-y-2">
                    <div class="text-lg">Port: {{ apiInfo.port }}</div>
                    <div class="w-full flex justify-center text-7xl font-bold text-green-800 mt-4">
                        {{ apiInfo.connections }}
                    </div>
                </div>
            </template>
        </Card>
    </div>

    <div class="p-4 border-2 border-gray-200 border-dashed rounded-lg dark:border-gray-700 mt-4">
        <div ref="chartRef" class="w-full" style="height: 360px;"></div>
    </div>

    <div class="p-4 border-2 border-gray-200 border-dashed rounded-lg dark:border-gray-700 mt-4">
        <div ref="netChartRef" class="w-full" style="height: 360px;"></div>
    </div>

    <div class="p-4 border-2 border-gray-200 border-dashed rounded-lg dark:border-gray-700 mt-4">
        <h3 class="text-xl font-semibold text-center mb-4">服务器信息</h3>
        <div class="space-y-2">
            <div class="flex justify-between">
                <span>进程启动时间</span>
                <span class="text-right">{{ processInfo?.start_time }}</span>
            </div>
            <div class="flex justify-between">
                <span>查询时间</span>
                <span class="text-right">{{ processInfo?.query_time }}</span>
            </div>
            <div class="flex justify-between">
                <span>进程已打开句柄数</span>
                <span class="text-right">{{ processInfo?.open_handles }}</span>
            </div>
            <div class="flex justify-between">
                <span>协程数</span>
                <span class="text-right">{{ processInfo?.threads }}</span>
            </div>
            <div class="flex justify-between">
                <span>进程占用内存 (MB)</span>
                <span class="text-right">{{ processInfo?.memory_mb.toFixed(2) }}</span>
            </div>
            <div class="flex justify-between">
                <span>GC总次数</span>
                <span class="text-right">{{ processInfo?.gc_count }}</span>
            </div>
            <div class="flex justify-between">
                <span>堆占用内存 (MB)</span>
                <span class="text-right">{{ processInfo?.heap_mb.toFixed(2) }}</span>
            </div>
        </div>
    </div>

</template>
