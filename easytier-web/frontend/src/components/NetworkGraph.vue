<script setup lang="ts">
import { Card, Button, Dialog, ProgressSpinner } from 'primevue';
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue';
import { Utils, type Api, type NetworkTypes } from 'easytier-frontend-lib';
import * as echarts from 'echarts';
import ApiClient from '../modules/api';

const props = defineProps<{
  api: ApiClient;
}>();

interface GraphNode {
  id: string;
  name: string;
  ip?: string;
  version?: string;
  nat?: string;
}

interface GraphEdge {
  source: string;
  target: string;
  latencyMs?: number;
  lossRate?: number;
}

const loading = ref(false);
const networkCards = ref<Array<string>>([]);
const graphData = ref<Record<string, { nodes: GraphNode[]; edges: GraphEdge[] }>>({});

const selectedNetwork = ref<string | null>(null);
const dialogVisible = ref(false);
const chartRef = ref<HTMLDivElement | null>(null);
const chartInstance = ref<echarts.ECharts | null>(null);
const dialogStyle = computed(() => ({
  width: '80vw',
  height: '80vh',
}));
const isHoverRefreshing = ref(false);
const lastHoverRefresh = ref(0);
const hoverRefreshIntervalMs = 1000;

const hasData = computed(() => networkCards.value.length > 0);

const uniqueEdgeKey = (edge: GraphEdge) => {
  const [a, b] = [edge.source, edge.target].sort();
  return `${a}-${b}`;
};

const formatIpv4 = (addr?: number): string | undefined => {
  if (addr === undefined || addr === null) return undefined;
  return [
    (addr >> 24) & 0xff,
    (addr >> 16) & 0xff,
    (addr >> 8) & 0xff,
    addr & 0xff,
  ].join('.');
};

const natLabel = (nat?: number): string | undefined => {
  if (nat === undefined || nat === null) return undefined;
  const mapping: Record<number, string> = {
    0: 'Unknown',
    1: 'Open Internet',
    2: 'No PAT',
    3: 'Full Cone',
    4: 'Restricted',
    5: 'Port Restricted',
    6: 'Symmetric',
    7: 'Symmetric UDP Firewall',
    8: 'Symmetric Easy Inc',
    9: 'Symmetric Easy Dec',
  };
  return mapping[nat] || `NAT-${nat}`;
};

const buildGraph = async () => {
  loading.value = true;
  try {
    const devicesRaw = await props.api.list_machines();
    const devices = (devicesRaw || []).map((dev) => Utils.buildDeviceInfo(dev));

    const grouped: Record<string, { nodes: Map<string, GraphNode>; edges: Map<string, GraphEdge> }> = {};

    for (const device of devices) {
      const instanceIds = device.running_network_instances || [];
      if (instanceIds.length === 0) continue;
      const remote = props.api.get_remote_client(device.machine_id) as Api.RemoteClient;
      const metasResp = await remote.get_network_metas(instanceIds);

      // fetch running info for each instance to build topology
      for (const instId of instanceIds) {
        const meta = metasResp.metas[instId];
        const networkName = meta?.network_name || 'Unknown';
        const runningInfo = await remote.get_network_info(instId) as NetworkTypes.NetworkInstanceRunningInfo | undefined;
        if (!grouped[networkName]) {
          grouped[networkName] = { nodes: new Map(), edges: new Map() };
        }
        const group = grouped[networkName];

        if (!runningInfo) continue;

        // Prepare helpful lookups
        const routeNameMap = new Map<number, string>();
        runningInfo.routes.forEach((route) => {
          routeNameMap.set(route.peer_id, route.hostname);
        });

        // Determine my peer id from connections (fallback to hostname-hash)
        const connWithMyId = runningInfo.peers.find((p) => p.conns?.[0]?.my_peer_id !== undefined);
        const myPeerId = connWithMyId?.conns[0].my_peer_id ?? Number(runningInfo.my_node_info.virtual_ipv4.address.addr || Math.random() * 1e6);
        const myNodeId = myPeerId.toString();
        if (!group.nodes.has(myNodeId)) {
          group.nodes.set(myNodeId, {
            id: myNodeId,
            name: runningInfo.my_node_info.hostname || device.hostname,
            ip: formatIpv4(runningInfo.my_node_info.virtual_ipv4.address.addr),
            version: runningInfo.my_node_info.version || device.easytier_version,
            nat: natLabel(runningInfo.my_node_info.stun_info?.udp_nat_type),
          });
        }

        // Build edges to peers
        runningInfo.peers.forEach((peer) => {
          const peerId = peer.peer_id.toString();
          const peerRoute = runningInfo.routes.find((r) => r.peer_id === peer.peer_id);
          if (!group.nodes.has(peerId)) {
            const peerName = routeNameMap.get(peer.peer_id) || peerRoute?.hostname || `Peer ${peer.peer_id}`;
            group.nodes.set(peerId, {
              id: peerId,
              name: peerName,
              ip: typeof peerRoute?.ipv4_addr === 'object' ? formatIpv4((peerRoute?.ipv4_addr as any)?.address?.addr) : undefined,
              version: peerRoute?.version,
              nat: natLabel(peerRoute?.stun_info?.udp_nat_type),
            });
          }
          const stats = peer.conns?.[0]?.stats;
          const edge: GraphEdge = {
            source: myNodeId,
            target: peerId,
            latencyMs: stats?.latency_us !== undefined ? stats.latency_us / 1000 : undefined,
            lossRate: peer.conns?.[0]?.loss_rate,
          };
          const key = uniqueEdgeKey(edge);
          if (!group.edges.has(key)) {
            group.edges.set(key, edge);
          }
        });
      }
    }

    networkCards.value = Object.keys(grouped);
    graphData.value = Object.fromEntries(
      Object.entries(grouped).map(([name, data]) => [
        name,
        {
          nodes: Array.from(data.nodes.values()),
          edges: Array.from(data.edges.values()),
        },
      ]),
    );
  } finally {
    loading.value = false;
  }
};

const openNetwork = async (networkName: string) => {
  selectedNetwork.value = networkName;
  dialogVisible.value = true;
  await nextTick();
  renderChart();
};

const renderChart = () => {
  if (!chartRef.value || !selectedNetwork.value) return;
  if (!chartInstance.value) {
    chartInstance.value = echarts.init(chartRef.value);
  }

  const data = graphData.value[selectedNetwork.value] || { nodes: [], edges: [] };

  // Preserve existing node positions to avoid jumping
  const existingPositions = new Map<string, { x: number; y: number }>();
  const existing = chartInstance.value.getOption() as any;
  const prevData = existing?.series?.[0]?.data || [];
  prevData.forEach((d: any) => {
    if (d?.id !== undefined && d.x !== undefined && d.y !== undefined) {
      existingPositions.set(String(d.id), { x: d.x, y: d.y });
    }
  });

  const seriesData = data.nodes.map((n) => {
    const pos = existingPositions.get(n.id);
    return {
      ...n,
      value: n.name,
      symbolSize: 45,
      x: pos?.x,
      y: pos?.y,
      itemStyle: {
        color: {
          type: 'radial',
          x: 0.3,
          y: 0.3,
          r: 0.8,
          colorStops: [
            { offset: 0, color: '#ffffff' },
            { offset: 1, color: '#60a5fa' },
          ],
        },
        shadowBlur: 16,
        shadowColor: 'rgba(0,0,0,0.25)',
      },
    };
  });

  const layoutMode = existingPositions.size > 0 ? 'none' : 'force';

  chartInstance.value.setOption({
    tooltip: {
      formatter: (params: any) => {
        if (params.dataType === 'edge') {
          const data = params.data as GraphEdge;
          const latency = data.latencyMs !== undefined ? `${data.latencyMs.toFixed(2)} ms` : 'N/A';
          const loss = data.lossRate !== undefined ? `${(data.lossRate * 100).toFixed(2)} %` : 'N/A';
          return `Latency: ${latency}<br/>Loss: ${loss}`;
        }
        if (params.dataType === 'node') {
          const node = params.data as GraphNode;
          const ip = node.ip || 'N/A';
          const version = node.version || 'Unknown';
          const nat = node.nat || 'Unknown';
          return `IP: ${ip}<br/>Version: ${version}<br/>NAT: ${nat}`;
        }
        return params.name || '';
      },
    },
    legend: [{ data: ['Node'] }],
    series: [
      {
        type: 'graph',
        layout: layoutMode,
        roam: true,
        draggable: true,
        force: { repulsion: 200, edgeLength: 120 },
        data: seriesData,
        edges: data.edges,
        label: {
          show: true,
          formatter: '{b}',
          color: 'rgb(24, 24, 24)',
          fontWeight: 'bold',
        },
        lineStyle: { color: '#4b5563', opacity: 0.8 },
      },
    ],
  });

  chartInstance.value.off('mouseover');
  chartInstance.value.on('mouseover', (params: any) => {
    if (params.dataType !== 'node' && params.dataType !== 'edge') return;
    if (!dialogVisible.value) return;
    const now = Date.now();
    if (now - lastHoverRefresh.value < hoverRefreshIntervalMs) return;
    if (isHoverRefreshing.value) return;
    isHoverRefreshing.value = true;
    buildGraph()
      .then(() => {
        renderChart();
        lastHoverRefresh.value = Date.now();
      })
      .finally(() => {
        isHoverRefreshing.value = false;
      });
  });
};

watch(dialogVisible, (visible) => {
  if (!visible) {
    chartInstance.value?.dispose();
    chartInstance.value = null;
  }
});

onMounted(() => {
  buildGraph();
  window.addEventListener('resize', resizeChart);
});

onUnmounted(() => {
  chartInstance.value?.dispose();
  window.removeEventListener('resize', resizeChart);
});

const resizeChart = () => {
  chartInstance.value?.resize();
};
</script>

<template>
  <div id="network-graph-root" class="flex flex-col gap-4">
    <div id="network-graph-header" class="flex items-center justify-between">
      <h1 id="network-graph-title" class="text-xl font-bold">Network Graph</h1>
      <Button id="network-graph-refresh" icon="pi pi-refresh" label="Refresh" @click="buildGraph" />
    </div>

    <div v-if="loading" id="network-graph-loading" class="w-full flex justify-center py-8">
      <ProgressSpinner />
    </div>

    <div v-else-if="!hasData" id="network-graph-empty" class="text-center text-gray-500">
      No network data available.
    </div>

    <div v-else id="network-graph-cards" class="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-4">
      <Card v-for="name in networkCards" :key="name" :id="`network-graph-card-${name}`" class="cursor-pointer"
        @click="openNetwork(name)">
        <template #title>
          <div class="flex items-center gap-2">
            <i class="pi pi-share-alt" />
            <span>{{ name }}</span>
          </div>
        </template>
        <template #content>
          <div class="text-sm text-gray-600">点击查看网络拓扑图</div>
        </template>
      </Card>
    </div>

    <Dialog v-model:visible="dialogVisible" modal :header="selectedNetwork || ''" :style="dialogStyle" :draggable="false" id="network-graph-dialog">
      <div id="network-graph-dialog-content" style="height: calc(80vh - 80px); width: 100%;">
        <div id="network-graph-canvas" ref="chartRef" style="width: 100%; height: 100%;"></div>
      </div>
    </Dialog>
  </div>
</template>
