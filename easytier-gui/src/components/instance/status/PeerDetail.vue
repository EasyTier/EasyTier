<script setup lang="ts">
import { Server } from 'lucide-vue-next'
import type { InstanceChartStat, InstanceData, InstancePeerDetail, InstancePeerStat } from '~/types/components'

const props = defineProps<PeerDetailProps>()
const { t } = useI18n()
const instanceStore = useInstanceStore()
const { statusUpTotal, statusDownTotal } = storeToRefs(instanceStore)
interface PeerDetailProps {
  id: string
  instance: InstanceData
  chartStatsData: InstanceChartStat[]
  local?: boolean
}

const detailStatsData = computed(() => {
  const sliceStats = props.instance.stats ?? []
  const peerDetail: InstancePeerDetail = {
    id: props.id,
    name: '',
    stats: [] as InstancePeerStat[],
  }

  peerDetail.stats = sliceStats.map((item) => {
    const peer = item.peers.find(peer => peer.id === props.id)
    if (peer && !peerDetail.name)
      peerDetail.name = peer.name

    if (peer && !peerDetail.version)
      peerDetail.version = peer.version

    return (peer
      ? {
          time: item.time,
          ipv4: peer?.ipv4,
          ipv6: peer?.ipv6,
          server: peer.server,
          relay: peer.relay,
          up: peer?.up || 0,
          down: peer?.down || 0,
          cost: peer?.cost || 0,
          latency: peer?.latency || 0,
          lost: peer?.lost || 0,
        }
      : {}) as InstancePeerStat
  }) ?? []
  return peerDetail
})

const version = computed(() => {
  const v = props.local ? props.instance.version : detailStatsData.value.version
  return `${v ? 'v' : ''}${v ?? 'unknown'}`
})

const currentStatsData = computed(() => {
  return detailStatsData.value.stats.at(-1)!
})

const deviceConnStatus = computed(() => {
  return currentStatsData.value.server ? t('component.instance.peerDetail.server') : currentStatsData.value.cost > 0 ? currentStatsData.value.cost === 1 ? 'p2p' : `relay(${currentStatsData.value.cost})` : t('component.instance.peerDetail.local')
})

const deviceName = computed(() => {
  const name = props.local ? props.instance.hostname : detailStatsData.value.name
  return currentStatsData.value.server && name?.includes('PublicServer_') ? name.replace('PublicServer_', '') : name
})
</script>

<template>
  <div v-if="currentStatsData" class="border rounded-xl p-4 w-auto flex flex-col space-y-2 overflow-hidden relative">
    <div class="flex justify-between items-center">
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger as-child>
            <span class="font-semibold tracking-tight flex-1 truncate">
              <Server v-if="currentStatsData.server" class="absolute left-4 top-4 size-5" />
              <span :class="currentStatsData.server ? 'pl-7' : ''">{{ deviceName }}</span>
            </span>
          </TooltipTrigger>
          <TooltipContent>
            <p>{{ props.local ? props.instance.hostname : detailStatsData.name }}</p>
          </TooltipContent>
        </Tooltip>
      </TooltipProvider>
      <span class="text-xs text-gray-500 ml-2">{{ version }}</span>
    </div>
    <div v-if="props.instance?.status">
      <template v-if="!currentStatsData.server">
        <Badge class="!bg-primary/85 mr-2 mt-2">
          {{ `IP: ${(props.local ? props.instance.ipv4 : currentStatsData.ipv4) || 'N/A'}` }}
        </Badge>
        <Badge variant="secondary" class="mr-2 mt-2">
          {{ deviceConnStatus }}
        </Badge>
      </template>
      <Badge v-if="currentStatsData.relay" variant="secondary" class="mr-2 mt-2">
        {{ t('component.instance.peerDetail.relay') }}
      </Badge>
    </div>
    <div v-if="currentStatsData.cost > 0" class="flex flex-wrap">
      <HoverCard>
        <HoverCardTrigger as-child>
          <Badge variant="outline" class="mr-2 mt-2 space-x-2">
            <NumberAnimation :to="currentStatsData.latency" :precision="0" suffix="ms" />
            <Separator orientation="vertical" />
            <NumberAnimation class="text-[--vis-accent-color-0x]" :to="currentStatsData.lost" suffix="%" />
          </Badge>
        </HoverCardTrigger>
        <HoverCardContent class="!p-0">
          <CardHeader class="border-b p-3">
            <CardTitle>
              <span>{{ t('component.instance.peerDetail.latency') }}</span>
              <span class="mx-1">/</span>
              <span class="text-[--vis-accent-color-0x]">{{ t('component.instance.peerDetail.lost') }}</span>
            </CardTitle>
          </CardHeader>
          <CardContent class="min-w-[180px] flex flex-col px-2 pb-2">
            <AreaChart
              class="w-full h-28 mt-4" :data="detailStatsData.stats" index="time"
              :categories="['latency', 'lost']" :colors="['#ffffff', '#f27474']"
              :y-formatter="(tick, _i) => tick.toString()" :show-tooltip="false" :show-grid-line="true"
              :show-legend="false" :show-x-axis="false"
            />
          </CardContent>
        </HoverCardContent>
      </HoverCard>
      <HoverCard>
        <HoverCardTrigger as-child>
          <Badge variant="outline" class="mr-2 mt-2 space-x-2">
            <NumberAnimation
              :to="humanStreamSizeSplit(currentStatsData.up).size"
              :suffix="humanStreamSizeSplit(currentStatsData.up).unit" :precision="1"
            />
            <Separator orientation="vertical" />
            <NumberAnimation
              class="text-[--vis-secondary-color-0x]"
              :to="humanStreamSizeSplit(currentStatsData.down).size" :precision="1"
              :suffix="humanStreamSizeSplit(currentStatsData.down).unit"
            />
          </Badge>
        </HoverCardTrigger>
        <HoverCardContent class="!p-0">
          <CardHeader class="border-b p-3">
            <CardTitle>
              <span>{{ t('component.instance.peerDetail.up') }}</span>
              <span class="mx-1">/</span>
              <span class="text-[--vis-secondary-color-0x]">{{ t('component.instance.peerDetail.down') }}</span>
            </CardTitle>
          </CardHeader>
          <CardContent class="min-w-[180px] flex flex-col px-2 pb-2">
            <AreaChart
              class="w-full h-28 mt-4" :data="detailStatsData.stats" index="time" :categories="['up', 'down']"
              :y-formatter="(tick, _i) => typeof tick === 'number' ? `${humanStreamSize(tick)}` : ''"
              :show-tooltip="false" :show-grid-line="true" :show-legend="false" :show-x-axis="false"
            />
          </CardContent>
        </HoverCardContent>
      </HoverCard>
    </div>
    <div
      v-if="props.instance && props.instance.stats.length > 0 && chartStatsData?.length && props.local"
      class="flex flex-wrap"
    >
      <HoverCard>
        <HoverCardTrigger as-child>
          <Badge variant="outline" class="mr-2 mt-2">
            <NumberAnimation
              :to="chartStatsData.at(-1)?.total"
              :prefix="`${t('component.instance.peerDetail.deviceNum')}: `"
            />
          </Badge>
        </HoverCardTrigger>
        <HoverCardContent class="!p-0">
          <CardHeader class="border-b p-3">
            <CardTitle>
              <p>{{ t('component.instance.peerDetail.deviceNum') }}</p>
            </CardTitle>
          </CardHeader>
          <CardContent class="min-w-[180px] flex flex-col px-2 pb-2">
            <LineChart
              class="h-[100px] mt-2 pt-2" :data="chartStatsData" index="time" :categories="['total']"
              :show-tooltip="false" :show-grid-line="false" :show-legend="false" :show-x-axis="false"
            />
          </CardContent>
        </HoverCardContent>
      </HoverCard>
      <HoverCard>
        <HoverCardTrigger as-child>
          <Badge variant="outline" class="mr-2 mt-2 space-x-2">
            <NumberAnimation :to="statusUpTotal.size" :suffix="statusUpTotal.unit" :precision="1" />
            <Separator orientation="vertical" />
            <NumberAnimation
              class="text-[--vis-secondary-color-0x]" :to="statusDownTotal.size" :precision="1"
              :suffix="statusDownTotal.unit"
            />
          </Badge>
        </HoverCardTrigger>
        <HoverCardContent class="!p-0">
          <CardHeader class="border-b p-3">
            <CardTitle>
              <span>{{ t('component.instance.peerDetail.up') }}</span>
              <span class="mx-1">/</span>
              <span class="text-[--vis-secondary-color-0x]">{{ t('component.instance.peerDetail.down') }}</span>
            </CardTitle>
          </CardHeader>
          <CardContent class="min-w-[180px] flex flex-col px-2 pb-2">
            <AreaChart
              class="w-full h-28 mt-4" :data="chartStatsData" index="time" :categories="['up', 'down']"
              :y-formatter="(tick, _i) => typeof tick === 'number' ? `${humanStreamSize(tick)}` : ''"
              :show-tooltip="false" :show-grid-line="true" :show-legend="false" :show-x-axis="false"
            />
          </CardContent>
        </HoverCardContent>
      </HoverCard>
    </div>
    <!-- <div v-if="currentStatsData.server" class="absolute top-2 right-2 !mt-0">
      <Server class="w-6 h-6" />
    </div> -->
    <!-- <Cable class="absolute top-[-32px] right-[-16px] w-20 h-20 text-gray-600 rotate-45" /> -->
  </div>
</template>

<style lang="postcss" scoped></style>
