<script setup lang="ts">
import { ArrowUpDown, PlaneTakeoff, Radar, Users } from 'lucide-vue-next'
import { natTypeNum2Str } from '~/composables/utils'
import type { InstanceChartStat } from '~/types/components'

const { t } = useI18n()
const instanceStore = useInstanceStore()
const { currentInstance, selectedId, statusIpv4, statusUpTotal, statusDownTotal, currentPeers } = storeToRefs(instanceStore)

const peerList = computed(() => {
  const peers = currentPeers.value
  return peers.sort((a, b) => a.server && !b.server ? -1 : 1) || []
})

const chartStatsData = computed(() => (currentInstance.value?.stats.slice(-15) ?? []).map(item => ({
  time: item.time,
  total: item.peers.length,
  up: item.peers.reduce((a, c) => a + c.up, 0),
  down: item.peers.reduce((a, c) => a + c.down, 0),
} as InstanceChartStat)) ?? [])
</script>

<template>
  <Tabs default-value="overview" style="height: calc(100% - 44px);">
    <TabsList>
      <TabsTrigger value="overview">
        {{ t('component.instance.status.overview.title') }}
      </TabsTrigger>
      <TabsTrigger value="detail">
        {{ t('component.instance.status.detail.title') }}
      </TabsTrigger>
      <TabsTrigger value="config">
        {{ t('component.instance.status.config') }}
      </TabsTrigger>
    </TabsList>
    <TabsContent value="overview" style="height: calc(100% - 44px);" class="h-full overflow-y-scroll">
      <div class="grid gap-4 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 pr-px">
        <Card>
          <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle class="text-sm font-medium">
              {{ t('component.instance.status.overview.ip') }}
            </CardTitle>
            <PlaneTakeoff class="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div v-if="statusIpv4.split('.').length < 3" class="text-2xl font-bold">
              {{ statusIpv4 === '' ? 'N/A' : statusIpv4 }}
            </div>
            <div v-else class="text-2xl font-bold">
              <NumberAnimation
                v-for="(item, index) in statusIpv4.split('.')" :key="index" :to="Number(item)"
                :suffix="index === 3 ? '' : '.'"
              />
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle class="text-sm font-medium">
              {{ t('component.instance.status.overview.nat') }}
            </CardTitle>
            <Radar class="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div class="text-2xl font-bold">
              {{ currentInstance?.udpNatType ? natTypeNum2Str(currentInstance?.udpNatType) : 'N/A' }}
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle class="text-sm font-medium">
              {{ t('component.instance.status.overview.device', {
                time:
                  t(`component.instance.status.overview.${currentInstance?.status ? 'realTime' : 'history'}`),
              }) }}
            </CardTitle>
            <Users class="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <NumberAnimation class="text-2xl font-bold" :to="currentInstance?.stats.at(-1)?.peers.length" />
            <LineChart
              v-if="currentInstance && currentInstance.stats.length > 0" class="h-[100px] mt-2 pt-2"
              :data="chartStatsData" index="time" :categories="['total']" :show-tooltip="false" :show-grid-line="false"
              :show-legend="false" :show-x-axis="false" :show-y-axis="false"
            />
          </CardContent>
        </Card>
        <Card>
          <CardHeader class="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle class="text-sm font-medium">
              {{ t('component.instance.status.overview.bandwidth', {
                time:
                  t(`component.instance.status.overview.${currentInstance?.status ? 'realTime' : 'history'}`),
              }) }}
            </CardTitle>
            <ArrowUpDown class="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div class="flex flex-wrap text-2xl font-bold space-x-2 items-center">
              <NumberAnimation :to="statusUpTotal.size" :suffix="statusUpTotal.unit" :precision="1" />
              <Separator orientation="vertical" label="/" />
              <NumberAnimation
                class="text-[--vis-secondary-color-0x]" :to="statusDownTotal.size" :precision="1"
                :suffix="statusDownTotal.unit"
              />
            </div>
            <LineChart
              v-if="currentInstance && currentInstance.stats.length > 0" class="mt-2 pt-2 h-[100px]"
              :data="chartStatsData" index="time" :categories="['up', 'down']"
              :y-formatter="(tick, _i) => typeof tick === 'number' ? `${humanStreamSize(tick)}` : ''"
              :show-tooltip="false" :show-grid-line="false" :show-legend="false" :show-x-axis="false"
              :show-y-axis="false"
            />
          </CardContent>
        </Card>
      </div>
    </TabsContent>
    <TabsContent value="detail" style="height: calc(100% - 44px);" class="h-full overflow-y-scroll">
      <div
        v-if="currentInstance" name="list" appear
        class="grid gap-4 md:grid-cols-2 xl:grid-cols-3 2xl:grid-cols-4 pr-px"
      >
        <PeerDetail :id="selectedId" local :instance="currentInstance" :chart-stats-data />
        <PeerDetail
          v-for="peer in peerList" :id="peer.id" :key="peer.id" :instance="currentInstance"
          :chart-stats-data
        />
      </div>
    </TabsContent>
    <TabsContent value="config" style="height: calc(100% - 44px);" class="overflow-hidden pr-px">
      <InstanceConfig />
    </TabsContent>
  </Tabs>
</template>

<style scoped lang="postcss"></style>
