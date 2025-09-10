<script setup lang="ts">
import { useTimeAgo } from '@vueuse/core'
import { IPv4 } from 'ip-num/IPNumber'
import { NetworkInstance, type NodeInfo, type PeerRoutePair } from '../types/network'
import { useI18n } from 'vue-i18n';
import { computed, onMounted, onUnmounted, ref } from 'vue';
import { ipv4InetToString, ipv4ToString, ipv6ToString, ipv6AddrToCompressedString } from '../modules/utils';
import { DataTable, Column, Tag, Chip, Button, Dialog, ScrollPanel, Timeline, Divider, Card, } from 'primevue';

const props = defineProps<{
  curNetworkInst: NetworkInstance | null,
}>()

const { t } = useI18n()

const peerRouteInfos = computed(() => {
  if (props.curNetworkInst) {
    const my_node_info = props.curNetworkInst.detail?.my_node_info
    return [{
      route: {
        ipv4_addr: my_node_info?.virtual_ipv4,
        hostname: my_node_info?.hostname,
        version: my_node_info?.version,
      },
    }, ...(props.curNetworkInst.detail?.peer_route_pairs || [])]
  }

  return []
})

function routeCost(info: any) {
  if (info.route) {
    const cost = info.route.cost
    return cost ? cost === 1 ? 'p2p' : `relay(${cost})` : t('status.local')
  }

  return '?'
}

function resolveObjPath(path: string, obj = globalThis, separator = '.') {
  const properties = Array.isArray(path) ? path : path.split(separator)
  return properties.reduce((prev, curr) => prev?.[curr], obj)
}

function statsCommon(info: any, field: string): number | undefined {
  if (!info.peer)
    return undefined

  const conns = info.peer.conns
  return conns.reduce((acc: number, conn: any) => {
    return acc + resolveObjPath(field, conn)
  }, 0)
}

function humanFileSize(bytes: number, si = false, dp = 1) {
  const thresh = si ? 1000 : 1024

  if (Math.abs(bytes) < thresh)
    return `${bytes} B`

  const units = si
    ? ['kB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    : ['KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB', 'ZiB', 'YiB']
  let u = -1
  const r = 10 ** dp

  do {
    bytes /= thresh
    ++u
  } while (Math.round(Math.abs(bytes) * r) / r >= thresh && u < units.length - 1)

  return `${bytes.toFixed(dp)} ${units[u]}`
}

function latencyMs(info: PeerRoutePair) {
  let lat_us_sum = statsCommon(info, 'stats.latency_us')
  if (lat_us_sum === undefined)
    return ''
  lat_us_sum = lat_us_sum / 1000 / info.peer!.conns.length
  return `${lat_us_sum % 1 > 0 ? Math.round(lat_us_sum) + 1 : Math.round(lat_us_sum)}ms`
}

function txBytes(info: PeerRoutePair) {
  const tx = statsCommon(info, 'stats.tx_bytes')
  return tx ? humanFileSize(tx) : ''
}

function rxBytes(info: PeerRoutePair) {
  const rx = statsCommon(info, 'stats.rx_bytes')
  return rx ? humanFileSize(rx) : ''
}

function lossRate(info: PeerRoutePair) {
  const lossRate = statsCommon(info, 'loss_rate')
  return lossRate !== undefined ? `${Math.round(lossRate * 100)}%` : ''
}

function version(info: PeerRoutePair) {
  return info.route.version === '' ? 'unknown' : info.route.version
}

function ipFormat(info: PeerRoutePair) {
  const ip = info.route.ipv4_addr
  if (typeof ip === 'string')
    return ip
  return ip ? `${IPv4.fromNumber(ip.address.addr)}/${ip.network_length}` : ''
}

function tunnelProto(info: PeerRoutePair) {
  return [...new Set(info.peer?.conns.map(c => c.tunnel?.tunnel_type))].join(',')
}

const myNodeInfo = computed(() => {
  if (!props.curNetworkInst)
    return {} as NodeInfo

  return props.curNetworkInst.detail?.my_node_info
})

// Backend now filters IPv6s by prefix intersection; no heuristic needed here.

function peerIpv6ArrayForRow(row: PeerRoutePair): string[] {
  const detail = props.curNetworkInst?.detail
  if (!detail) return []
  // Self row (no inst_id) -> show my own assigned IPv6s
  if (!row.route.inst_id) {
    const mine = detail.my_node_info?.assigned_ipv6s || []
    return mine.map(inet => ipv6AddrToCompressedString(inet.address))
  }
  // Peer row -> use back-end prepared list for that inst_id
  const peerList = (detail.peer_assigned_ipv6s || []).find(p => p.inst_id === row.route.inst_id)?.addrs || []
  return peerList.map(inet => ipv6AddrToCompressedString(inet.address))
}

async function copyOneIpv6(text: string) {
  try {
    if (navigator && navigator.clipboard) await navigator.clipboard.writeText(text)
  } catch { /* ignore */ }
}

interface Chip {
  label: string
  icon: string
}

const myNodeInfoChips = computed(() => {
  if (!props.curNetworkInst)
    return []

  const chips: Array<Chip> = []
  const my_node_info = props.curNetworkInst.detail?.my_node_info
  if (!my_node_info)
    return chips

  // TUN Device Name
  const dev_name = props.curNetworkInst.detail?.dev_name
  if (dev_name) {
    chips.push({
      label: `TUN Device Name: ${dev_name}`,
      icon: '',
    } as Chip)
  }

  // virtual ip (v4)
  chips.push({
    label: `Virtual IP: ${ipv4InetToString(my_node_info.virtual_ipv4)}`,
    icon: '',
  } as Chip)

  // local ipv4s
  const local_ipv4s = my_node_info.ips?.interface_ipv4s
  for (const [idx, ip] of local_ipv4s?.entries()) {
    chips.push({
      label: `Local IPv4 ${idx}: ${ipv4ToString(ip)}`,
      icon: '',
    } as Chip)
  }

  // local ipv6s
  const local_ipv6s = my_node_info.ips?.interface_ipv6s
  for (const [idx, ip] of local_ipv6s?.entries()) {
    chips.push({
      label: `Local IPv6 ${idx}: ${ipv6ToString(ip)}`,
      icon: '',
    } as Chip)
  }

  // overlay assigned ipv6s
  const assigned = my_node_info.assigned_ipv6s
  for (const [idx, inet] of assigned?.entries() || []) {
    chips.push({
      label: `Overlay IPv6 ${idx}: ${ipv6ToString(inet.address)}/${inet.network_length}`,
      icon: '',
    } as Chip)
  }

  // peers overlay assigned ipv6s moved to table near Virtual IPv4

  // public ip
  const public_ip = my_node_info.ips?.public_ipv4
  if (public_ip) {
    chips.push({
      label: `Public IP: ${IPv4.fromNumber(public_ip.addr)}`,
      icon: '',
    } as Chip)
  }

  const public_ipv6 = my_node_info.ips?.public_ipv6
  if (public_ipv6) {
    chips.push({
      label: `Public IPv6: ${ipv6ToString(public_ipv6)}`,
      icon: '',
    } as Chip)
  }

  // listeners:
  const listeners = my_node_info.listeners
  for (const [idx, listener] of listeners?.entries()) {
    chips.push({
      label: `Listener ${idx}: ${listener.url}`,
      icon: '',
    } as Chip)
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
    SymmetricEasyInc = 8,
    SymmetricEasyDec = 9,
  };
  const udpNatType: NatType = my_node_info.stun_info?.udp_nat_type
  if (udpNatType !== undefined) {
    const udpNatTypeStrMap = {
      [NatType.Unknown]: 'Unknown',
      [NatType.OpenInternet]: 'Open Internet',
      [NatType.NoPAT]: 'No PAT',
      [NatType.FullCone]: 'Full Cone',
      [NatType.Restricted]: 'Restricted',
      [NatType.PortRestricted]: 'Port Restricted',
      [NatType.Symmetric]: 'Symmetric',
      [NatType.SymUdpFirewall]: 'Symmetric UDP Firewall',
      [NatType.SymmetricEasyInc]: 'Symmetric Easy Inc',
      [NatType.SymmetricEasyDec]: 'Symmetric Easy Dec',
    }

    chips.push({
      label: `UDP NAT Type: ${udpNatTypeStrMap[udpNatType]}`,
      icon: '',
    } as Chip)
  }

  return chips
})

function globalSumCommon(field: string) {
  let sum = 0
  if (!peerRouteInfos.value)
    return sum

  for (const info of peerRouteInfos.value) {
    const tx = statsCommon(info, field)
    if (tx)
      sum += tx
  }
  return sum
}

function txGlobalSum() {
  return globalSumCommon('stats.tx_bytes')
}

function rxGlobalSum() {
  return globalSumCommon('stats.rx_bytes')
}

const peerCount = computed(() => {
  if (!peerRouteInfos.value)
    return 0

  return peerRouteInfos.value.length
})

// calculate tx/rx rate every 2 seconds
let rateIntervalId = 0
const rateInterval = 2000
let prevTxSum = 0
let prevRxSum = 0
const txRate = ref('0')
const rxRate = ref('0')
onMounted(() => {
  rateIntervalId = window.setInterval(() => {
    const curTxSum = txGlobalSum()
    txRate.value = humanFileSize((curTxSum - prevTxSum) / (rateInterval / 1000))
    prevTxSum = curTxSum

    const curRxSum = rxGlobalSum()
    rxRate.value = humanFileSize((curRxSum - prevRxSum) / (rateInterval / 1000))
    prevRxSum = curRxSum
  }, rateInterval)
})

onUnmounted(() => {
  clearInterval(rateIntervalId)
})

const dialogVisible = ref(false)
const dialogContent = ref<any>('')
const dialogHeader = ref('event_log')

function showVpnPortalConfig() {
  const my_node_info = myNodeInfo.value
  if (!my_node_info)
    return

  const url = 'https://www.wireguardconfig.com/qrcode'
  dialogContent.value = `${my_node_info.vpn_portal_cfg}\n\n # can generate QR code: ${url}`
  dialogHeader.value = 'vpn_portal_config'
  dialogVisible.value = true
}

function showEventLogs() {
  const detail = props.curNetworkInst?.detail
  if (!detail)
    return

  dialogContent.value = detail.events.map((event: string) => JSON.parse(event))
  dialogHeader.value = 'event_log'
  dialogVisible.value = true
}
</script>

<template>
  <div class="frontend-lib">
    <Dialog v-model:visible="dialogVisible" modal :header="t(dialogHeader)" class="w-full h-auto max-h-full"
      :baseZIndex="2000">
      <ScrollPanel v-if="dialogHeader === 'vpn_portal_config'">
        <pre>{{ dialogContent }}</pre>
      </ScrollPanel>
      <Timeline v-else :value="dialogContent">
        <template #opposite="slotProps">
          <small class="text-surface-500 dark:text-surface-400">{{ useTimeAgo(Date.parse(slotProps.item.time))
          }}</small>
        </template>
        <template #content="slotProps">
          <HumanEvent :event="slotProps.item.event" />
        </template>
      </Timeline>
    </Dialog>

    <Card v-if="curNetworkInst?.error_msg">
      <template #title>
        Run Network Error
      </template>
      <template #content>
        <div class="flex flex-col gap-y-5">
          <div class="text-red-500">
            {{ curNetworkInst.error_msg }}
          </div>
        </div>
      </template>
    </Card>

    <template v-else>
      <Card>
        <template #title>
          {{ t('my_node_info') }}
        </template>
        <template #content>
          <div class="flex w-full flex-col gap-y-5">
            <div class="m-0 flex flex-row justify-center gap-x-5">
              <div class="rounded-full w-32 h-32 flex flex-col items-center pt-6" style="border: 1px solid green">
                <div class="font-bold">
                  {{ t('peer_count') }}
                </div>
                <div class="text-5xl mt-1">
                  {{ peerCount }}
                </div>
              </div>

              <div class="rounded-full w-32 h-32 flex flex-col items-center pt-6" style="border: 1px solid purple">
                <div class="font-bold">
                  {{ t('upload') }}
                </div>
                <div class="text-xl mt-2">
                  {{ txRate }}/s
                </div>
              </div>

              <div class="rounded-full w-32 h-32 flex flex-col items-center pt-6" style="border: 1px solid fuchsia">
                <div class="font-bold">
                  {{ t('download') }}
                </div>
                <div class="text-xl mt-2">
                  {{ rxRate }}/s
                </div>
              </div>
            </div>

            <div class="flex flex-row items-center flex-wrap w-full max-h-40 overflow-scroll">
              <Chip v-for="(chip, i) in myNodeInfoChips" :key="i" :label="chip.label" :icon="chip.icon"
                class="mr-2 mt-2 text-sm" />
            </div>

            <div v-if="myNodeInfo" class="m-0 flex flex-row justify-center gap-x-5 text-sm">
              <Button severity="info" :label="t('show_vpn_portal_config')" @click="showVpnPortalConfig" />
              <Button severity="info" :label="t('show_event_log')" @click="showEventLogs" />
            </div>
          </div>
        </template>
      </Card>

      <Divider />

      <Card>
        <template #title>
          {{ t('peer_info') }}
        </template>
        <template #content>
          <DataTable :value="peerRouteInfos" column-resize-mode="fit" table-class="w-full">
            <Column :header="t('virtual_ipv4')">
              <template #body="slotProps">
                <div class="flex flex-col">
                  <div>{{ ipFormat(slotProps.data) }}</div>
                  <template v-if="peerIpv6ArrayForRow(slotProps.data).length">
                    <div
                      v-for="(addr, i) in peerIpv6ArrayForRow(slotProps.data)"
                      :key="i"
                      class="text-xs overflow-hidden text-color-secondary cursor-pointer"
                      v-tooltip="addr"
                      @click="copyOneIpv6(addr)"
                    >
                      {{ addr }}
                    </div>
                  </template>
                </div>
              </template>
            </Column>
            <Column :header="t('hostname')">
              <template #body="slotProps">
                <div v-if="!slotProps.data.route.cost || !slotProps.data.route.feature_flag.is_public_server"
                  v-tooltip="slotProps.data.route.hostname">
                  {{
                    slotProps.data.route.hostname }}
                </div>
                <div v-else v-tooltip="slotProps.data.route.hostname" class="space-x-1">
                  <Tag v-if="slotProps.data.route.feature_flag.is_public_server" severity="info" value="Info">
                    {{ t('status.server') }}
                  </Tag>
                  <Tag v-if="slotProps.data.route.feature_flag.avoid_relay_data" severity="warn" value="Warn">
                    {{ t('status.relay') }}
                  </Tag>
                </div>
              </template>
            </Column>
            <Column :field="routeCost" :header="t('route_cost')" />
            <Column :field="tunnelProto" :header="t('tunnel_proto')" />
            <Column :field="latencyMs" :header="t('latency')" />
            <Column :field="txBytes" :header="t('upload_bytes')" />
            <Column :field="rxBytes" :header="t('download_bytes')" />
            <Column :field="lossRate" :header="t('loss_rate')" />
            <Column :header="t('status.version')">
              <template #body="slotProps">
                <span>{{ version(slotProps.data) }}</span>
              </template>
            </Column>
          </DataTable>
        </template>
      </Card>
    </template>
  </div>
</template>

<style lang="postcss" scoped>
.p-timeline :deep(.p-timeline-event-opposite) {
  @apply flex-none;
}
</style>
