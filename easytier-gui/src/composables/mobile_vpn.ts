import type { NetworkTypes } from 'easytier-frontend-lib'
import type { TunFdInstanceSources } from './backend'
import { addPluginListener } from '@tauri-apps/api/core'
import { Utils } from 'easytier-frontend-lib'
import {
  consume_vpn_tile_action,
  get_vpn_status,
  prepare_vpn,
  start_vpn,
  stop_vpn,
  type VpnTileAction,
} from 'tauri-plugin-vpnservice-api'
import { collectNetworkInfo, getConfig, listNetworkInstanceIds, setTunFd } from './backend'

type Route = NetworkTypes.Route

interface vpnStatus {
  running: boolean
  ipv4Addr: string | null | undefined
  ipv4Addrs: string[]
  ipv4Cidr: number | null | undefined
  routes: string[]
  dns: string | null | undefined
  instanceIds: string[]
  instanceSources: TunFdInstanceSources[]
}

let vpnReconcileTimer: ReturnType<typeof setTimeout> | null = null
const VPN_RECONCILE_INTERVAL_MS = 2000
const VPN_RECONCILE_MAX_ATTEMPTS = 60

let desiredVpnInstanceId: string | undefined
let activeVpnInstanceId: string | undefined
let vpnReconcileGeneration = 0
let vpnReconcileAttempts = 0
let vpnReconcileQueue: Promise<void> = Promise.resolve()
let vpnPermissionRequest: Promise<boolean> | null = null
let vpnTileActionHandler: ((action: VpnTileAction) => Promise<void>) | undefined
let vpnTileActionQueue: Promise<void> = Promise.resolve()

const curVpnStatus: vpnStatus = {
  running: false,
  ipv4Addr: undefined,
  ipv4Addrs: [],
  ipv4Cidr: undefined,
  routes: [],
  dns: undefined,
  instanceIds: [],
  instanceSources: [],
}

export function setMobileVpnTileActionHandler(
  handler?: (action: VpnTileAction) => Promise<void>,
) {
  vpnTileActionHandler = handler
}

export async function consumePendingMobileVpnTileAction() {
  const handler = vpnTileActionHandler
  if (!handler) {
    return false
  }

  const action = (await consume_vpn_tile_action())?.action
  if (action !== 'start' && action !== 'stop') {
    return false
  }

  const run = vpnTileActionQueue
    .catch(error => console.error('previous VPN tile action failed', error))
    .then(() => handler(action))
  vpnTileActionQueue = run.catch(error => console.error('VPN tile action failed', error))
  await run
  return true
}

async function requestVpnPermissionOnce() {
  console.log('prepare vpn')
  const prepare_ret = await prepare_vpn()
  console.log('prepare vpn', JSON.stringify((prepare_ret)))
  if (prepare_ret?.errorMsg?.length) {
    throw new Error(prepare_ret.errorMsg)
  }

  const granted = prepare_ret?.granted ?? true
  if (!granted) {
    console.info('vpn permission request was denied or dismissed')
  }

  return granted
}

async function requestVpnPermission() {
  if (vpnPermissionRequest) {
    console.log('reuse pending vpn permission request')
    return await vpnPermissionRequest
  }

  const request = requestVpnPermissionOnce()
  vpnPermissionRequest = request
  try {
    return await request
  }
  finally {
    if (vpnPermissionRequest === request) {
      vpnPermissionRequest = null
    }
  }
}

function clearVpnReconcileTimer() {
  if (vpnReconcileTimer) {
    clearTimeout(vpnReconcileTimer)
    vpnReconcileTimer = null
  }
}

function beginVpnReconcile(instanceId?: string) {
  clearVpnReconcileTimer()
  desiredVpnInstanceId = instanceId
  vpnReconcileAttempts = 0
  vpnReconcileGeneration += 1
  return vpnReconcileGeneration
}

function isCurrentVpnReconcile(instanceId: string, generation: number) {
  return desiredVpnInstanceId === (instanceId || undefined) && vpnReconcileGeneration === generation
}

function scheduleVpnReconcile(instanceId: string, generation: number, reason: string) {
  if (!isCurrentVpnReconcile(instanceId, generation))
    return

  if (vpnReconcileAttempts >= VPN_RECONCILE_MAX_ATTEMPTS) {
    console.error(
      'vpn service reconcile stopped after maximum attempts',
      instanceId,
      VPN_RECONCILE_MAX_ATTEMPTS,
      reason,
    )
    return
  }

  clearVpnReconcileTimer()
  vpnReconcileAttempts += 1
  console.log(
    'vpn service is not ready, retrying',
    JSON.stringify({
      instanceId,
      attempt: vpnReconcileAttempts,
      maxAttempts: VPN_RECONCILE_MAX_ATTEMPTS,
      delayMs: VPN_RECONCILE_INTERVAL_MS,
      reason,
    }),
  )
  vpnReconcileTimer = setTimeout(() => {
    vpnReconcileTimer = null
    void enqueueVpnReconcile(instanceId, generation)
  }, VPN_RECONCILE_INTERVAL_MS)
}

function resetVpnConfigStatus() {
  curVpnStatus.ipv4Addr = undefined
  curVpnStatus.ipv4Addrs = []
  curVpnStatus.ipv4Cidr = undefined
  curVpnStatus.routes = []
  curVpnStatus.dns = undefined
  curVpnStatus.instanceIds = []
  curVpnStatus.instanceSources = []
}

function syncVpnStatusFromNative(status: Awaited<ReturnType<typeof get_vpn_status>>) {
  curVpnStatus.running = status?.running ?? false
  if (!curVpnStatus.running) {
    activeVpnInstanceId = undefined
    resetVpnConfigStatus()
    return
  }

  const ipv4Addrs = status?.ipv4Addrs?.length
    ? [...status.ipv4Addrs]
    : status?.ipv4Addr
      ? [status.ipv4Addr]
      : []
  curVpnStatus.ipv4Addrs = ipv4Addrs
  const ipv4WithCidr = ipv4Addrs[0]
  if (ipv4WithCidr?.length) {
    const [ipv4Addr, cidr] = ipv4WithCidr.split('/')
    curVpnStatus.ipv4Addr = ipv4Addr

    const parsedCidr = Number(cidr)
    curVpnStatus.ipv4Cidr = Number.isInteger(parsedCidr) ? parsedCidr : undefined
  }
  else {
    curVpnStatus.ipv4Addr = undefined
    curVpnStatus.ipv4Cidr = undefined
  }

  curVpnStatus.routes = [...(status?.routes ?? [])]
  curVpnStatus.dns = status?.dns ?? undefined
}

async function waitVpnStatus(target_status: boolean, timeout_sec: number) {
  const start_time = Date.now()
  while (curVpnStatus.running !== target_status) {
    if (Date.now() - start_time > timeout_sec * 1000) {
      throw new Error('wait vpn status timeout')
    }
    await new Promise(r => setTimeout(r, 50))
  }
}

async function detachTunFd(instanceIds: string[], instanceSources: TunFdInstanceSources[]) {
  try {
    await setTunFd(0, instanceIds, instanceSources)
  }
  catch (e) {
    console.error('detach tun fd failed', e)
  }
}

async function doStopVpn(force = false) {
  const wasRunning = curVpnStatus.running
  if (!force && !wasRunning) {
    activeVpnInstanceId = undefined
    return
  }
  const instanceIds = [...curVpnStatus.instanceIds]
  const instanceSources = [...curVpnStatus.instanceSources]
  await detachTunFd(instanceIds, instanceSources)
  console.log('stop vpn')
  const stop_ret = await stop_vpn()
  console.log('stop vpn', JSON.stringify((stop_ret)))
  if (wasRunning) {
    await waitVpnStatus(false, 3)
  }

  activeVpnInstanceId = undefined
  resetVpnConfigStatus()
}

async function doStartVpn(
  ipv4Addrs: string[],
  routes: string[],
  dns: string | undefined,
  instanceIds: string[],
  instanceSources: TunFdInstanceSources[],
) {
  if (curVpnStatus.running) {
    return
  }

  const [ipv4Addr, cidr] = ipv4Addrs[0].split('/')
  curVpnStatus.instanceIds = [...instanceIds]
  curVpnStatus.instanceSources = [...instanceSources]
  console.log('start vpn service', ipv4Addrs, routes, dns, instanceIds)
  const request = {
    ipv4Addr: ipv4Addrs[0],
    ipv4Addrs,
    routes,
    dns,
    disallowedApplications: ['com.kkrainbow.easytier'],
    mtu: 1300,
  }

  let start_ret = await start_vpn(request)
  console.log('start vpn response', JSON.stringify(start_ret))
  if (start_ret?.errorMsg === 'need_prepare') {
    const granted = await requestVpnPermission()
    if (!granted) {
      throw new Error('vpn_permission_denied')
    }
    start_ret = await start_vpn(request)
    console.log('start vpn retry response', JSON.stringify(start_ret))
  }

  if (start_ret?.errorMsg?.length) {
    throw new Error(start_ret.errorMsg)
  }
  await waitVpnStatus(true, 3)

  curVpnStatus.ipv4Addr = ipv4Addr
  curVpnStatus.ipv4Addrs = [...ipv4Addrs]
  curVpnStatus.ipv4Cidr = Number(cidr)
  curVpnStatus.routes = routes
  curVpnStatus.dns = dns
  activeVpnInstanceId = instanceIds[0]
}

async function onVpnServiceStart(payload: any) {
  console.log('vpn service start', JSON.stringify(payload))
  curVpnStatus.running = true
  if (payload.fd) {
    await setTunFd(payload.fd, curVpnStatus.instanceIds, curVpnStatus.instanceSources).catch(async (e) => {
      console.error('set tun fd failed', e)
      await doStopVpn(true).catch(stopError => console.error('stop vpn after tun attach failure', stopError))
    })
  }
}

async function onVpnServiceStop(payload: any) {
  console.log('vpn service stop', JSON.stringify(payload))
  const instanceIds = [...curVpnStatus.instanceIds]
  const instanceSources = [...curVpnStatus.instanceSources]
  await detachTunFd(instanceIds, instanceSources)
  curVpnStatus.running = false
  activeVpnInstanceId = undefined
  resetVpnConfigStatus()
}

async function registerVpnServiceListener() {
  console.log('register vpn service listener')
  await addPluginListener(
    'vpnservice',
    'vpn_service_start',
    onVpnServiceStart,
  )

  await addPluginListener(
    'vpnservice',
    'vpn_service_stop',
    onVpnServiceStop,
  )

  await addPluginListener(
    'vpnservice',
    'vpn_tile_action',
    () => {
      void consumePendingMobileVpnTileAction().catch((error) => {
        console.error('consume VPN tile action failed', error)
      })
    },
  )
}

function getRoutesForVpn(routes: Route[] | undefined, node_config: NetworkTypes.NetworkConfig): string[] {
  const ret = []
  for (const r of routes ?? []) {
    for (let cidr of r.proxy_cidrs ?? []) {
      if (!cidr.includes('/')) {
        cidr += '/32'
      }
      ret.push(cidr)
    }
  }

  for (const route of node_config.routes ?? []) {
    ret.push(route)
  }

  if (node_config.enable_magic_dns) {
    ret.push('100.100.100.101/32')
  }

  // sort and dedup
  return Array.from(new Set(ret)).sort()
}

function ipv4CidrToRoute(cidr: string): string | undefined {
  const [address, prefixText] = cidr.split('/')
  const prefix = Number(prefixText)
  const octets = address?.split('.').map(octet => Number(octet))

  if (
    octets?.length !== 4
    || !Number.isInteger(prefix)
    || prefix < 0
    || prefix > 32
    || octets.some((octet) => {
      return !Number.isInteger(octet) || octet < 0 || octet > 255
    })
  ) {
    return undefined
  }

  const ip = (
    octets[0] * 0x1000000
    + octets[1] * 0x10000
    + octets[2] * 0x100
    + octets[3]
  ) >>> 0
  const mask = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0
  const network = (ip & mask) >>> 0
  const route = [
    (network >>> 24) & 0xFF,
    (network >>> 16) & 0xFF,
    (network >>> 8) & 0xFF,
    network & 0xFF,
  ].join('.')

  return `${route}/${prefix}`
}

function getCollectedNetworkInfo(response: Awaited<ReturnType<typeof collectNetworkInfo>>, instanceId: string) {
  const info = response.info as any
  const map = info?.map ?? info
  return map?.[instanceId]
}

function sortInstanceSources(sources: TunFdInstanceSources[]): TunFdInstanceSources[] {
  return sources
    .map(source => ({
      instanceId: source.instanceId,
      ipv4Addrs: [...source.ipv4Addrs].sort(),
      ipv6Addrs: [...(source.ipv6Addrs ?? [])].sort(),
      ipv4Routes: [...(source.ipv4Routes ?? [])].sort(),
      ipv6Routes: [...(source.ipv6Routes ?? [])].sort(),
    }))
    .sort((a, b) => a.instanceId.localeCompare(b.instanceId))
}

function splitRoutesByFamily(routes: string[]) {
  const ipv4Routes: string[] = []
  const ipv6Routes: string[] = []
  routes.forEach((route) => {
    if (route.includes(':')) {
      ipv6Routes.push(route)
    }
    else {
      ipv4Routes.push(route)
    }
  })
  return { ipv4Routes, ipv6Routes }
}

async function stopVpnOwnedByOtherInstance(instanceId: string, generation: number) {
  if (!isCurrentVpnReconcile(instanceId, generation))
    return false

  if (curVpnStatus.running && activeVpnInstanceId !== instanceId) {
    let sameSharedDevice = curVpnStatus.instanceIds.includes(instanceId)
    if (!sameSharedDevice && activeVpnInstanceId) {
      try {
        const [activeConfig, nextConfig] = await Promise.all([
          getConfig(activeVpnInstanceId),
          getConfig(instanceId),
        ])
        sameSharedDevice = !!nextConfig.dev_name?.length
          && nextConfig.dev_name === activeConfig.dev_name
      }
      catch (error) {
        console.warn('vpn service owner config unavailable', error)
      }
    }
    if (!isCurrentVpnReconcile(instanceId, generation))
      return false
    if (!sameSharedDevice) {
      console.warn('vpn service owner changed', activeVpnInstanceId, instanceId)
      await doStopVpn()
    }
  }

  return isCurrentVpnReconcile(instanceId, generation)
}

async function reconcileNetworkInstance(instanceId: string, generation: number) {
  if (!isCurrentVpnReconcile(instanceId, generation))
    return

  clearVpnReconcileTimer()

  let group: Awaited<ReturnType<typeof findRunningTunInstanceGroup>>
  try {
    group = await findRunningTunInstanceGroup(instanceId || undefined)
  }
  catch (error) {
    console.warn('vpn service instance group query failed', instanceId, error)
    scheduleVpnReconcile(instanceId, generation, 'instance_group_unavailable')
    return
  }

  if (!isCurrentVpnReconcile(instanceId, generation))
    return

  if (!group.length) {
    if (curVpnStatus.running)
      await doStopVpn()
    return
  }

  if (!await stopVpnOwnedByOtherInstance(instanceId, generation))
    return

  const ipv4Addrs: string[] = []
  const instanceSources: TunFdInstanceSources[] = []
  const routes = new Set<string>()
  let dns: string | undefined
  let retryReason: string | undefined
  const retainCurrentSource = (memberId: string, enableMagicDns?: boolean) => {
    const source = curVpnStatus.running
      ? curVpnStatus.instanceSources.find(source => source.instanceId === memberId)
      : undefined
    if (!source)
      return

    ipv4Addrs.push(...source.ipv4Addrs)
    for (const route of [...(source.ipv4Routes ?? []), ...(source.ipv6Routes ?? [])])
      routes.add(route)
    instanceSources.push(source)
    if (enableMagicDns)
      dns = '100.100.100.101'
  }

  for (const { instanceId: memberId, config } of group) {
    let curNetworkInfo
    try {
      curNetworkInfo = getCollectedNetworkInfo(await collectNetworkInfo(memberId), memberId)
    }
    catch (error) {
      console.warn('vpn service network info query failed', memberId, error)
      retryReason ??= 'network_info_query_failed'
      retainCurrentSource(memberId, config.enable_magic_dns)
      continue
    }

    if (!isCurrentVpnReconcile(instanceId, generation))
      return

    if (!curNetworkInfo) {
      console.warn('vpn service network info unavailable', memberId, curNetworkInfo?.error_msg)
      retryReason ??= 'network_info_unavailable'
      retainCurrentSource(memberId, config.enable_magic_dns)
      continue
    }

    if (curNetworkInfo.error_msg?.length) {
      console.warn('vpn service network failed', memberId, curNetworkInfo.error_msg)
      retryReason ??= 'network_failed'
      continue
    }

    const virtualIpv4 = curNetworkInfo.my_node_info?.virtual_ipv4
    const virtualIp = virtualIpv4?.address?.addr ? Utils.ipv4ToString(virtualIpv4.address) : undefined
    if (!virtualIp) {
      retryReason ??= config.dhcp ? 'dhcp_ipv4_unavailable' : 'static_ipv4_unavailable'
      retainCurrentSource(memberId, config.enable_magic_dns)
      continue
    }

    const networkLength = virtualIpv4?.network_length || 24
    const sourceIpv4 = virtualIp + '/' + networkLength
    ipv4Addrs.push(sourceIpv4)
    const instanceRoutes = new Set<string>()
    const localRoute = ipv4CidrToRoute(sourceIpv4)
    if (localRoute) {
      routes.add(localRoute)
      instanceRoutes.add(localRoute)
    }
    getRoutesForVpn(curNetworkInfo.routes, config).forEach((route) => {
      routes.add(route)
      instanceRoutes.add(route)
    })
    const { ipv4Routes, ipv6Routes } = splitRoutesByFamily([...instanceRoutes])
    instanceSources.push({
      instanceId: memberId,
      ipv4Addrs: [sourceIpv4],
      ipv6Addrs: [],
      ipv4Routes,
      ipv6Routes,
    })
    if (config.enable_magic_dns)
      dns = '100.100.100.101'
  }

  if (!isCurrentVpnReconcile(instanceId, generation))
    return

  if (!ipv4Addrs.length) {
    if (retryReason)
      scheduleVpnReconcile(instanceId, generation, retryReason)
    const selectedIds = group.map(({ instanceId }) => instanceId).sort()
    const activeIds = curVpnStatus.instanceIds
    if (curVpnStatus.running && (!activeIds.length || activeIds.some(id => !selectedIds.includes(id))))
      await doStopVpn()
    return
  }

  if (retryReason)
    scheduleVpnReconcile(instanceId, generation, retryReason)
  else
    vpnReconcileAttempts = 0
  const sortedIpv4Addrs = [...ipv4Addrs].sort()
  const sortedRoutes = [...routes].sort()
  const sortedInstanceIds = instanceSources.map(({ instanceId }) => instanceId).sort()
  const sortedInstanceSources = sortInstanceSources(instanceSources)
  const configChanged
    = JSON.stringify(sortedIpv4Addrs) !== JSON.stringify(curVpnStatus.ipv4Addrs)
      || JSON.stringify(sortedRoutes) !== JSON.stringify(curVpnStatus.routes)
      || dns !== curVpnStatus.dns
      || JSON.stringify(sortedInstanceIds) !== JSON.stringify(curVpnStatus.instanceIds)
      || JSON.stringify(sortedInstanceSources) !== JSON.stringify(sortInstanceSources(curVpnStatus.instanceSources))

  if (!curVpnStatus.running || configChanged) {
    if (curVpnStatus.running) {
      try {
        await doStopVpn()
      }
      catch (error) {
        console.error('stop vpn service failed', error)
      }
    }

    if (!isCurrentVpnReconcile(instanceId, generation))
      return

    try {
      await doStartVpn(sortedIpv4Addrs, sortedRoutes, dns, sortedInstanceIds, sortedInstanceSources)
      if (!isCurrentVpnReconcile(instanceId, generation) && activeVpnInstanceId === sortedInstanceIds[0])
        await doStopVpn()
    }
    catch (error) {
      if (error instanceof Error && error.message === 'vpn_permission_denied') {
        console.info('vpn permission request was denied or dismissed')
        return
      }
      console.error('start vpn service failed', error)
    }
  }
}

function enqueueVpnTask(task: () => Promise<void>) {
  const run = vpnReconcileQueue
    .catch((e) => {
      console.error('previous vpn service reconcile failed', e)
    })
    .then(task)
  vpnReconcileQueue = run.catch((e) => {
    console.error('vpn service reconcile failed', e)
  })
  return run
}

function enqueueVpnReconcile(instanceId: string, generation: number) {
  return enqueueVpnTask(() => reconcileNetworkInstance(instanceId, generation))
}

export async function onNetworkInstanceChange(instanceId: string) {
  const generation = beginVpnReconcile(instanceId || undefined)
  const group = await findRunningTunInstanceGroup(instanceId || undefined)

  if (vpnReconcileGeneration !== generation)
    return

  const selectedId = group[0]?.instanceId
  desiredVpnInstanceId = selectedId
  await enqueueVpnReconcile(selectedId || '', generation)
}

export async function onNetworkInstanceUpdate(instanceId: string) {
  if (!instanceId)
    return

  if (instanceId !== desiredVpnInstanceId && !curVpnStatus.instanceIds.includes(instanceId)) {
    const group = await findRunningTunInstanceGroup(desiredVpnInstanceId)
    if (!group.some(inst => inst.instanceId === instanceId))
      return
  }

  await onNetworkInstanceChange(desiredVpnInstanceId || instanceId)
}

async function isNoTunEnabled(instanceId: string | undefined) {
  if (!instanceId) {
    return false
  }
  return (await getConfig(instanceId)).no_tun ?? false
}

async function findRunningTunInstanceId() {
  const instanceIds = await listNetworkInstanceIds()
  const runningIds = (instanceIds.running_inst_ids ?? []).map(Utils.UuidToStr)
  console.log('vpn service sync running instances', JSON.stringify(runningIds))

  for (const instanceId of runningIds) {
    if (await isNoTunEnabled(instanceId)) {
      continue
    }

    return instanceId
  }

  return undefined
}

async function findRunningTunInstanceGroup(preferredInstanceId?: string) {
  const instanceIds = await listNetworkInstanceIds()
  const runningIds = (instanceIds.running_inst_ids ?? []).map(Utils.UuidToStr)
  const runningTunInstances = []

  for (const instanceId of runningIds) {
    const config = await getConfig(instanceId)
    if (config.no_tun)
      continue
    runningTunInstances.push({ instanceId, config })
  }

  const selected = runningTunInstances.find(inst => inst.instanceId === preferredInstanceId)
    ?? runningTunInstances.find(inst => curVpnStatus.instanceIds.includes(inst.instanceId))
    ?? runningTunInstances[0]
  if (!selected)
    return []

  const devName = selected.config.dev_name
  if (!devName?.length)
    return [selected]

  return runningTunInstances.filter(inst => inst.config.dev_name === devName)
}

export async function initMobileVpnService() {
  await registerVpnServiceListener()
}

export async function prepareVpnService(instanceId: string) {
  if (await isNoTunEnabled(instanceId)) {
    return
  }

  const generation = beginVpnReconcile(instanceId)
  const stopPreviousOwner = enqueueVpnTask(async () => {
    await stopVpnOwnedByOtherInstance(instanceId, generation)
  })
  await Promise.all([requestVpnPermission(), stopPreviousOwner])
}

export async function syncMobileVpnService() {
  syncVpnStatusFromNative(await get_vpn_status())
  const instanceId = await findRunningTunInstanceId()
  if (instanceId) {
    console.log('vpn service sync selected instance', instanceId)
    await onNetworkInstanceChange(instanceId)
    return
  }

  await onNetworkInstanceChange('')
}
