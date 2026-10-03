import type { NetworkTypes } from 'easytier-frontend-lib'
import { addPluginListener } from '@tauri-apps/api/core'
import { Utils } from 'easytier-frontend-lib'
import { IPv4CidrRange } from 'ip-num/IPRange'
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
  ipv4Addrs: string[]
  routes: string[]
  dns: string | null | undefined
}

let vpnReconcileTimer: ReturnType<typeof setTimeout> | null = null
const VPN_RECONCILE_INTERVAL_MS = 2000
const VPN_RECONCILE_MAX_ATTEMPTS = 60

let vpnReconcileGeneration = 0
let vpnReconcileAttempts = 0
let vpnReconcileQueue: Promise<void> = Promise.resolve()
let vpnPermissionRequest: Promise<boolean> | null = null
let vpnTileActionHandler: ((action: VpnTileAction) => Promise<void>) | undefined
let vpnTileActionQueue: Promise<void> = Promise.resolve()

const curVpnStatus: vpnStatus = {
  running: false,
  ipv4Addrs: [],
  routes: [],
  dns: undefined,
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

function beginVpnReconcile() {
  clearVpnReconcileTimer()
  vpnReconcileAttempts = 0
  vpnReconcileGeneration += 1
  return vpnReconcileGeneration
}

function isCurrentVpnReconcile(generation: number) {
  return vpnReconcileGeneration === generation
}

function scheduleVpnReconcile(generation: number, reason: string) {
  if (!isCurrentVpnReconcile(generation))
    return

  if (vpnReconcileAttempts >= VPN_RECONCILE_MAX_ATTEMPTS) {
    console.error(
      'vpn service reconcile stopped after maximum attempts',
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
      attempt: vpnReconcileAttempts,
      maxAttempts: VPN_RECONCILE_MAX_ATTEMPTS,
      delayMs: VPN_RECONCILE_INTERVAL_MS,
      reason,
    }),
  )
  vpnReconcileTimer = setTimeout(() => {
    vpnReconcileTimer = null
    void enqueueVpnReconcile(generation)
  }, VPN_RECONCILE_INTERVAL_MS)
}

function resetVpnConfigStatus() {
  curVpnStatus.ipv4Addrs = []
  curVpnStatus.routes = []
  curVpnStatus.dns = undefined
}

function syncVpnStatusFromNative(status: Awaited<ReturnType<typeof get_vpn_status>>) {
  curVpnStatus.running = status?.running ?? false
  if (!curVpnStatus.running) {
    resetVpnConfigStatus()
    return
  }

  curVpnStatus.ipv4Addrs = [...(status?.ipv4Addrs ?? [])]
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

async function detachTunFd() {
  try {
    await setTunFd(0)
  }
  catch (e) {
    console.error('detach tun fd failed', e)
  }
}

async function doStopVpn(force = false) {
  const wasRunning = curVpnStatus.running
  if (!force && !wasRunning) {
    return
  }
  await detachTunFd()
  console.log('stop vpn')
  const stop_ret = await stop_vpn()
  console.log('stop vpn', JSON.stringify((stop_ret)))
  if (wasRunning) {
    await waitVpnStatus(false, 3)
  }

  resetVpnConfigStatus()
}

async function doStartVpn(
  ipv4Addrs: string[],
  routes: string[],
  dns: string | undefined,
) {
  if (curVpnStatus.running) {
    return
  }

  console.log('start vpn service', ipv4Addrs, routes, dns)
  const request = {
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

  curVpnStatus.ipv4Addrs = [...ipv4Addrs]
  curVpnStatus.routes = routes
  curVpnStatus.dns = dns
}

async function onVpnServiceStart(payload: any) {
  console.log('vpn service start', JSON.stringify(payload))
  curVpnStatus.running = true
  if (payload.fd) {
    await setTunFd(payload.fd).catch(async (e) => {
      console.error('set tun fd failed', e)
      await doStopVpn(true).catch(stopError => console.error('stop vpn after tun attach failure', stopError))
    })
  }
}

async function onVpnServiceStop(payload: any) {
  console.log('vpn service stop', JSON.stringify(payload))
  await detachTunFd()
  curVpnStatus.running = false
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
  if (node_config.enable_manual_routes) {
    ret.push(...(node_config.routes ?? []))
  }
  else {
    for (const r of routes ?? []) {
      for (let cidr of r.proxy_cidrs ?? []) {
        if (!cidr.includes('/')) {
          cidr += '/32'
        }
        ret.push(cidr)
      }
    }
  }

  if (node_config.enable_magic_dns) {
    ret.push('100.100.100.101/32')
  }

  return ret
}

function ipv4CidrToRoute(cidr: string): string | undefined {
  try {
    const range = IPv4CidrRange.fromCidr(cidr)
    return `${range.getFirst()}/${range.getPrefix()}`
  }
  catch {
    return undefined
  }
}

async function reconcileNetworkInstance(generation: number) {
  if (!isCurrentVpnReconcile(generation))
    return

  clearVpnReconcileTimer()

  let instances: Awaited<ReturnType<typeof findRunningTunInstances>>
  try {
    instances = await findRunningTunInstances()
  }
  catch (error) {
    console.warn('vpn service instance query failed', error)
    scheduleVpnReconcile(generation, 'instance_list_unavailable')
    return
  }

  if (!isCurrentVpnReconcile(generation))
    return

  if (!instances.length) {
    if (curVpnStatus.running)
      await doStopVpn()
    return
  }

  const ipv4Addrs: string[] = []
  const routes = new Set<string>()
  let dns: string | undefined
  let retryReason: string | undefined
  let networkInfoUnavailable = false

  for (const { instanceId: memberId, config } of instances) {
    let curNetworkInfo
    try {
      curNetworkInfo = (await collectNetworkInfo(memberId)).info.map[memberId]
    }
    catch (error) {
      console.warn('vpn service network info query failed', memberId, error)
      retryReason ??= 'network_info_query_failed'
      networkInfoUnavailable = true
      continue
    }

    if (!isCurrentVpnReconcile(generation))
      return

    if (!curNetworkInfo) {
      console.warn('vpn service network info unavailable', memberId)
      retryReason ??= 'network_info_unavailable'
      networkInfoUnavailable = true
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
      if (!config.dhcp)
        networkInfoUnavailable = true
      continue
    }

    const networkLength = virtualIpv4?.network_length || 24
    const sourceIpv4 = virtualIp + '/' + networkLength
    ipv4Addrs.push(sourceIpv4)
    const localRoute = ipv4CidrToRoute(sourceIpv4)
    if (localRoute)
      routes.add(localRoute)
    getRoutesForVpn(curNetworkInfo.routes, config).forEach((route) => {
      routes.add(route)
    })
    if (config.enable_magic_dns)
      dns = '100.100.100.101'
  }

  if (!isCurrentVpnReconcile(generation))
    return

  if (networkInfoUnavailable && curVpnStatus.running) {
    scheduleVpnReconcile(generation, retryReason || 'network_info_unavailable')
    return
  }

  if (!ipv4Addrs.length) {
    if (retryReason)
      scheduleVpnReconcile(generation, retryReason)
    if (curVpnStatus.running)
      await doStopVpn()
    return
  }

  if (retryReason)
    scheduleVpnReconcile(generation, retryReason)
  else
    vpnReconcileAttempts = 0
  const sortedIpv4Addrs = [...ipv4Addrs].sort()
  const sortedRoutes = [...routes].sort()
  const configChanged
    = JSON.stringify(sortedIpv4Addrs) !== JSON.stringify(curVpnStatus.ipv4Addrs)
      || JSON.stringify(sortedRoutes) !== JSON.stringify(curVpnStatus.routes)
      || dns !== curVpnStatus.dns

  if (!curVpnStatus.running || configChanged) {
    if (curVpnStatus.running) {
      try {
        await doStopVpn()
      }
      catch (error) {
        console.error('stop vpn service failed', error)
      }
    }

    if (!isCurrentVpnReconcile(generation))
      return

    try {
      await doStartVpn(sortedIpv4Addrs, sortedRoutes, dns)
      if (!isCurrentVpnReconcile(generation))
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

function enqueueVpnReconcile(generation: number) {
  return enqueueVpnTask(() => reconcileNetworkInstance(generation))
}

export async function onNetworkInstanceChange(_instanceId: string) {
  await enqueueVpnReconcile(beginVpnReconcile())
}

export async function onNetworkInstanceUpdate(instanceId: string) {
  if (!instanceId)
    return
  await onNetworkInstanceChange(instanceId)
}

async function isNoTunEnabled(instanceId: string | undefined) {
  if (!instanceId) {
    return false
  }
  return (await getConfig(instanceId)).no_tun ?? false
}

async function findRunningTunInstances() {
  const instanceIds = await listNetworkInstanceIds()
  const runningIds = (instanceIds.running_inst_ids ?? []).map(Utils.UuidToStr)
  const runningTunInstances = []

  for (const instanceId of runningIds) {
    const config = await getConfig(instanceId)
    if (config.no_tun)
      continue
    runningTunInstances.push({ instanceId, config })
  }

  return runningTunInstances
}

export async function initMobileVpnService() {
  await registerVpnServiceListener()
}

export async function prepareVpnService(instanceId: string) {
  if (await isNoTunEnabled(instanceId)) {
    return
  }

  await requestVpnPermission()
}

export async function syncMobileVpnService() {
  syncVpnStatusFromNative(await get_vpn_status())
  await onNetworkInstanceChange('')
}
