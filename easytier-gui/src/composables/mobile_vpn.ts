import type { NetworkTypes } from 'easytier-frontend-lib'
import { addPluginListener } from '@tauri-apps/api/core'
import { Utils } from 'easytier-frontend-lib'
import { get_vpn_status, prepare_vpn, start_vpn, stop_vpn } from 'tauri-plugin-vpnservice-api'

type Route = NetworkTypes.Route

interface vpnStatus {
  running: boolean
  ipv4Addr: string | null | undefined
  ipv4Cidr: number | null | undefined
  routes: string[]
  dns: string | null | undefined
}

let dhcpPollingTimer: NodeJS.Timeout | null = null
const DHCP_POLLING_INTERVAL = 2000 // 2秒后重试

const curVpnStatus: vpnStatus = {
  running: false,
  ipv4Addr: undefined,
  ipv4Cidr: undefined,
  routes: [],
  dns: undefined,
}

async function requestVpnPermission() {
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

function resetVpnConfigStatus() {
  curVpnStatus.ipv4Addr = undefined
  curVpnStatus.ipv4Cidr = undefined
  curVpnStatus.routes = []
  curVpnStatus.dns = undefined
}

function syncVpnStatusFromNative(status: Awaited<ReturnType<typeof get_vpn_status>>) {
  curVpnStatus.running = status?.running ?? false
  if (!curVpnStatus.running) {
    resetVpnConfigStatus()
    return
  }

  const ipv4WithCidr = status?.ipv4Addr
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

async function doStopVpn(force = false) {
  const wasRunning = curVpnStatus.running
  if (!force && !wasRunning) {
    return
  }
  console.log('stop vpn')
  const stop_ret = await stop_vpn()
  console.log('stop vpn', JSON.stringify((stop_ret)))
  if (wasRunning) {
    await waitVpnStatus(false, 3)
  }

  resetVpnConfigStatus()
}

async function doStartVpn(ipv4Addr: string, cidr: number, routes: string[], dns?: string) {
  if (curVpnStatus.running) {
    return
  }

  console.log('start vpn service', ipv4Addr, cidr, routes, dns)
  const request = {
    ipv4Addr: `${ipv4Addr}/${cidr}`,
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
  curVpnStatus.ipv4Cidr = cidr
  curVpnStatus.routes = routes
  curVpnStatus.dns = dns
}

async function onVpnServiceStart(payload: any) {
  console.log('vpn service start', JSON.stringify(payload))
  curVpnStatus.running = true
  if (payload.fd) {
    await setTunFd(payload.fd).catch((e) => {
      console.error('set tun fd failed', e)
    })
  }
}

async function onVpnServiceStop(payload: any) {
  console.log('vpn service stop', JSON.stringify(payload))
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
}

function getRoutesForVpn(routes: Route[], node_config: NetworkTypes.NetworkConfig): string[] {
  if (!routes) {
    return []
  }

  const ret = []
  for (const r of routes) {
    for (let cidr of r.proxy_cidrs) {
      if (!cidr.includes('/')) {
        cidr += '/32'
      }
      ret.push(cidr)
    }
  }

  node_config.routes.forEach(r => {
    ret.push(r)
  })

  if (node_config.enable_magic_dns) {
    ret.push('100.100.100.101/32')
  }

  // sort and dedup
  return Array.from(new Set(ret)).sort()
}

export async function onNetworkInstanceChange(instanceId: string) {
  console.error('vpn service network instance change id', instanceId)

  if (dhcpPollingTimer) {
    clearTimeout(dhcpPollingTimer)
    dhcpPollingTimer = null
  }

  if (!instanceId) {
    console.warn('vpn service skipped because instance id is empty')
    if (curVpnStatus.running) {
      await doStopVpn()
    }
    return
  }
  const config = await getConfig(instanceId)
  console.log('vpn service loaded config', instanceId, JSON.stringify({
    no_tun: config.no_tun,
    dhcp: config.dhcp,
    enable_magic_dns: config.enable_magic_dns,
  }))
  if (config.no_tun) {
    console.log('vpn service skipped because no_tun is enabled', instanceId)
    return
  }
  const curNetworkInfo = (await collectNetworkInfo(instanceId)).info.map[instanceId]
  if (!curNetworkInfo || curNetworkInfo?.error_msg?.length) {
    console.warn('vpn service skipped because network info is unavailable', instanceId, curNetworkInfo?.error_msg)
    await doStopVpn()
    return
  }

  const virtual_ip = Utils.ipv4ToString(curNetworkInfo?.my_node_info?.virtual_ipv4.address)

  if (config.dhcp && (!virtual_ip || !virtual_ip.length)) {
    console.log('DHCP enabled but no IP yet, will retry in', DHCP_POLLING_INTERVAL, 'ms')
    dhcpPollingTimer = setTimeout(() => {
      onNetworkInstanceChange(instanceId)
    }, DHCP_POLLING_INTERVAL)
    return
  }

  if (!virtual_ip || !virtual_ip.length) {
    await doStopVpn()
    return
  }

  let network_length = curNetworkInfo?.my_node_info?.virtual_ipv4.network_length
  if (!network_length) {
    network_length = 24
  }

  const routes = getRoutesForVpn(curNetworkInfo?.routes, config)

  const dns = config.enable_magic_dns ? '100.100.100.101' : undefined

  const ipChanged = virtual_ip !== curVpnStatus.ipv4Addr
  const cidrChanged = network_length !== curVpnStatus.ipv4Cidr
  const routesChanged = JSON.stringify(routes) !== JSON.stringify(curVpnStatus.routes)
  const dnsChanged = dns != curVpnStatus.dns
  const configChanged = ipChanged || cidrChanged || routesChanged || dnsChanged
  const shouldStartVpn = !curVpnStatus.running

  if (shouldStartVpn || configChanged) {
    console.info('vpn service virtual ip changed', JSON.stringify(curVpnStatus), virtual_ip)
    if (curVpnStatus.running) {
      try {
        await doStopVpn()
      }
      catch (e) {
        console.error(e)
      }
    }

    try {
      await doStartVpn(virtual_ip, network_length, routes, dns)
    }
    catch (e) {
      if (e instanceof Error && e.message === 'need_prepare') {
        console.info('vpn permission is required before starting the Android VPN service')
        return
      }
      if (e instanceof Error && e.message === 'vpn_permission_denied') {
        console.info('vpn permission request was denied or dismissed')
        return
      }
      console.error('start vpn service failed', e)
    }
  }
}

async function isNoTunEnabled(instanceId: string | undefined) {
  if (!instanceId) {
    return false
  }
  return (await getConfig(instanceId)).no_tun ?? false
}

async function findRunningTunInstanceId() {
  const instanceIds = await listNetworkInstanceIds()
  const runningIds = instanceIds.running_inst_ids.map(Utils.UuidToStr)
  console.log('vpn service sync running instances', JSON.stringify(runningIds))

  for (const instanceId of runningIds) {
    if (await isNoTunEnabled(instanceId)) {
      continue
    }

    return instanceId
  }

  return undefined
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
  const instanceId = await findRunningTunInstanceId()
  if (instanceId) {
    console.log('vpn service sync selected instance', instanceId)
    await onNetworkInstanceChange(instanceId)
    return
  }

  if (dhcpPollingTimer) {
    clearTimeout(dhcpPollingTimer)
    dhcpPollingTimer = null
  }

  await doStopVpn(true)
}
