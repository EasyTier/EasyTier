import type { NetworkTypes } from 'easytier-frontend-lib'
import { addPluginListener } from '@tauri-apps/api/core'
import { Utils } from 'easytier-frontend-lib'
import { prepare_vpn, start_vpn, stop_vpn } from 'tauri-plugin-vpnservice-api'

type Route = NetworkTypes.Route

const networkStore = useNetworkStore()

interface vpnStatus {
  running: boolean
  ipv4Addr: string | null | undefined
  ipv4Cidr: number | null | undefined
  routes: string[]
}

const curVpnStatus: vpnStatus = {
  running: false,
  ipv4Addr: undefined,
  ipv4Cidr: undefined,
  routes: [],
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

async function doStopVpn() {
  if (!curVpnStatus.running) {
    return
  }
  console.log('stop vpn')
  const stop_ret = await stop_vpn()
  console.log('stop vpn', JSON.stringify((stop_ret)))
  await waitVpnStatus(false, 3)

  curVpnStatus.ipv4Addr = undefined
  curVpnStatus.routes = []
}

async function doStartVpn(ipv4Addr: string, cidr: number, routes: string[]) {
  if (curVpnStatus.running) {
    return
  }

  console.log('start vpn service', ipv4Addr, cidr, routes)
  const start_ret = await start_vpn({
    ipv4Addr: `${ipv4Addr}/${cidr}`,
    routes,
    disallowedApplications: ['com.kkrainbow.easytier'],
    mtu: 1300,
  })
  if (start_ret?.errorMsg?.length) {
    throw new Error(start_ret.errorMsg)
  }
  await waitVpnStatus(true, 3)

  curVpnStatus.ipv4Addr = ipv4Addr
  curVpnStatus.routes = routes
}

async function onVpnServiceStart(payload: any) {
  console.log('vpn service start', JSON.stringify(payload))
  curVpnStatus.running = true
  if (payload.fd) {
    setTunFd(networkStore.networkInstanceIds[0], payload.fd)
  }
}

async function onVpnServiceStop(payload: any) {
  console.log('vpn service stop', JSON.stringify(payload))
  curVpnStatus.running = false
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

  // sort and dedup
  return Array.from(new Set(ret)).sort()
}

async function onNetworkInstanceChange() {
  console.error('vpn service watch network instance change ids', JSON.stringify(networkStore.networkInstanceIds))
  const insts = networkStore.networkInstanceIds
  const no_tun = networkStore.isNoTunEnabled(insts[0])
  if (no_tun) {
    await doStopVpn()
    return
  }
  if (!insts) {
    await doStopVpn()
    return
  }

  const curNetworkInfo = networkStore.networkInfos[insts[0]]
  if (!curNetworkInfo || curNetworkInfo?.error_msg?.length) {
    await doStopVpn()
    return
  }

  const virtual_ip = Utils.ipv4ToString(curNetworkInfo?.my_node_info?.virtual_ipv4.address)
  if (!virtual_ip || !virtual_ip.length) {
    await doStopVpn()
    return
  }

  let network_length = curNetworkInfo?.my_node_info?.virtual_ipv4.network_length
  if (!network_length) {
    network_length = 24
  }

  const routes = getRoutesForVpn(curNetworkInfo?.routes, networkStore.curNetwork)

  const ipChanged = virtual_ip !== curVpnStatus.ipv4Addr
  const routesChanged = JSON.stringify(routes) !== JSON.stringify(curVpnStatus.routes)

  if (ipChanged || routesChanged) {
    console.info('vpn service virtual ip changed', JSON.stringify(curVpnStatus), virtual_ip)
    try {
      await doStopVpn()
    }
    catch (e) {
      console.error(e)
    }

    try {
      await doStartVpn(virtual_ip, 24, routes)
    }
    catch (e) {
      console.error('start vpn service failed, clear all network insts.', e)
      networkStore.clearNetworkInstances()
      await retainNetworkInstance(networkStore.networkInstanceIds)
    }
  }
}

async function watchNetworkInstance() {
  let subscribe_running = false
  networkStore.$subscribe(async () => {
    if (subscribe_running) {
      return
    }
    subscribe_running = true
    try {
      await onNetworkInstanceChange()
    }
    catch (_) {
    }
    subscribe_running = false
  })
  console.error('vpn service watch network instance')
}

function isNoTunEnabled(instanceId: string | undefined) {
  if (!instanceId) {
    return false
  }
  const no_tun = networkStore.isNoTunEnabled(instanceId)
  if (no_tun) {
    return true
  }
  return false
}

export async function initMobileVpnService() {
  await registerVpnServiceListener()
  await watchNetworkInstance()
}

export async function prepareVpnService(instanceId: string) {
  if (isNoTunEnabled(instanceId)) {
    return
  }
  console.log('prepare vpn')
  const prepare_ret = await prepare_vpn()
  console.log('prepare vpn', JSON.stringify((prepare_ret)))
  if (prepare_ret?.errorMsg?.length) {
    throw new Error(prepare_ret.errorMsg)
  }
}
