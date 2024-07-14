import { addPluginListener } from '@tauri-apps/api/core';
import { prepare_vpn, start_vpn, stop_vpn } from 'tauri-plugin-vpnservice-api';

const networkStore = useNetworkStore()

interface vpnStatus {
    running: boolean
    ipv4Addr: string | null | undefined
    ipv4Cidr: number | null | undefined
}

var curVpnStatus: vpnStatus = {
    running: false,
    ipv4Addr: undefined,
    ipv4Cidr: undefined,
}

async function waitVpnStatus(target_status: boolean, timeout_sec: number) {
    let start_time = Date.now()
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
    let stop_ret = await stop_vpn()
    console.log('stop vpn', JSON.stringify((stop_ret)))
    await waitVpnStatus(false, 3)

    curVpnStatus.ipv4Addr = undefined
}

async function doStartVpn(ipv4Addr: string, cidr: number) {
    if (curVpnStatus.running) {
        return
    }

    console.log('start vpn')
    let start_ret = await start_vpn({
        "ipv4Addr": ipv4Addr + '/' + cidr,
        "routes": ["0.0.0.0/0"],
        "disallowedApplications": ["com.kkrainbow.easytier"],
        "mtu": 1300,
    });
    if (start_ret?.errorMsg?.length) {
        throw new Error(start_ret.errorMsg)
    }
    await waitVpnStatus(true, 3)

    curVpnStatus.ipv4Addr = ipv4Addr
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
    networkStore.clearNetworkInstances()
    await retainNetworkInstance(networkStore.networkInstanceIds)
}

async function registerVpnServiceListener() {
    console.log('register vpn service listener')
    await addPluginListener(
        'vpnservice',
        'vpn_service_start',
        onVpnServiceStart
    )

    await addPluginListener(
        'vpnservice',
        'vpn_service_stop',
        onVpnServiceStop
    )
}

async function watchNetworkInstance() {
    networkStore.$subscribe(async () => {
        let insts = networkStore.networkInstanceIds
        if (!insts) {
            await doStopVpn()
            return
        }

        const curNetworkInfo = networkStore.networkInfos[insts[0]]
        if (!curNetworkInfo || curNetworkInfo?.error_msg?.length) {
            await doStopVpn()
            return
        }

        const virtual_ip = curNetworkInfo?.node_info?.virtual_ipv4
        if (virtual_ip !== curVpnStatus.ipv4Addr) {
            console.log('virtual ip changed', JSON.stringify(curVpnStatus), virtual_ip)
            await doStopVpn()
            if (virtual_ip.length > 0) {
                await doStartVpn(virtual_ip, 24)
            }
            return
        }
    })
}

export async function initMobileVpnService() {
    await registerVpnServiceListener()
    await watchNetworkInstance()
}

export async function prepareVpnService() {
    console.log('prepare vpn')
    let prepare_ret = await prepare_vpn()
    console.log('prepare vpn', JSON.stringify((prepare_ret)))
    if (prepare_ret?.errorMsg?.length) {
        throw new Error(prepare_ret.errorMsg)
    }
}
