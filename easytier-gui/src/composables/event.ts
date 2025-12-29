import { Event, listen } from "@tauri-apps/api/event";
import { type } from "@tauri-apps/plugin-os";
import { NetworkTypes } from "easytier-frontend-lib"

const EVENTS = Object.freeze({
    SAVE_CONFIGS: 'save_configs',
    PRE_RUN_NETWORK_INSTANCE: 'pre_run_network_instance',
    POST_RUN_NETWORK_INSTANCE: 'post_run_network_instance',
    VPN_SERVICE_STOP: 'vpn_service_stop',
    DHCP_IP_CHANGED: 'dhcp_ip_changed',
    PROXY_CIDRS_UPDATED: 'proxy_cidrs_updated',
    EVENT_LAGGED: 'event_lagged',
});

function onSaveConfigs(event: Event<NetworkTypes.NetworkConfig[]>) {
    console.log(`Received event '${EVENTS.SAVE_CONFIGS}': ${event.payload}`);
    localStorage.setItem('networkList', JSON.stringify(event.payload));
}

async function onPreRunNetworkInstance(event: Event<string>) {
    if (type() === 'android') {
        await prepareVpnService(event.payload);
    }
}

async function onPostRunNetworkInstance(event: Event<string>) {
    if (type() === 'android') {
        await onNetworkInstanceChange(event.payload);
    }
}

async function onVpnServiceStop(event: Event<string>) {
    await onNetworkInstanceChange(event.payload);
}

async function onDhcpIpChanged(event: Event<string>) {
    console.log(`Received event '${EVENTS.DHCP_IP_CHANGED}' for instance: ${event.payload}`);
    if (type() === 'android') {
        await onNetworkInstanceChange(event.payload);
    }
}

async function onProxyCidrsUpdated(event: Event<string>) {
    console.log(`Received event '${EVENTS.PROXY_CIDRS_UPDATED}' for instance: ${event.payload}`);
    if (type() === 'android') {
        await onNetworkInstanceChange(event.payload);
    }
}

async function onEventLagged(event: Event<string>) {
    if (type() === 'android') {
        await onNetworkInstanceChange(event.payload);
    }
}

export async function listenGlobalEvents() {
    const unlisteners = [
        await listen(EVENTS.SAVE_CONFIGS, onSaveConfigs),
        await listen(EVENTS.PRE_RUN_NETWORK_INSTANCE, onPreRunNetworkInstance),
        await listen(EVENTS.POST_RUN_NETWORK_INSTANCE, onPostRunNetworkInstance),
        await listen(EVENTS.VPN_SERVICE_STOP, onVpnServiceStop),
        await listen(EVENTS.DHCP_IP_CHANGED, onDhcpIpChanged),
        await listen(EVENTS.PROXY_CIDRS_UPDATED, onProxyCidrsUpdated),
        await listen(EVENTS.EVENT_LAGGED, onEventLagged),
    ];

    return () => {
        unlisteners.forEach(unlisten => unlisten());
    };
}
