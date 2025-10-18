import { Event, listen } from "@tauri-apps/api/event";
import { type } from "@tauri-apps/plugin-os";
import { NetworkTypes } from "easytier-frontend-lib"

const EVENTS = Object.freeze({
    SAVE_CONFIGS: 'save_configs',
    SAVE_ENABLED_NETWORKS: 'save_enabled_networks',
    PRE_RUN_NETWORK_INSTANCE: 'pre_run_network_instance',
    POST_RUN_NETWORK_INSTANCE: 'post_run_network_instance',
    VPN_SERVICE_STOP: 'vpn_service_stop',
});

function onSaveConfigs(event: Event<NetworkTypes.NetworkConfig[]>) {
    console.log(`Received event '${EVENTS.SAVE_CONFIGS}': ${event.payload}`);
    localStorage.setItem('networkList', JSON.stringify(event.payload));
}

function onSaveEnabledNetworks(event: Event<string[]>) {
    console.log(`Received event '${EVENTS.SAVE_ENABLED_NETWORKS}': ${event.payload}`);
    localStorage.setItem('autoStartInstIds', JSON.stringify(event.payload));
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

export async function listenGlobalEvents() {
    const unlisteners = [
        await listen(EVENTS.SAVE_CONFIGS, onSaveConfigs),
        await listen(EVENTS.SAVE_ENABLED_NETWORKS, onSaveEnabledNetworks),
        await listen(EVENTS.PRE_RUN_NETWORK_INSTANCE, onPreRunNetworkInstance),
        await listen(EVENTS.POST_RUN_NETWORK_INSTANCE, onPostRunNetworkInstance),
        await listen(EVENTS.VPN_SERVICE_STOP, onVpnServiceStop),
    ];

    return () => {
        unlisteners.forEach(unlisten => unlisten());
    };
}