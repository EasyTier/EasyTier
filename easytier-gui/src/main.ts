import "./styles.css";
import "primevue/resources/themes/aura-light-green/theme.css";
import "primeicons/primeicons.css";
import "primeflex/primeflex.css";

import { createPinia, defineStore } from 'pinia'

import { createMemoryHistory, createRouter } from 'vue-router'

import { createApp } from "vue";
import PrimeVue from 'primevue/config';
import App from "./App.vue";
import { invoke } from "@tauri-apps/api/tauri";

import { v4 as uuidv4 } from 'uuid';

import ToastService from 'primevue/toastservice';


const pinia = createPinia()

export enum NetworkingMethod {
    PublicServer = "PublicServer",
    Manual = "Manual",
    Standalone = "Standalone",
}

export interface NetworkConfig {
    instance_id: string,

    virtual_ipv4: string
    network_name: string
    network_secret: string

    networking_method: NetworkingMethod,

    public_server_url: string,
    peer_urls: Array<string>,

    proxy_cidrs: Array<string>,

    enable_vpn_portal: boolean,
    vpn_portal_listne_port: number,
    vpn_portal_client_network_addr: string,
    vpn_portal_client_network_len: number,

    advanced_settings: boolean,

    listener_urls: Array<string>,
    rpc_port: number,
}

function default_network(): NetworkConfig {
    return {
        instance_id: uuidv4(),

        virtual_ipv4: "",
        network_name: "default",
        network_secret: "",

        networking_method: NetworkingMethod.PublicServer,

        public_server_url: "tcp://easytier.public.kkrainbow.top:11010",
        peer_urls: [],

        proxy_cidrs: [],

        enable_vpn_portal: false,
        vpn_portal_listne_port: 22022,
        vpn_portal_client_network_addr: "",
        vpn_portal_client_network_len: 24,

        advanced_settings: false,

        listener_urls: [
            "tcp://0.0.0.0:11010",
            "udp://0.0.0.0:11010",
            "wg://0.0.0.0:11011",
        ],
        rpc_port: 15888,
    }
}

export interface NetworkInstance {
    instance_id: string,

    running: boolean,
    error_msg: string,

    detail: any,
}

export const useNetworkStore = defineStore('network', {
    state: () => {
        const networkList = [default_network()];
        return {
            // for initially empty lists
            networkList: networkList as NetworkConfig[],
            // for data that is not yet loaded
            curNetwork: networkList[0],

            // uuid -> instance
            instances: {} as Record<string, NetworkInstance>,

            networkInfos: {} as Record<string, any>,
        }
    },

    getters: {
        lastNetwork(): NetworkConfig {
            return this.networkList[this.networkList.length - 1];
        },

        curNetworkId(): string {
            return this.curNetwork.instance_id;
        },

        networkInstances(): Array<NetworkInstance> {
            return Object.values(this.instances);
        },

        networkInstanceIds(): Array<string> {
            return Object.keys(this.instances);
        }
    },

    actions: {
        addNewNetwork() {
            this.networkList.push(default_network());
        },

        delCurNetwork() {
            const curNetworkIdx = this.networkList.indexOf(this.curNetwork);
            this.networkList.splice(curNetworkIdx, 1);
            const nextCurNetworkIdx = Math.min(curNetworkIdx, this.networkList.length - 1);
            this.curNetwork = this.networkList[nextCurNetworkIdx];
        },

        removeNetworkInstance(instanceId: string) {
            delete this.instances[instanceId];
        },

        addNetworkInstance(instanceId: string) {
            this.instances[instanceId] = {
                instance_id: instanceId,
                running: false,
                error_msg: "",
                detail: {},
            };
        },

        updateWithNetworkInfos(networkInfos: Record<string, any>) {
            this.networkInfos = networkInfos;
            for (const [instanceId, info] of Object.entries(networkInfos)) {
                if (this.instances[instanceId] === undefined) {
                    this.addNetworkInstance(instanceId);
                }
                this.instances[instanceId].running = info["running"];
                this.instances[instanceId].error_msg = info["error_msg"];
                this.instances[instanceId].detail = info;
            }
        },

        loadFromLocalStorage() {
            const networkList = JSON.parse(localStorage.getItem("networkList") || '[]');
            let result = [];
            for (const cfg of networkList) {
                result.push({
                    ...default_network(),
                    ...cfg,
                });
            }
            if (result.length === 0) {
                result.push(default_network());
            }
            this.networkList = result;
            this.curNetwork = this.networkList[0];
        },

        saveToLocalStroage() {
            localStorage.setItem("networkList", JSON.stringify(this.networkList));
        }
    }
})

export async function parseNetworkConfig(cfg: NetworkConfig): Promise<string> {
    const ret: string = await invoke("parse_network_config", { cfg: JSON.stringify(cfg) });
    return ret;
}

export async function runNetworkInstance(cfg: NetworkConfig) {
    const ret: string = await invoke("run_network_instance", { cfg: JSON.stringify(cfg) });
    return ret;
}

export async function retainNetworkInstance(instanceIds: Array<string>) {
    const ret: string = await invoke("retain_network_instance", { instanceIds: JSON.stringify(instanceIds) });
    return ret;
}

export async function collectNetworkInfos() {
    const ret: string = await invoke("collect_network_infos", {});
    return JSON.parse(ret);
}

import { createI18n } from 'vue-i18n'

const messages = {
    en: {
        "network": "Network",
        "networking_method": "Networking Method",
        "public_server": "Public Server",
        "manual": "Manual",
        "standalone": "Standalone",
        "virtual_ipv4": "Virtual IPv4",
        "network_name": "Network Name",
        "network_secret": "Network Secret",
        "public_server_url": "Public Server URL",
        "peer_urls": "Peer URLs",
        "proxy_cidrs": "Subnet Proxy CIDRs",
        "enable_vpn_portal": "Enable VPN Portal",
        "vpn_portal_listen_port": "VPN Portal Listen Port",
        "vpn_portal_client_network": "Client Sub Network",
        "advanced_settings": "Advanced Settings",
        "listener_urls": "Listener URLs",
        "rpc_port": "RPC Port",
        "config_network": "Config Network",
        "running": "Running",
        "error_msg": "Error Message",
        "detail": "Detail",
        "add_new_network": "Add New Network",
        "del_cur_network": "Delete Current Network",
        "select_network": "Select Network",
        "network_instances": "Network Instances",
        "instance_id": "Instance ID",
        "network_infos": "Network Infos",
        "parse_network_config": "Parse Network Config",
        "run_network_instance": "Run Network Instance",
        "retain_network_instance": "Retain Network Instance",
        "collect_network_infos": "Collect Network Infos",
        "settings": "Settings",
        "exchange_language": "切换中文",
        "exit": "Exit",

        "chips_placeholder": "e.g: {0}, press Enter to add",
        "off_text": "Press to disable",
        "on_text": "Press to enable",

        "show_config": "Show Config",
        "close": "Close",

        "my_node_info": "My Node Info",
        "peer_count": "Connected",
        "upload": "Upload",
        "download": "Download",
        "show_vpn_portal_config": "Show VPN Portal Config",
        "show_event_log": "Show Event Log",
        "peer_info": "Peer Info",
        "route_cost": "Route Cost",
        "hostname": "Hostname",
        "latency": "Latency",
        "upload_bytes": "Upload",
        "download_bytes": "Download",
        "loss_rate": "Loss Rate",
    },
    cn: {
        "network": "网络",
        "networking_method": "网络方式",
        "public_server": "公共服务器",
        "manual": "手动",
        "standalone": "独立",
        "virtual_ipv4": "虚拟IPv4地址",
        "network_name": "网络名称",
        "network_secret": "网络密码",
        "public_server_url": "公共服务器地址",
        "peer_urls": "对等节点地址",
        "proxy_cidrs": "子网代理CIDR",
        "enable_vpn_portal": "启用VPN门户",
        "vpn_portal_listen_port": "监听端口",
        "vpn_portal_client_network": "客户端子网",
        "advanced_settings": "高级设置",
        "listener_urls": "监听地址",
        "rpc_port": "RPC端口",
        "config_network": "配置网络",
        "running": "运行中",
        "error_msg": "错误信息",
        "detail": "详情",
        "add_new_network": "添加新网络",
        "del_cur_network": "删除当前网络",
        "select_network": "选择网络",
        "network_instances": "网络实例",
        "instance_id": "实例ID",
        "network_infos": "网络信息",
        "parse_network_config": "解析网络配置",
        "run_network_instance": "运行网络实例",
        "retain_network_instance": "保留网络实例",
        "collect_network_infos": "收集网络信息",
        "settings": "设置",
        "exchange_language": "Switch to English",
        "exit": "退出",
        "chips_placeholder": "例如: {0}, 按回车添加",
        "off_text": "点击关闭",
        "on_text": "点击开启",
        "show_config": "显示配置",
        "close": "关闭",

        "my_node_info": "当前节点信息",
        "peer_count": "已连接",
        "upload": "上传",
        "download": "下载",
        "show_vpn_portal_config": "显示VPN门户配置",
        "show_event_log": "显示事件日志",
        "peer_info": "节点信息",
        "hostname": "主机名",
        "route_cost": "路由",
        "latency": "延迟",
        "upload_bytes": "上传",
        "download_bytes": "下载",
        "loss_rate": "丢包率",
    }
}

function saveLocaleToLocalStorage(locale: string) {
    localStorage.setItem("locale", locale);
}

export function loadLocaleFromLocalStorage(): string {
    return localStorage.getItem("locale") || "en";
}

export const i18n = createI18n({
    legacy: false,
    locale: 'en', // set locale
    fallbackLocale: 'cn', // set fallback locale
    messages,
})

export function changeLocale(locale: 'en' | 'cn') {
    i18n.global.locale.value = locale;
    saveLocaleToLocalStorage(locale);
}

const app = createApp(App);
app.use(i18n, { useScope: 'global' })
app.use(pinia)
app.use(PrimeVue);
app.use(ToastService);
app.mount("#app");

export const router = createRouter({
    history: createMemoryHistory(),
    routes: [{ path: "/", component: App }]
});
