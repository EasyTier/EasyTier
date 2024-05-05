import { DEFAULT_NETWORK_CONFIG, NetworkConfig, NetworkInstance } from '~/types/network';

export const useNetworkStore = defineStore('networkStore', {
  state: () => {
    const networkList = [DEFAULT_NETWORK_CONFIG()];
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
      this.networkList.push(DEFAULT_NETWORK_CONFIG());
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
          ...DEFAULT_NETWORK_CONFIG,
          ...cfg,
        });
      }
      if (result.length === 0) {
        result.push(DEFAULT_NETWORK_CONFIG);
      }
      this.networkList = result;
      this.curNetwork = this.networkList[0];
    },

    saveToLocalStorage() {
      localStorage.setItem("networkList", JSON.stringify(this.networkList));
    }
  }
})

if (import.meta.hot)
  import.meta.hot.accept(acceptHMRUpdate(useNetworkStore as any, import.meta.hot))