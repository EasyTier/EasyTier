import { NetworkTypes } from 'easytier-frontend-lib'

export const useNetworkStore = defineStore('networkStore', {
  state: () => {
    const networkList = [NetworkTypes.DEFAULT_NETWORK_CONFIG()]
    return {
      // for initially empty lists
      networkList: networkList as NetworkTypes.NetworkConfig[],
      // for data that is not yet loaded
      curNetwork: networkList[0],

      // uuid -> instance
      instances: {} as Record<string, NetworkTypes.NetworkInstance>,

      networkInfos: {} as Record<string, NetworkTypes.NetworkInstanceRunningInfo>,

      autoStartInstIds: [] as string[],
    }
  },

  getters: {
    lastNetwork(): NetworkTypes.NetworkConfig {
      return this.networkList[this.networkList.length - 1]
    },

    curNetworkId(): string {
      return this.curNetwork.instance_id
    },

    networkInstances(): Array<NetworkTypes.NetworkInstance> {
      return Object.values(this.instances)
    },

    networkInstanceIds(): Array<string> {
      return Object.keys(this.instances)
    },
  },

  actions: {
    addNewNetwork() {
      this.networkList.push(NetworkTypes.DEFAULT_NETWORK_CONFIG())
    },

    delCurNetwork() {
      const curNetworkIdx = this.networkList.indexOf(this.curNetwork)
      this.networkList.splice(curNetworkIdx, 1)
      const nextCurNetworkIdx = Math.min(curNetworkIdx, this.networkList.length - 1)
      this.curNetwork = this.networkList[nextCurNetworkIdx]
    },

    removeNetworkInstance(instanceId: string) {
      delete this.instances[instanceId]
    },

    addNetworkInstance(instanceId: string) {
      this.instances[instanceId] = {
        instance_id: instanceId,
        running: false,
        error_msg: '',
        detail: undefined,
      }
    },

    clearNetworkInstances() {
      this.instances = {}
    },

    updateWithNetworkInfos(networkInfos: Record<string, NetworkTypes.NetworkInstanceRunningInfo>) {
      this.networkInfos = networkInfos
      for (const [instanceId, info] of Object.entries(networkInfos)) {
        if (this.instances[instanceId] === undefined)
          this.addNetworkInstance(instanceId)

        this.instances[instanceId].running = info.running
        this.instances[instanceId].error_msg = info.error_msg || ''
        this.instances[instanceId].detail = info
      }
    },

    loadFromLocalStorage() {
      let networkList: NetworkTypes.NetworkConfig[]

      // if localStorage default is [{}], instanceId will be undefined
      networkList = JSON.parse(localStorage.getItem('networkList') || '[]')
      networkList = networkList.map((cfg) => {
        return { ...NetworkTypes.DEFAULT_NETWORK_CONFIG(), ...cfg } as NetworkTypes.NetworkConfig
      })

      // prevent a empty list from localStorage, should not happen
      if (networkList.length === 0)
        networkList = [NetworkTypes.DEFAULT_NETWORK_CONFIG()]

      this.networkList = networkList
      this.curNetwork = this.networkList[0]

      this.loadAutoStartInstIdsFromLocalStorage()
    },

    saveToLocalStorage() {
      localStorage.setItem('networkList', JSON.stringify(this.networkList))
    },

    saveAutoStartInstIdsToLocalStorage() {
      localStorage.setItem('autoStartInstIds', JSON.stringify(this.autoStartInstIds))
    },

    loadAutoStartInstIdsFromLocalStorage() {
      try {
        this.autoStartInstIds = JSON.parse(localStorage.getItem('autoStartInstIds') || '[]')
      }
      catch (e) {
        console.error(e)
        this.autoStartInstIds = []
      }
    },

    addAutoStartInstId(instanceId: string) {
      if (!this.autoStartInstIds.includes(instanceId)) {
        this.autoStartInstIds.push(instanceId)
      }
      this.saveAutoStartInstIdsToLocalStorage()
    },

    removeAutoStartInstId(instanceId: string) {
      const idx = this.autoStartInstIds.indexOf(instanceId)
      if (idx !== -1) {
        this.autoStartInstIds.splice(idx, 1)
      }
      this.saveAutoStartInstIdsToLocalStorage()
    },

    isNoTunEnabled(instanceId: string): boolean {
      const cfg = this.networkList.find((cfg) => cfg.instance_id === instanceId)
      if (!cfg)
        return false
      return cfg.no_tun ?? false
    },
  },
})

if (import.meta.hot)
  import.meta.hot.accept(acceptHMRUpdate(useNetworkStore as any, import.meta.hot))
