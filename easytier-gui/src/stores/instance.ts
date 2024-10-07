import { parse, stringify } from 'smol-toml'
import type { InstanceData, InstancePeer } from '~/types/components'

export const useInstanceStore = defineStore('instanceStore', () => {
  const instances = ref<InstanceData[]>(isDev ? instancesMock() : [])
  const selectedId = ref('')

  const currentInstance = computed<InstanceData | undefined>(() => instances.value.find(instance => instance.id === selectedId.value) || undefined)

  const statusIpv4 = computed(() => {
    return currentInstance.value?.ipv4 ?? 'N/A'
  })

  const statusUpTotal = computed(() => {
    return humanStreamSizeSplit(currentInstance.value?.stats.at(-1)?.peers.reduce((a, c) => a + c.up, 0))
  })

  const statusDownTotal = computed(() => {
    return humanStreamSizeSplit(currentInstance.value?.stats.at(-1)?.peers.reduce((a, c) => a + c.down, 0))
  })

  const currentPeers = computed<InstancePeer[]>(() => {
    return currentInstance.value?.stats.at(-1)?.peers || []
  })

  async function toggleInstanceStatus(id: string) {
    const curInstance = instances.value.find(i => i.id === id)

    if (curInstance) {
      if (curInstance?.status) {
        await stopNetworkInstance(id)
      }
      else {
        const toml = parse(curInstance!.config.str)
        toml.instance_id = id
        instances.value.forEach((i) => {
          if (i.id === id) {
            i.stats = []
          }
        })
        await prepareVpnService()
        await startNetworkInstance(stringify(toml))
      }
    }
  }

  return {
    instances,
    selectedId,
    currentInstance,
    statusIpv4,
    statusUpTotal,
    statusDownTotal,
    currentPeers,
    setInstances(newInstances: InstanceData[]) {
      instances.value = newInstances
    },
    addInstance(adder: InstanceData) {
      instances.value.push(adder)
    },
    setSelectedId(newId: string) {
      selectedId.value = newId
    },
    deleteInstance(id: string) {
      // stop instance
      instances.value = instances.value.filter(instance => instance.id !== id)
      const appStore = useAppStore()
      const { autostart } = storeToRefs(appStore)
      if (autostart.value.id === id) {
        autostart.value.id = ''
      }
      if (selectedId.value === id)
        selectedId.value = ''
    },
    toggleInstanceStatus,
  }
}, {
  persist: true,
})

if (import.meta.hot)
  import.meta.hot.accept(acceptHMRUpdate(useInstanceStore, import.meta.hot))
