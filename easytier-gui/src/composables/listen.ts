import type { InstanceInstantData } from '~/types/components'

const unlistenArr: any[] = []
export async function listen() {
  if (isTauri) {
    unlistenArr.push(await listenDragDrop())
    unlistenArr.push(await listenCloseRequest())
    unlistenArr.push(await listenInstanceInfo())
  }
}

export async function unlisten() {
  if (isTauri)
    unlistenArr.forEach(unlisten => unlisten())
}

async function listenDragDrop() {
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  const appWindow = getCurrentWindow()
  const appStore = useAppStore()
  const fileUnlisten = await appWindow.onDragDropEvent((event) => {
    switch (event.event) {
      case 'tauri://drag-enter':
        if (event.payload.type === 'enter' && event.payload.paths.length > 0) {
          appStore.hideAllDialog()
          appStore.setAddInstanceFromFileDrawerVisible(true)
        }
        break
      case 'tauri://drag-leave':
        appStore.setAddInstanceFromFileDrawerVisible(false)
        break
      case 'tauri://drag-drop':
        if (event.payload.type === 'drop' && event.payload.paths.length > 0) {
          appStore.setAddInstanceFromFileDrawerVisible(false)
          appStore.setAddInstanceDialogVisible(true)
        }
        break
      default:
        break
    }
  })
  return fileUnlisten
}

async function listenCloseRequest() {
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  const appWindow = getCurrentWindow()
  const appStore = useAppStore()
  const unlisten = await appWindow.listen<null>('easytier-gui://close', () => {
    appStore.setAppCloseConfirmDialogVisible(true)
  })
  return unlisten
}

async function listenInstanceInfo() {
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  const appWindow = getCurrentWindow()
  const instanceStore = useInstanceStore()
  const { instances } = storeToRefs(instanceStore)
  instances.value.forEach(i => i.status = false)
  const unlisten = await appWindow.listen<InstanceInstantData[]>('easytier-gui://instance/info', (resp) => {
    // console.log(resp.payload)
    const runningIds = resp.payload.map((data) => {
      return data.id
    })

    instances.value.forEach((instance) => {
      instance.status = runningIds.includes(instance.id)
      const instantData = resp.payload.find(data => data.id === instance.id)
      if (instance.status && instantData) {
        instance.ipv4 = instantData.ipv4
        instance.version = instantData.version
        instance.hostname = instantData.hostname
        instance.udpNatType = instantData.udpNatType
        instance.tcpNatType = instantData.tcpNatType
        instance.events = instantData.events || []
        instance.prps = instantData.prps
        instance.err = instantData.err
        if (instance.stats.length >= 59)
          instance.stats.shift()
        instance.stats.push(instantData.stat)
      }
    })
  })
  return unlisten
}
