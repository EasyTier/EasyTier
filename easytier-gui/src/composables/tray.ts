import type { MenuItem } from '@tauri-apps/api/menu'
import { Menu, PredefinedMenuItem } from '@tauri-apps/api/menu'
import { TrayIcon } from '@tauri-apps/api/tray'
import { getCurrentWindow } from '@tauri-apps/api/window'

const DEFAULT_TRAY_NAME = 'main'

async function toggleVisibility() {
  if (await getCurrentWindow().isVisible()) {
    await getCurrentWindow().hide()
  }
  else {
    await getCurrentWindow().show()
    await getCurrentWindow().setFocus()
  }
}

const menuItems = computedAsync(
  async () => {
    // const { t } = useI18n()
    return [
      await PredefinedMenuItem.new({
        text: 'exit',
        item: 'Quit',
      }),
    ]
  },
  [],
)

export async function useTray(init: boolean = false) {
  let tray
  try {
    tray = await TrayIcon.getById(DEFAULT_TRAY_NAME)
    if (!tray) {
      tray = await TrayIcon.new({
        tooltip: `EasyTier\n${pkg.version}`,
        title: `EasyTier\n${pkg.version}`,
        id: DEFAULT_TRAY_NAME,
        menu: await Menu.new({
          id: 'main',
          items: menuItems.value,
        }),
        action: async () => {
          toggleVisibility()
        },
      })
    }
  }
  catch (error) {
    console.warn('Error while creating tray icon:', error)
    return null
  }

  if (init) {
    tray.setTooltip(`EasyTier\n${pkg.version}`)
    tray.setMenuOnLeftClick(false)
    tray.setMenu(await Menu.new({
      id: 'main',
      items: menuItems.value,
    }))
  }

  return tray
}

export async function setTrayMenu(items: (MenuItem | PredefinedMenuItem)[] | undefined = undefined) {
  if (isTauri && !platformIsMobile.value) {
    const tray = await useTray()
    if (!tray)
      return
    const menu = await Menu.new({
      id: 'main',
      items: items || menuItems.value,
    })
    tray.setMenu(menu)
  }
}

export async function setTrayRunState(isRunning: boolean = false) {
  if (isTauri && !platformIsMobile.value) {
    const tray = await useTray()
    if (!tray)
      return
    tray.setIcon(isRunning ? 'icons/icon-inactive.ico' : 'icons/icon.ico')
  }
}

export async function setTrayTooltip(tooltip: string) {
  if (tooltip) {
    const tray = await useTray()
    if (!tray)
      return
    tray.setTooltip(`EasyTier\n${pkg.version}\n${tooltip}`)
    tray.setTitle(`EasyTier\n${pkg.version}\n${tooltip}`)
  }
}
