import { invoke } from '@tauri-apps/api/core'
import { Menu, MenuItem, PredefinedMenuItem } from '@tauri-apps/api/menu'
import { TrayIcon } from '@tauri-apps/api/tray'
import { getCurrentWindow } from '@tauri-apps/api/window'
import pkg from '~/../package.json'

const DEFAULT_TRAY_NAME = 'main'

interface TrayMenuLabels {
  show: string
  quit: string
}

function usesUserTray() {
  return invoke<boolean>('uses_user_tray')
}

async function toggleVisibility() {
  if (await getCurrentWindow().isVisible()) {
    await getCurrentWindow().hide()
  }
  else {
    await getCurrentWindow().show()
    await getCurrentWindow().setFocus()
  }
}

export async function useTray(init: boolean = false) {
  let tray
  try {
    // The Linux user-session process owns the tray; never recreate it as root.
    if (await usesUserTray())
      return null

    tray = await TrayIcon.getById(DEFAULT_TRAY_NAME)
    if (!tray) {
      tray = await TrayIcon.new({
        tooltip: `EasyTier\n${pkg.version}`,
        title: `EasyTier\n${pkg.version}`,
        id: DEFAULT_TRAY_NAME,
        menu: await Menu.new({
          id: 'main',
          items: await generateMenuItem(),
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
      items: await generateMenuItem(),
    }))
  }

  return tray
}

export async function generateMenuItem() {
  return [
    await MenuItemShow('Show / Hide'),
    await PredefinedMenuItem.new({ item: 'Separator' }),
    await MenuItemExit('Exit'),
  ]
}

export async function MenuItemExit(text: string) {
  return await PredefinedMenuItem.new({
    text,
    item: 'Quit',
  })
}

export async function MenuItemShow(text: string) {
  return await MenuItem.new({
    id: 'show',
    text,
    action: async () => {
      await toggleVisibility()
    },
  })
}

export async function setTrayMenu(labels?: TrayMenuLabels) {
  if (await usesUserTray()) {
    await invoke('update_user_tray', {
      update: { type: 'menu', ...(labels ?? { show: 'Show / Hide', quit: 'Exit' }) },
    })
    return
  }
  const tray = await useTray()
  if (!tray)
    return
  const menu = await Menu.new({
    id: 'main',
    items: labels
      ? [await MenuItemShow(labels.show), await MenuItemExit(labels.quit)]
      : await generateMenuItem(),
  })
  tray.setMenu(menu)
}

export async function setTrayRunState(isRunning: boolean = false) {
  if (await usesUserTray()) {
    await invoke('update_user_tray', { update: { type: 'run_state', running: isRunning } })
    return
  }
  const tray = await useTray()
  if (!tray)
    return
  tray.setIcon(isRunning ? 'icons/icon-inactive.ico' : 'icons/icon.ico')
}

export async function setTrayTooltip(tooltip: string) {
  if (tooltip) {
    const text = `EasyTier\n${pkg.version}\n${tooltip}`
    if (await usesUserTray()) {
      await invoke('update_user_tray', { update: { type: 'tooltip', tooltip: text } })
      return
    }
    const tray = await useTray()
    if (!tray)
      return
    tray.setTooltip(text)
    tray.setTitle(text)
  }
}
