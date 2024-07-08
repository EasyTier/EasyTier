import { getCurrent } from '@tauri-apps/api/window'
import { Menu, MenuItem, PredefinedMenuItem } from '@tauri-apps/api/menu'
import { TrayIcon } from '@tauri-apps/api/tray'
import pkg from '~/../package.json'

const DEFAULT_TRAY_NAME = 'main'

async function toggleVisibility() {
  if (await getCurrent().isVisible()) {
    await getCurrent().hide()
  } else {
    await getCurrent().show()
    await getCurrent().setFocus()
  }
}

export async function useTray(init: boolean = false) {
  let tray = await TrayIcon.getById(DEFAULT_TRAY_NAME)
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
      }
    })
  }

  if (init) {
    tray.setTooltip(`EasyTier\n${pkg.version}`)
    tray.setMenuOnLeftClick(false);
    tray.setMenu(await Menu.new({
      id: 'main',
      items: await generateMenuItem(),
    }))
  }

  return tray
}

export async function generateMenuItem() {
  return [
    await MenuItemExit('Exit'),
    await PredefinedMenuItem.new({ item: 'Separator' }),
    await MenuItemShow('Show / Hide'),
  ] || []
}

export async function MenuItemExit(text: string) {
  return await PredefinedMenuItem.new({
    text: text,
    item: 'Quit',
  })
}

export async function MenuItemShow(text: string) {
  return await MenuItem.new({
    id: 'show',
    text,
    action: async () => {
        await toggleVisibility();
    },
  })
}

export async function setTrayMenu(items: (MenuItem | PredefinedMenuItem)[] | undefined = undefined) {
  const tray = await useTray()
  const menu = await Menu.new({
    id: 'main',
    items: items || await generateMenuItem(),
  })
  tray.setMenu(menu)
}

export async function setTrayRunState(isRunning: boolean = false) {
  const tray = await useTray()
  tray.setIcon(isRunning ? 'icons/icon-inactive.ico' : 'icons/icon.ico')
}

export async function setTrayTooltip(tooltip: string) {
  if (tooltip) {
    const tray = await useTray()
    tray.setTooltip(`EasyTier\n${pkg.version}\n${tooltip}`)
    tray.setTitle(`EasyTier\n${pkg.version}\n${tooltip}`)
  }
}