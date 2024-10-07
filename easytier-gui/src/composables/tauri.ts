export async function tauriCloseWindow() {
  if (isTauri) {
    const { exit } = await import('@tauri-apps/plugin-process')
    await exit()
  }
}

export async function tauriMinimizeWindow() {
  if (isTauri) {
    const { getCurrentWindow } = await import('@tauri-apps/api/window')
    await getCurrentWindow().hide()
  }
}
