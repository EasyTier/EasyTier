import { type } from '@tauri-apps/plugin-os'
import type { Mode } from '~/composables/mode'
import { isElevated, restartElevated } from '~/composables/backend'

export async function checkElevationForService(currentMode: Mode): Promise<boolean> {
  if (type() === 'android') return true
  if (currentMode.mode === 'remote') return true
  return await isElevated()
}

export async function checkElevationForTun(currentMode: Mode): Promise<boolean> {
  if (type() === 'android') return true
  if (currentMode.mode === 'remote' || currentMode.mode === 'service') return true
  return await isElevated()
}

export async function requireElevationForService(
  mode: Mode,
  t: Function,
  confirm: any,
  toast: any
): Promise<boolean> {
  const hasElevation = await checkElevationForService(mode)
  if (!hasElevation) {
    const userAccepted = await promptElevationRestart(t, confirm)
    if (!userAccepted) {
      toast.add({
        severity: 'warn',
        summary: t('elevation.cancelled'),
        detail: t('elevation.operation_cancelled'),
        life: 3000
      })
    }
    return false
  }
  return true
}

export function promptElevationRestart(t: Function, confirm: any): Promise<boolean> {
  return new Promise((resolve, reject) => {
    confirm.require({
      group: 'elevation',
      message: t('elevation.restart_confirm'),
      header: t('elevation.restart_required'),
      icon: 'pi pi-exclamation-triangle',
      rejectProps: {
        label: t('web.common.cancel'),
        severity: 'secondary',
        outlined: true
      },
      acceptProps: {
        label: t('elevation.restart'),
      },
      accept: async () => {
        try {
          await restartElevated()
          resolve(true)
        } catch (e) {
          console.error('Failed to restart elevated:', e)
          reject(e)
        }
      },
      reject: () => {
        resolve(false)
      }
    })
  })
}
