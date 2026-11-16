import { beforeEach, expect, it, vi } from 'vitest'

const invoke = vi.hoisted(() => vi.fn())
vi.mock('@tauri-apps/api/core', () => ({ invoke }))
vi.mock('@tauri-apps/plugin-os', () => ({ type: () => 'android' }))
vi.mock('easytier-frontend-lib', () => ({
  NetworkTypes: { normalizeNetworkConfig: (value: unknown) => value, toBackendNetworkConfig: (value: unknown) => value },
}))

const snapshot = { schema_version: 1, configs: [], desired_enabled: [], profile: { mode: 'normal' }, selected_network: 'saved' }
let storage: Map<string, string>
beforeEach(() => {
  vi.resetModules()
  invoke.mockReset()
  storage = new Map()
  vi.stubGlobal('localStorage', {
    getItem: (key: string) => storage.get(key) ?? null,
    setItem: (key: string, value: string) => storage.set(key, value),
    removeItem: (key: string) => storage.delete(key),
  })
})

it('uses native data without parsing or uploading stale legacy data', async () => {
  storage.set('networkList', 'broken JSON')
  invoke.mockResolvedValue(snapshot)
  const { bootstrapAndroidManagement, androidPreferences } = await import('./android_management')
  await bootstrapAndroidManagement()
  expect(invoke).toHaveBeenCalledTimes(1)
  expect(androidPreferences().selected_network).toBe('saved')
  expect(storage.has('networkList')).toBe(false)
})

it('migrates source, backend and selection before deleting plaintext', async () => {
  storage.set('networkList', JSON.stringify([{ instance_id: 'legacy' }, { config: { instance_id: 'managed' }, source: 'webhook' }]))
  storage.set('app_mode', JSON.stringify({ mode: 'remote', remote_rpc_address: 'tcp://example.invalid:15888' }))
  storage.set('last_network_instance_id', 'legacy')
  invoke.mockResolvedValueOnce(null).mockResolvedValueOnce(snapshot)
  const { bootstrapAndroidManagement } = await import('./android_management')
  await bootstrapAndroidManagement()
  expect(invoke.mock.calls[1][1].legacy).toMatchObject({
    configs: [{ source: 'legacy' }, { source: 'web' }],
    profile: { mode: 'remote' },
    selected_network: 'legacy',
    desired_enabled: [],
  })
  expect(storage.size).toBe(0)
})

it('keeps legacy credentials when migration fails', async () => {
  storage.set('networkList', '[]')
  storage.set('app_mode', '{"mode":"normal"}')
  invoke.mockResolvedValueOnce(null).mockRejectedValueOnce(new Error('write failed'))
  const { bootstrapAndroidManagement } = await import('./android_management')
  await expect(bootstrapAndroidManagement()).rejects.toThrow('write failed')
  expect(storage.size).toBe(2)
})

it('does not import defaults over corrupt native data', async () => {
  storage.set('networkList', '[]')
  invoke.mockRejectedValue(new Error('unreadable'))
  const { bootstrapAndroidManagement } = await import('./android_management')
  await expect(bootstrapAndroidManagement()).rejects.toThrow('unreadable')
  expect(invoke).toHaveBeenCalledTimes(1)
  expect(storage.has('networkList')).toBe(true)
})

it('rejects malformed legacy records rather than importing an empty list', async () => {
  storage.set('networkList', '{}')
  invoke.mockResolvedValueOnce(null)
  const { bootstrapAndroidManagement } = await import('./android_management')
  await expect(bootstrapAndroidManagement()).rejects.toThrow('Invalid legacy')
  expect(invoke).toHaveBeenCalledTimes(1)
  expect(storage.get('networkList')).toBe('{}')
})

it('serializes preference changes and permits retry after failed writes', async () => {
  invoke.mockResolvedValueOnce(snapshot)
  const { bootstrapAndroidManagement, saveAndroidPreferences } = await import('./android_management')
  await bootstrapAndroidManagement()
  invoke.mockRejectedValueOnce(new Error('write failed')).mockResolvedValueOnce(undefined)
  const first = saveAndroidPreferences({ selected_network: 'one' })
  const second = saveAndroidPreferences({ selected_network: 'two' })
  await expect(first).rejects.toThrow('write failed')
  await second
  expect(invoke.mock.calls[2][1].selectedNetwork).toBe('two')
})
