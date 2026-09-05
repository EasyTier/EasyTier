export type ConfigSource = 'user' | 'web' | 'legacy'

export function normalizeConfigSource(source: unknown): ConfigSource {
  if (source === 'user' || source === 'web' || source === 'legacy') {
    return source
  }

  if (source === 'webhook') {
    return 'web'
  }

  return 'legacy'
}
