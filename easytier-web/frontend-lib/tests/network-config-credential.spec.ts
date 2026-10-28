import { describe, expect, it } from 'vitest'

import {
  DEFAULT_NETWORK_CONFIG,
  normalizeNetworkConfig,
  toBackendNetworkConfig,
} from '../src/types/network'

// The form's credential field compiles into the credential-identity shape
// (empty network secret, secure mode keyed by the credential) and back.
describe('network config credential mode', () => {
  it('saves the form credential as secure mode with an empty secret', () => {
    const form = {
      ...DEFAULT_NETWORK_CONFIG(),
      network_name: 'mesh',
      network_secret: 'leaked-secret',
      credential_secret: 'EWAhomework/',
      secure_mode: undefined,
    }

    const saved: any = toBackendNetworkConfig(form)
    expect(saved.network_secret).toBeFalsy()
    expect(saved.secure_mode).toEqual({
      enabled: true,
      local_private_key: 'EWAhomework/',
    })
  })

  it('normalizes a credential instance back into the form field', () => {
    const backend: any = {
      network_name: 'mesh',
      peer_urls: ['tcp://10.1.1.1:11010'],
      secure_mode: { enabled: true, local_private_key: 'EWAhomework/' },
    }

    const form: any = normalizeNetworkConfig(backend)
    expect(form.network_secret).toBeFalsy()
    expect(form.credential_secret).toBe('EWAhomework/')
    expect(form.secure_mode).toEqual({ enabled: true })
  })

  it('preserves the credential when normalizing a form again', () => {
    const backend = {
      ...DEFAULT_NETWORK_CONFIG(),
      secure_mode: { enabled: true, local_private_key: 'EWAhomework/' },
    }

    const form = normalizeNetworkConfig(backend)
    expect(normalizeNetworkConfig(form)).toEqual(form)
    expect(normalizeNetworkConfig(form).credential_secret).toBe('EWAhomework/')
  })

  it('restores a saved form credential into the backend config', () => {
    const form = {
      ...DEFAULT_NETWORK_CONFIG(),
      credential_secret: 'EWAhomework/',
    }
    const saved = JSON.stringify(normalizeNetworkConfig(form))
    const restored = normalizeNetworkConfig(JSON.parse(saved))
    const backend = toBackendNetworkConfig(restored)

    expect(restored.credential_secret).toBe('EWAhomework/')
    expect(backend.network_secret).toBeFalsy()
    expect(backend.secure_mode).toEqual({
      enabled: true,
      local_private_key: 'EWAhomework/',
    })
  })

  it.each(['new-credential', ''])('preserves the explicit form credential %j over a backend key', (credential) => {
    const form = normalizeNetworkConfig({
      ...DEFAULT_NETWORK_CONFIG(),
      credential_secret: credential,
      secure_mode: { enabled: true, local_private_key: 'old-credential' },
    })

    expect(form.credential_secret).toBe(credential)
    expect(form.secure_mode).toEqual({ enabled: true })
    expect(toBackendNetworkConfig(form).secure_mode?.local_private_key)
      .toBe(credential || undefined)
  })

  it('keeps admin instances with a secret untouched', () => {
    const backend: any = {
      network_name: 'mesh',
      network_secret: 's3cret',
      secure_mode: { enabled: true, local_private_key: 'node-key' },
    }

    const form: any = normalizeNetworkConfig(backend)
    expect(form.credential_secret).toBeUndefined()
    expect(form.secure_mode?.local_private_key).toBe('node-key')

    const saved: any = toBackendNetworkConfig(form)
    expect(saved.network_secret).toBe('s3cret')
    expect(saved.secure_mode?.local_private_key).toBe('node-key')
  })

  it('clears the credential when switching back to the network secret', () => {
    // The form's back-link clears credential_secret (Config.useSecretMode);
    // with the field cleared, a later save must keep the network secret.
    const form = {
      ...DEFAULT_NETWORK_CONFIG(),
      network_name: 'mesh',
      network_secret: 's3cret',
      credential_secret: undefined,
    }

    const saved: any = toBackendNetworkConfig(form)
    expect(saved.network_secret).toBe('s3cret')
    expect(saved.secure_mode).toBeFalsy()
  })
})
