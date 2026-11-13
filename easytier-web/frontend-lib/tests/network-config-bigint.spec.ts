import { describe, expect, it } from 'vitest'

import { NetworkConfig as NetworkConfigPb } from '../src/generated/proto/api_manage'
import {
  normalizeNetworkConfig,
  toBackendNetworkConfig,
} from '../src/types/network'

// The member config form round-trips a NetworkConfig through fromJson twice:
// once when loading the backend response, once when converting the form back
// for saving. int64 fields (managed credential expiry) become protobuf-ts
// bigints after the first pass; the second pass must still work.
describe('network config int64 round trip', () => {
  it('converts bigint form state back to backend JSON', () => {
    const backend: any = {
      network_name: 'test-mesh',
      network_secret: 's',
      managed_credentials: [
        {
          credential_id: 'cred-x',
          credential_secret: 'sec',
          allow_relay: true,
          expiry_unix: '1791971218',
          reusable: true,
        },
      ],
    }

    const form: any = normalizeNetworkConfig(backend)
    expect(typeof form.managed_credentials[0].expiry_unix).toBe('bigint')

    const saved: any = toBackendNetworkConfig(form)
    expect(saved.managed_credentials[0].expiry_unix).toBe('1791971218')

    // The saved shape must deserialize on the backend (pbjson accepts the
    // string form for int64) and survive a further fromJson pass.
    expect(() =>
      NetworkConfigPb.fromJson(saved, { ignoreUnknownFields: true }),
    ).not.toThrow()
  })
})
