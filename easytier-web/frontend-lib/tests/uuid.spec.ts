import { describe, expect, it } from 'vitest'
import { StrToUuid, UuidToStr } from '../src/modules/utils'

describe('UUID protobuf conversion', () => {
  it('round-trips all four uint32 parts', () => {
    const value = '12345678-9abc-def0-fedc-ba9876543210'
    const protobuf = StrToUuid(value)

    expect(protobuf).toEqual({
      part1: 0x12345678,
      part2: 0x9abcdef0,
      part3: 0xfedcba98,
      part4: 0x76543210,
    })
    expect(UuidToStr(protobuf)).toBe(value)
  })

  it('rejects malformed UUIDs', () => {
    expect(() => StrToUuid('not-a-uuid')).toThrow('Invalid UUID')
  })
})
