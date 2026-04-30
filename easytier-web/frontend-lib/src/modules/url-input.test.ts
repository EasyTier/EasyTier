import { describe, expect, it } from 'vitest'
import { buildUrlInputValue, getHostInputValue, parseHostInputOnBlur, parseUrlInput, type ProtoPorts } from './url-input'

const protos: ProtoPorts = {
    tcp: 11010,
    udp: 11010,
    wg: 11011,
    ws: 11011,
    wss: 11012,
    quic: 11012,
    faketcp: 11013,
    http: 80,
    https: 443,
    txt: 0,
    srv: 0,
}

function normalizeUrl(input: string, defaultProto = 'tcp') {
    return buildUrlInputValue(parseUrlInput(input, protos, defaultProto), protos, true)
}

describe('parseUrlInput', () => {
    it.each([
        ['https://raw.githubusercontent.com/aaa/bb/cc.txt', {
            proto: 'https',
            host: 'raw.githubusercontent.com',
            port: null,
            suffix: '/aaa/bb/cc.txt',
            hasExplicitPort: false,
        }],
        ['https://host:4443/path?x=1#hash', {
            proto: 'https',
            host: 'host',
            port: 4443,
            suffix: '/path?x=1#hash',
            hasExplicitPort: true,
        }],
        ['[::1]:11010/path', {
            proto: 'tcp',
            host: '[::1]',
            port: 11010,
            suffix: '/path',
            hasExplicitPort: true,
        }],
        ['  http://host/path  ', {
            proto: 'http',
            host: 'host',
            port: null,
            suffix: '/path',
            hasExplicitPort: false,
        }],
    ])('parses %s', (input, expected) => {
        expect(parseUrlInput(input, protos)).toEqual(expected)
    })

    it('parses IPv6 host without an explicit port', () => {
        expect(parseUrlInput('[::1]', protos)).toEqual({
            proto: 'tcp',
            host: '[::1]',
            port: null,
            suffix: '',
            hasExplicitPort: false,
        })
    })

    it.each([
        ['host:', 'host'],
        ['host:notaport', 'host'],
    ])('falls back to the default port for invalid port input %s', (input, host) => {
        expect(parseUrlInput(input, protos)).toEqual({
            proto: 'tcp',
            host,
            port: 11010,
            suffix: '',
            hasExplicitPort: false,
        })
    })

    it('keeps the explicit proto for an input without authority', () => {
        expect(parseUrlInput('https://', protos)).toEqual({
            proto: 'https',
            host: '',
            port: null,
            suffix: '',
            hasExplicitPort: false,
        })
    })
})

describe('buildUrlInputValue', () => {
    it.each([
        ['https://host', 'https://host'],
        ['http://host', 'http://host'],
        ['https://host:4443/path', 'https://host:4443/path'],
        ['https://host:443/path', 'https://host:443/path'],
        ['tcp://host', 'tcp://host'],
        ['wss://host', 'wss://host'],
        ['http://host/path?x=1#hash', 'http://host/path?x=1#hash'],
        ['https://host?x=1', 'https://host?x=1'],
        ['https://host#hash', 'https://host#hash'],
        ['txt://example.com/path.txt', 'txt://example.com/path.txt'],
        ['srv://_easytier._tcp.example.com', 'srv://_easytier._tcp.example.com'],
        ['custom://host/path', 'custom://host/path'],
    ])('normalizes %s to %s', (input, expected) => {
        expect(normalizeUrl(input)).toBe(expected)
    })

    it('returns null for empty host unless default host is forced', () => {
        const parsed = parseUrlInput('', protos)

        expect(buildUrlInputValue(parsed, protos, false)).toBeNull()
        expect(buildUrlInputValue(parsed, protos, true)).toBe('tcp://0.0.0.0:11010')
    })

    it('does not build a broken URL for a protocol without authority', () => {
        const parsed = parseUrlInput('https://', protos)

        expect(buildUrlInputValue(parsed, protos, false)).toBeNull()
        expect(buildUrlInputValue(parsed, protos, true)).toBe('https://0.0.0.0')
    })
})

describe('parseHostInputOnBlur', () => {
    it('infers https for a pasted host:port/path when the current proto is tcp', () => {
        const parsed = parseHostInputOnBlur('raw.githubusercontent.com:4443/aaa/bb/cc.txt', 'tcp', protos)

        expect(parsed).toEqual({
            proto: 'https',
            host: 'raw.githubusercontent.com',
            port: 4443,
            suffix: '/aaa/bb/cc.txt',
            hasExplicitPort: true,
        })
        expect(buildUrlInputValue(parsed!, protos, true)).toBe('https://raw.githubusercontent.com:4443/aaa/bb/cc.txt')
    })

    it.each([
        ['raw.githubusercontent.com/aaa/bb/cc.txt', 'tcp', 'https://raw.githubusercontent.com/aaa/bb/cc.txt'],
        ['raw.githubusercontent.com:4443/aaa/bb/cc.txt', 'https', 'https://raw.githubusercontent.com:4443/aaa/bb/cc.txt'],
        ['https://raw.githubusercontent.com:4443/aaa/bb/cc.txt', 'tcp', 'https://raw.githubusercontent.com:4443/aaa/bb/cc.txt'],
        ['  https://raw.githubusercontent.com/aaa/bb/cc.txt  ', 'tcp', 'https://raw.githubusercontent.com/aaa/bb/cc.txt'],
    ])('normalizes pasted host input %s with current proto %s', (input, currentProto, expected) => {
        const parsed = parseHostInputOnBlur(input, currentProto, protos)

        expect(buildUrlInputValue(parsed!, protos, true)).toBe(expected)
    })

    it('keeps ordinary host:port input on the current tcp protocol', () => {
        const parsed = parseHostInputOnBlur('example.com:11010', 'tcp', protos)

        expect(buildUrlInputValue(parsed!, protos, true)).toBe('tcp://example.com:11010')
    })

    it('returns null for a simple host without port or suffix', () => {
        expect(parseHostInputOnBlur('example.com', 'tcp', protos)).toBeNull()
    })
})

describe('getHostInputValue', () => {
    it('shows host and suffix while keeping the port in the port field', () => {
        const parsed = parseUrlInput('https://raw.githubusercontent.com:4443/aaa/bb/cc.txt', protos)

        expect(getHostInputValue(parsed)).toBe('raw.githubusercontent.com/aaa/bb/cc.txt')
    })

    it('shows query and hash in the host input suffix', () => {
        const parsed = parseUrlInput('https://host/path?x=1#hash', protos)

        expect(getHostInputValue(parsed)).toBe('host/path?x=1#hash')
    })
})

describe('round trip scenarios', () => {
    it.each([
        ['https://raw.githubusercontent.com/aaa/bb/cc.txt'],
        ['https://raw.githubusercontent.com:4443/aaa/bb/cc.txt'],
        ['http://host/path?x=1#hash'],
        ['tcp://example.com:11010'],
        ['txt://example.com/path.txt'],
        ['srv://_easytier._tcp.example.com'],
    ])('keeps %s stable after parse and build', (input) => {
        expect(normalizeUrl(input)).toBe(input)
    })
})
