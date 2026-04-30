export interface UrlInputParts {
    proto: string
    host: string
    port: number | null
    suffix?: string
    hasExplicitPort?: boolean
}

export type ProtoPorts = Record<string, number>

const fallbackProto = 'tcp'
const fallbackPort = 11010
const defaultHost = '0.0.0.0'

function defaultPortFor(protos: ProtoPorts, proto: string) {
    return protos[proto] ?? fallbackPort
}

function getValidPort(portStr: string, protos: ProtoPorts, proto: string) {
    const p = parseInt(portStr)
    return isNaN(p) ? defaultPortFor(protos, proto) : p
}

export function parseUrlInput(val: string | null | undefined, protos: ProtoPorts, defaultProto = fallbackProto): UrlInputParts {
    const parseByPattern = (input: string) => {
        const trimmed = input.trim()
        if (!trimmed) {
            return null
        }

        const match = trimmed.match(/^(\w+):\/\/(.*)$/)
        const proto = match ? match[1] : defaultProto
        const rest = match ? match[2] : trimmed
        const suffixStart = rest.search(/[/?#]/)
        const authority = suffixStart >= 0 ? rest.slice(0, suffixStart) : rest
        const suffix = suffixStart >= 0 ? rest.slice(suffixStart) : ''
        if (!authority) {
            return { proto, host: '', port: null, suffix, hasExplicitPort: false }
        }

        const hostAndMaybePort = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority
        if (hostAndMaybePort.startsWith('[')) {
            const ipv6End = hostAndMaybePort.indexOf(']')
            if (ipv6End > 0) {
                const host = hostAndMaybePort.slice(0, ipv6End + 1)
                const remain = hostAndMaybePort.slice(ipv6End + 1)
                const hasExplicitPort = remain.startsWith(':')
                const port = hasExplicitPort ? getValidPort(remain.slice(1), protos, proto) : null
                return { proto, host, port, suffix, hasExplicitPort }
            }
        }

        const portMatch = hostAndMaybePort.match(/^(.*):(\d+)$/)
        if (portMatch) {
            return { proto, host: portMatch[1], port: parseInt(portMatch[2]), suffix, hasExplicitPort: true }
        }

        const invalidPortMatch = hostAndMaybePort.match(/^([^:]+):[^:]*$/)
        const host = invalidPortMatch ? invalidPortMatch[1] : hostAndMaybePort
        const port = invalidPortMatch ? defaultPortFor(protos, proto) : null
        return { proto, host, port, suffix, hasExplicitPort: false }
    }

    if (!val) {
        return { proto: defaultProto, host: '', port: defaultPortFor(protos, defaultProto) }
    }
    const parsedByPattern = parseByPattern(val)
    if (parsedByPattern) {
        return parsedByPattern
    }
    return { proto: defaultProto, host: '', port: defaultPortFor(protos, defaultProto) }
}

export function buildUrlInputValue(value: UrlInputParts, protos: ProtoPorts, forceDefaultHost = false) {
    const proto = value.proto || fallbackProto
    const rawHost = (value.host ?? '').trim()
    const host = rawHost || (forceDefaultHost ? defaultHost : '')
    if (!host) {
        return null
    }

    if (protos[proto] === 0 || value.port === null) {
        return `${proto}://${host}${value.suffix ?? ''}`
    }

    let port = value.port
    if (isNaN(parseInt(port as any))) {
        port = defaultPortFor(protos, proto)
    }

    return `${proto}://${host}:${port}${value.suffix ?? ''}`
}

export function parseHostInputOnBlur(rawHost: string, currentProto: string, protos: ProtoPorts) {
    const inferredProto = rawHost.includes('/') && currentProto === fallbackProto ? 'https' : currentProto
    const parsedHost = parseUrlInput(rawHost, protos, inferredProto)
    if (parsedHost.host && (parsedHost.proto !== currentProto || parsedHost.hasExplicitPort || parsedHost.suffix)) {
        return parsedHost
    }
    return null
}

export function getHostInputValue(value: UrlInputParts) {
    return `${value.host ?? ''}${value.suffix ?? ''}`
}
