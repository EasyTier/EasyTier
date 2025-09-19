import { IPv4, IPv6 } from 'ip-num/IPNumber'
import { Ipv4Addr, Ipv4Inet, Ipv6Addr, Ipv6Inet } from '../types/network'

export function ipv4ToString(ip: Ipv4Addr) {
    return IPv4.fromNumber(ip.addr).toString()
}

export function ipv4InetToString(ip: Ipv4Inet | undefined) {
    if (ip?.address === undefined) {
        return 'undefined'
    }
    return `${ipv4ToString(ip.address)}/${ip.network_length}`
}

export function ipv6ToString(ip: Ipv6Addr) {
    return IPv6.fromBigInt(
        (BigInt(ip.part1) << BigInt(96))
        + (BigInt(ip.part2) << BigInt(64))
        + (BigInt(ip.part3) << BigInt(32))
        + BigInt(ip.part4),
    )
}

// Compress an expanded IPv6 string like "6:0:0:0:0:0:0:0" to "6::"
export function compressIpv6String(s: string): string {
    // Normalize to lowercase and split into groups
    const parts = s.toLowerCase().split(':').map(p => p || '0')
    // If input already contains '::', return as-is
    if (s.includes('::')) return s.toLowerCase()
    // Remove leading zeros per group
    const norm = parts.map(p => p.replace(/^0+([0-9a-f]+)$/i, '$1') || '0')
    // Find the longest run of consecutive '0'
    let bestStart = -1, bestLen = 0
    let curStart = -1, curLen = 0
    for (let i = 0; i < norm.length; i++) {
        if (norm[i] === '0') {
            if (curStart === -1) curStart = i
            curLen++
        } else {
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart }
            curStart = -1; curLen = 0
        }
    }
    if (curLen > bestLen) { bestLen = curLen; bestStart = curStart }
    // If there is a run to compress, replace it with '' sentinel then join
    if (bestLen > 1) {
        const replaced: string[] = []
        for (let i = 0; i < norm.length; i++) {
            if (i === bestStart) {
                replaced.push('')
                i += bestLen - 1
            } else {
                replaced.push(norm[i])
            }
        }
        // Fix leading/trailing empties for correct '::'
        let out = replaced.join(':')
        if (out.startsWith(':')) out = ':' + out
        if (out.endsWith(':')) out = out + ':'
        return out.replace(':::', '::')
    }
    return norm.join(':')
}

function ipv6AddrToGroups(addr: Ipv6Addr): number[] {
    const hi = BigInt(addr.part1) << BigInt(96)
    const h2 = BigInt(addr.part2) << BigInt(64)
    const h3 = BigInt(addr.part3) << BigInt(32)
    const val = hi + h2 + h3 + BigInt(addr.part4)
    const groups: number[] = []
    for (let i = 7; i >= 0; i--) {
        const shift = BigInt(i * 16)
        const g = Number((val >> shift) & BigInt(0xffff))
        groups.push(g)
    }
    return groups
}

function groupsToCompressed(groups: number[]): string {
    // Find longest zero run
    let bestStart = -1, bestLen = 0
    let curStart = -1, curLen = 0
    for (let i = 0; i < groups.length; i++) {
        if (groups[i] === 0) {
            if (curStart === -1) curStart = i
            curLen++
        } else {
            if (curLen > bestLen) { bestLen = curLen; bestStart = curStart }
            curStart = -1; curLen = 0
        }
    }
    if (curLen > bestLen) { bestLen = curLen; bestStart = curStart }
    const hex = groups.map(g => g.toString(16))
    if (bestLen > 1) {
        const left = hex.slice(0, bestStart).join(':')
        const right = hex.slice(bestStart + bestLen).join(':')
        if (left && right) return `${left}::${right}`
        if (left) return `${left}::`
        if (right) return `::${right}`
        return '::'
    }
    return hex.join(':')
}

export function ipv6AddrToCompressedString(addr: Ipv6Addr): string {
    return groupsToCompressed(ipv6AddrToGroups(addr))
}

export function ipv6InetToCompressedString(inet: Ipv6Inet): string {
    return `${ipv6AddrToCompressedString(inet.address)}/${inet.network_length}`
}

function toHexString(uint64: bigint, padding = 9): string {
    let hexString = uint64.toString(16);
    while (hexString.length < padding) {
        hexString = '0' + hexString;
    }
    return hexString;
}

function uint32ToUuid(part1: number, part2: number, part3: number, part4: number): string {
    // 将两个 uint64 转换为 16 进制字符串
    const part1Hex = toHexString(BigInt(part1), 8);
    const part2Hex = toHexString(BigInt(part2), 8);
    const part3Hex = toHexString(BigInt(part3), 8);
    const part4Hex = toHexString(BigInt(part4), 8);

    // 构造 UUID 格式字符串
    const uuid = `${part1Hex.substring(0, 8)}-${part2Hex.substring(0, 4)}-${part2Hex.substring(4, 8)}-${part3Hex.substring(0, 4)}-${part3Hex.substring(4, 8)}${part4Hex.substring(0, 12)}`;

    return uuid;
}

export interface UUID {
    part1: number;
    part2: number;
    part3: number;
    part4: number;
}

export function UuidToStr(uuid: UUID): string {
    return uint32ToUuid(uuid.part1, uuid.part2, uuid.part3, uuid.part4);
}

export interface Location {
    country: string | undefined;
    city: string | undefined;
    region: string | undefined;
}

export interface DeviceInfo {
    hostname: string;
    public_ip: string;
    running_network_count: number;
    report_time: string;
    easytier_version: string;
    running_network_instances?: Array<string>;
    machine_id: string;
    location: Location | undefined;
}

export function buildDeviceInfo(device: any): DeviceInfo {
    let dev_info: DeviceInfo = {
        hostname: device.info?.hostname,
        public_ip: device.client_url,
        running_network_instances: device.info?.running_network_instances.map((instance: any) => UuidToStr(instance)),
        running_network_count: device.info?.running_network_instances.length,
        report_time: device.info?.report_time,
        easytier_version: device.info?.easytier_version,
        machine_id: UuidToStr(device.info?.machine_id),
        location: device.location,
    };

    return dev_info;
}

// write a class to run a function periodically and can be stopped by calling stop(), use setTimeout to trigger the function
export class PeriodicTask {
    private interval: number;
    private task: (() => Promise<void>) | undefined;
    private timer: any;

    constructor(task: () => Promise<void>, interval: number) {
        this.interval = interval;
        this.task = task;
    }

    _runTaskHelper(nextInterval: number) {
        this.timer = setTimeout(async () => {
            if (this.task) {
                await this.task();
                this._runTaskHelper(this.interval);
            }
        }, nextInterval);
    }

    start() {
        this._runTaskHelper(0);
    }

    stop() {
        this.task = undefined;
        clearTimeout(this.timer);
    }
}
