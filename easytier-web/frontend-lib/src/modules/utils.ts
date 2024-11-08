import { IPv4, IPv6 } from 'ip-num/IPNumber'
import { Ipv4Addr, Ipv6Addr } from '../types/network'

export function num2ipv4(ip: Ipv4Addr) {
    return IPv4.fromNumber(ip.addr)
}

export function num2ipv6(ip: Ipv6Addr) {
    return IPv6.fromBigInt(
        (BigInt(ip.part1) << BigInt(96))
        + (BigInt(ip.part2) << BigInt(64))
        + (BigInt(ip.part3) << BigInt(32))
        + BigInt(ip.part4),
    )
}
