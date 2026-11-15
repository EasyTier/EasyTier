import type { ConsoleInfo } from './api';

export function enrollmentCommands(info: ConsoleInfo | null, hostname: string): string[] {
    if (!info) return [];
    const protocols = info.config_server_protocols ?? [info.config_server_protocol];
    const host = hostname.includes(':') && !hostname.startsWith('[') ? `[${hostname}]` : hostname;
    return protocols.filter(protocol => ['udp', 'tcp', 'ws'].includes(protocol))
        .map(protocol => `easytier-core --config-server ${protocol}://${host}:${info.config_server_port}/${encodeURIComponent(info.username)}`);
}
