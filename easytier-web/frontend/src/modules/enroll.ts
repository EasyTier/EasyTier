import type { ConsoleInfo } from './api';
import { getApiBase } from './api-host';

// Devices reach the console through whatever address the deployment exposes,
// which is not necessarily the host the dashboard is opened with (reverse
// proxy, port mapping, NAT). Operators can pin that address with
// --config-server-host, given as host, host:port or a full URL such as
// udp://et.example.com:22020. Without it the browser origin stands in.
const configuredHost = (info: ConsoleInfo): string => info.config_server_host?.trim() ?? '';

// An authority already carrying a port wins over --config-server-port, so
// host:443 keeps working when the console itself listens on 22020.
const hasExplicitPort = (authority: string): boolean =>
    authority.startsWith('[') ? /^\[[^\]]*\]:\d+$/.test(authority) : /^[^:]+:\d+$/.test(authority);

// The config-server URL embedded in the enrollment command.
export const enrollEndpoint = (info: ConsoleInfo): string => {
    const configured = configuredHost(info);
    if (configured) {
        const scheme = configured.match(/^([a-z][a-z0-9+.-]*):\/\/(.*)$/i);
        const protocol = scheme ? scheme[1].toLowerCase() : info.config_server_protocol;
        const host = (scheme ? scheme[2] : configured).split('/')[0];
        return `${protocol}://${hasExplicitPort(host) ? host : `${host}:${info.config_server_port}`}`;
    }
    const host = new URL(getApiBase(), window.location.href).hostname;
    return `${info.config_server_protocol}://${host}:${info.config_server_port}`;
};

// The command a device runs to enroll into this console.
export const enrollCommand = (info: ConsoleInfo): string =>
    `easytier-core --config-server ${enrollEndpoint(info)}/${info.username}`;
