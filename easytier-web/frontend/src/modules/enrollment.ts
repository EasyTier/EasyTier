import type { ConsoleInfo } from './api';
import { getApiBase } from './api-host';

const defaultCommand = 'easytier-core --config-server {protocol}://{host}:{port}/{username}';

export function buildEnrollCommand(info: ConsoleInfo | null): string {
    if (!info) return '';

    const values = {
        username: info.username,
        host: new URL(getApiBase(), window.location.href).hostname,
        protocol: info.config_server_protocol,
        port: String(info.config_server_port),
    };
    // Replace known placeholders in a single pass so values are never
    // interpreted as templates themselves; all other braces remain literal.
    return (info.console_enroll_command ?? defaultCommand).replace(
        /\{(username|host|protocol|port)\}/g,
        (_, key: keyof typeof values) => values[key],
    );
}
