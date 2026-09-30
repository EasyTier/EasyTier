// Regression E2E for central configuration validation before persistence.
// Requires built Web (embed) and Core binaries and the privileged `rust`
// container with the shared /data mount. Results and logs are retained in
// .test-env/central-validation-* for diagnosis.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { resolve, join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import { chromium } from 'playwright';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const run = String(Date.now()).slice(-7);
const output = join(repo, '.test-env', `central-validation-${run}`);
await mkdir(output, { recursive: true });
console.log(`ARTIFACTS=${output}`);
const webBin = join(repo, 'target/debug/easytier-web');
const coreBin = join(repo, 'target/debug/easytier-core');
const username = `validation-${run}`;
const password = 'e2e-password';
const passwordHash = '$argon2id$v=19$m=4096,t=3,p=1$ZWFzeXRpZXItZTJlLXNhbHQ$FHbDjVElaTXuArgEEQrQrO4AdsnqNOcXGA5PFY8cG/s';
const database = join(output, 'web.db');
const results = [];
const processes = [];
const namespaces = [];
const bridge = `ce${run}`;
const subnet = `10.244.${170 + Math.floor(Math.random() * 50)}`;
const gatewayIp = `${subnet}.1`;
let bridgeCreated = false;
let browser, context, page, web;
const nodes = [];
let network;

function docker(args, { allowFailure = false, input, timeout = 20000 } = {}) {
    const r = spawnSync('docker', ['exec', ...(input === undefined ? [] : ['-i']), 'rust', ...args], { encoding: 'utf8', input, timeout });
    if (!allowFailure && r.status !== 0) throw new Error(`docker ${args.join(' ')}: ${r.stderr || r.stdout || r.error}`);
    return allowFailure ? r : r.stdout.trim();
}
function ns(node, args, options) { return docker(['ip', 'netns', 'exec', node.ns, ...args], options); }
async function waitFor(check, label, timeout = 45000) {
    const end = Date.now() + timeout;
    let last;
    while (Date.now() < end) {
        try { const value = await check(); if (value) return value; } catch (error) { last = error.message; }
        await delay(300);
    }
    throw new Error(`Timed out: ${label}${last ? `; last error: ${last}` : ''}`);
}
async function step(ids, name, action) {
    const started = new Date().toISOString();
    try {
        const evidence = await action();
        results.push({ ids, name, status: 'PASS', started, evidence: evidence ?? 'assertions passed' });
        console.log(`PASS ${ids.join(',')} ${name}`);
        return true;
    } catch (error) {
        results.push({ ids, name, status: 'FAIL', started, error: error.stack });
        console.error(`FAIL ${ids.join(',')} ${name}: ${error.message}`);
        if (network && context) await writeFile(join(output, `failure-${results.length}-members.json`), JSON.stringify(await members().catch(() => null), null, 2));
        if (page) await page.screenshot({ path: join(output, `failure-${results.length}.png`), fullPage: true }).catch(() => {});
        return false;
    } finally {
        await writeFile(join(output, 'results.json'), JSON.stringify(results, null, 2));
    }
}
async function freePort() {
    return new Promise((resolvePort, reject) => {
        const server = createServer();
        server.once('error', reject);
        server.listen(0, '0.0.0.0', () => { const port = server.address().port; server.close(() => resolvePort(port)); });
    });
}
function processLog(child, label, pidFile) {
    let logs = '';
    for (const stream of [child.stdout, child.stderr]) stream.on('data', data => { logs += data; });
    const p = { child, label, pidFile, logs: () => logs };
    processes.push(p);
    return p;
}
async function dockerProcess(label, args) {
    const pidFile = join(output, `${label}.pid`);
    return processLog(spawn('docker', ['exec', 'rust', 'sh', '-c', 'echo $$ > "$1"; shift; exec "$@"', 'audit', pidFile, ...args], { stdio: ['ignore', 'pipe', 'pipe'] }), label, pidFile);
}
async function stop(p) {
    if (!p || p.stopped) return;
    if (p.pidFile) {
        const pid = await readFile(p.pidFile, 'utf8').catch(() => '');
        if (pid.trim()) docker(['kill', '-INT', pid.trim()], { allowFailure: true });
    } else p.child.kill('SIGINT');
    if (p.child.exitCode === null) await Promise.race([new Promise(r => p.child.once('exit', r)), delay(3000)]);
    if (p.child.exitCode === null && p.pidFile) {
        const pid = await readFile(p.pidFile, 'utf8').catch(() => '');
        if (pid.trim()) docker(['kill', '-KILL', pid.trim()], { allowFailure: true });
    }
    if (p.child.exitCode === null) p.child.kill('SIGTERM');
    p.stopped = true;
    await writeFile(join(output, `${p.label}.log`), p.logs());
}
const apiPort = await freePort();
const configPort = await freePort();
const proxyPort = await freePort();
const base = `http://127.0.0.1:${apiPort}`;
const peerUrl = `tcp://${gatewayIp}:${proxyPort}`;
function startWeb(relay = true) {
    return processLog(spawn(webBin, ['--db', database, '--api-server-addr', '127.0.0.1', '--api-server-port', String(apiPort), '--config-server-protocol', 'tcp', '--config-server-port', String(configPort), '--gateway-peer-url', peerUrl, ...(relay ? ['--gateway-relay-data'] : []), '--console-log-level', 'error'], { stdio: ['ignore', 'pipe', 'pipe'] }), `web-${processes.length}`);
}
async function request(method, path, data, expected = 200) {
    const r = await context.request.fetch(`/api/v1${path}`, { method, ...(data === undefined ? {} : { data }) });
    const text = await r.text();
    assert.equal(r.status(), expected, `${method} ${path}: ${text}`);
    return text ? JSON.parse(text) : undefined;
}
function protoUuid(value) {
    const hex = value.replaceAll('-', '');
    return Object.fromEntries([0, 1, 2, 3].map(i => [`part${i + 1}`, parseInt(hex.slice(i * 8, i * 8 + 8), 16)]));
}
async function rpc(node, id, method, service = 'api.instance.PeerManageRpcService', payload = {}) {
    return request('POST', `/machines/${node.id}/proxy-rpc`, { service_name: service, method_name: method, payload: { ...(id ? { instance: { id: protoUuid(id) } } : {}), ...payload } });
}
const memberPath = (node, id = network.network_id) => `/networks/${id}/members/${node.id}`;
async function runtimeConfig(node, id = network.network_id) { return request('GET', `/machines/${node.id}/networks/config/${id}`); }
async function members(id = network.network_id) { return (await request('GET', `/networks/${id}/members`)).members; }
async function setOverride(node, override, id = network.network_id) {
    await request('PUT', `${memberPath(node, id)}/config`, { config: override });
}
function baseOverride(node) {
    return { no_tun: false, disable_ipv6: true, multi_thread: false, dev_name: `et${node.name}`, listener_urls: ['tcp://0.0.0.0:11010'], disable_udp_hole_punching: true, disable_tcp_hole_punching: true, disable_upnp: true };
}
async function createNetwork(name, options = {}) {
    return request('POST', '/networks', { settings: { display_name: name, network_name: `${username}-${name}`, networking_method: 'Gateway', virtual_cidr: '10.88.99.0/24', secure_mode: true, ...options } });
}
async function addNodes(selected, id = network.network_id, extra = {}) {
    await request('POST', `/networks/${id}/members`, { device_ids: selected.map(n => n.id), ...extra }, 204);
    await waitFor(async () => {
        const current = await members(id);
        return selected.every(n => current.some(m => m.device_id === n.id && m.running));
    }, 'members running');
}
async function startNode(node) {
    node.process = await dockerProcess(`core-${node.name}-${processes.length}`, ['ip', 'netns', 'exec', node.ns, coreBin, '--config-server', `${peerUrl}/${username}`, '--machine-id', node.id, '--config-dir', node.config, '--no-listener', '--no-tun', '--hostname', `audit-${node.name}`, '--rpc-portal', '127.0.0.1:15888', '--console-log-level', 'error']);
    await waitFor(async () => (await request('GET', '/machines')).machines.some(m => m.info?.machine_id && m.online && m.info.hostname === `audit-${node.name}`), `enroll ${node.name}`);
}
async function login() {
    await page.goto('/');
    await page.locator('#username').fill(username);
    await page.locator('#password input').fill(password);
    await page.getByRole('button', { name: 'Login', exact: true }).click();
    await page.locator('.console-page').waitFor();
    await context.storageState({ path: join(output, 'browser-state.json') });
}
function ping(from, to, expected = true) {
    const r = ns(from, ['ping', '-c', '2', '-W', '1', to], { allowFailure: true, timeout: 5000 });
    assert.equal(r.status === 0, expected, `ping ${from.name} -> ${to}: ${r.stdout} ${r.stderr}`);
    return r.stdout;
}
async function eventualPing(from, to) { return waitFor(async () => ns(from, ['ping', '-c', '1', '-W', '1', to], { allowFailure: true }).status === 0, `ping ${from.name} -> ${to}`); }

try {
    docker(['ip', 'link', 'add', bridge, 'type', 'bridge']); bridgeCreated = true;
    docker(['ip', 'addr', 'add', `${gatewayIp}/24`, 'dev', bridge]);
    docker(['ip', 'link', 'set', bridge, 'up']);
    for (const [i, name] of ['a', 'b'].entries()) {
        const node = { name, ns: `ce-${run}-${name}`, id: randomUUID(), ip: `${subnet}.${10 + i}`, config: join(output, name) };
        await mkdir(node.config);
        docker(['ip', 'netns', 'add', node.ns]); namespaces.push(node.ns);
        const veth = `v${run}${name}`;
        docker(['ip', 'link', 'add', veth, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', node.ns]);
        docker(['ip', 'link', 'set', veth, 'master', bridge]);
        docker(['ip', 'link', 'set', veth, 'up']);
        ns(node, ['ip', 'link', 'set', 'lo', 'up']);
        ns(node, ['ip', 'addr', 'add', `${node.ip}/24`, 'dev', 'eth0']);
        ns(node, ['ip', 'link', 'set', 'eth0', 'up']);
        nodes.push(node);
    }
    const route = docker(['ip', 'route']);
    const host = route.match(/default via ([\d.]+)/)?.[1];
    assert.ok(host);
    const proxyScript = join(output, 'proxy.py');
    await writeFile(proxyScript, `import socket,socketserver,threading\nclass H(socketserver.BaseRequestHandler):\n def handle(self):\n  remote=socket.create_connection(('${host}',${configPort}))\n  def copy(a,b):\n   try:\n    while True:\n     data=a.recv(65536)\n     if not data: break\n     b.sendall(data)\n   except OSError: pass\n   finally:\n    try: b.shutdown(socket.SHUT_WR)\n    except OSError: pass\n  t=threading.Thread(target=copy,args=(self.request,remote));t.start();copy(remote,self.request);t.join();remote.close()\nclass S(socketserver.ThreadingTCPServer):\n allow_reuse_address=True\n daemon_threads=True\nS(('${gatewayIp}',${proxyPort}),H).serve_forever()\n`);
    await dockerProcess('config-proxy', ['python3', proxyScript]);
    web = startWeb();
    await waitFor(async () => (await fetch(`${base}/api_meta.js`)).ok, 'Web ready');
    const db = new DatabaseSync(database);
    const user = db.prepare('INSERT INTO users(username,password) VALUES (?,?)').run(username, passwordHash);
    const group = db.prepare("SELECT id FROM groups WHERE name='users'").get();
    db.prepare('INSERT INTO users_groups(user_id,group_id) VALUES (?,?)').run(user.lastInsertRowid, group.id); db.close();
    browser = await chromium.launch({ headless: true });
    context = await browser.newContext({ baseURL: base });
    await context.addInitScript(() => localStorage.setItem('lang', 'en'));
    page = await context.newPage();
    await login();
    await writeFile(join(output, 'environment.json'), JSON.stringify({ run, base, apiPort, configPort, peerUrl, bridge, nodes, code: spawnSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' }).stdout.trim() }, null, 2));
    const [a, b] = nodes;
    for (const node of nodes) await startNode(node);
    network = await createNetwork('validation');
    await addNodes(nodes);
    for (const node of nodes) await setOverride(node, baseOverride(node));
    const current = await waitFor(async () => {
        const value = await members();
        return value.length === 2 && value.every(member => member.runtime_virtual_ipv4) ? value : false;
    }, 'two assigned addresses');
    for (const node of nodes) node.vip = current.find(member => member.device_id === node.id).runtime_virtual_ipv4.split('/')[0];
    await eventualPing(a, b.vip);

    // Read only intent tables: device heartbeats and browser sessions may change.
    function intentSnapshot() {
        const db = new DatabaseSync(database, { readOnly: true });
        try {
            return Object.fromEntries(['networks', 'network_members', 'network_credentials'].map(table => [table, db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all()]));
        } finally { db.close(); }
    }
    async function snapshot() {
        return {
            database: intentSnapshot(),
            network: await request('GET', `/networks/${network.network_id}`),
            overrides: await Promise.all(nodes.map(node => request('GET', `${memberPath(node)}/config`))),
            runtime: await Promise.all(nodes.map(node => runtimeConfig(node))),
            coreConfig: await Promise.all(nodes.map(async node => {
                const result = await rpc(node, network.network_id, 'show_node_info');
                assert.ok(result.node_info?.config);
                return result.node_info.config;
            })),
        };
    }
    async function rejectWithoutMutation(method, path, candidate) {
        await eventualPing(a, b.vip);
        const before = await snapshot();
        // A continuous probe spans the rejected request and reconciliation window.
        const probe = spawn('docker', ['exec', 'rust', 'ip', 'netns', 'exec', a.ns, 'ping', '-i', '0.2', '-c', '15', '-W', '1', b.vip], { stdio: ['ignore', 'pipe', 'pipe'] });
        let packets = '';
        probe.stdout.on('data', data => { packets += data; });
        probe.stderr.on('data', data => { packets += data; });
        const completed = new Promise(resolveExit => probe.on('exit', code => resolveExit(code)));
        const response = await request(method, path, candidate, 400);
        assert.equal(await completed, 0, packets);
        assert.match(packets, /15 packets transmitted, 15 received, 0% packet loss/);
        assert.deepEqual(await snapshot(), before, 'rejected candidate changed intent or runtime config');
        return { response, ping: packets, databaseUnchanged: true, runtimeUnchanged: true };
    }

    await step(['F01'], 'unsupported Manual and PublicServer URLs rejected without members', async () => {
        const evidence = [];
        for (const method of ['Manual', 'PublicServer']) {
            const settings = { display_name: `empty-${method}`, network_name: `${username}-${method}`, networking_method: method, virtual_cidr: '10.90.0.0/24', secure_mode: true, ...(method === 'Manual' ? { peer_urls: ['bogus://127.0.0.1:9999'] } : { public_server_url: 'bogus://127.0.0.1:9999' }) };
            evidence.push(await rejectWithoutMutation('POST', '/networks', { settings }));
        }
        return evidence;
    });
    await step(['F01'], 'unsupported Manual and PublicServer updates rejected with running members', async () => {
        const evidence = [];
        for (const method of ['Manual', 'PublicServer']) {
            const settings = { ...network, networking_method: method, ...(method === 'Manual' ? { peer_urls: ['bogus://127.0.0.1:9999'] } : { public_server_url: 'bogus://127.0.0.1:9999' }) };
            evidence.push(await rejectWithoutMutation('PATCH', `/networks/${network.network_id}`, { settings }));
        }
        return evidence;
    });
    await step(['F01'], 'supported discovery protocols accepted for empty networks', async () => {
        const evidence = [];
        for (const protocol of ['http', 'https', 'txt', 'srv']) {
            for (const method of ['Manual', 'PublicServer']) {
                const url = `${protocol}://discovery.invalid`;
                const created = await createNetwork(`${method}-${protocol}`, { networking_method: method, ...(method === 'Manual' ? { peer_urls: [url] } : { public_server_url: url }) });
                const saved = await request('GET', `/networks/${created.network_id}`);
                assert.equal(method === 'Manual' ? saved.peer_urls[0] : saved.public_server_url, url);
                evidence.push({ method, url, accepted: true });
                await request('DELETE', `/networks/${created.network_id}`, undefined, 204);
            }
        }
        return evidence;
    });
    await step(['F02'], 'IPv6 proxy CIDR rejected before persistence', () => rejectWithoutMutation('PATCH', memberPath(a), { proxy_cidrs: ['2001:db8:240::/64'] }));
    await step(['F02'], 'IPv4 proxy CIDR accepted and advertised by real Core', async () => {
        ns(a, ['ip', 'addr', 'add', '198.18.240.1/24', 'dev', 'lo']);
        await request('PATCH', memberPath(a), { proxy_cidrs: ['198.18.240.0/24'] });
        await waitFor(async () => JSON.stringify(await rpc(b, network.network_id, 'list_route')).includes('198.18.240.0/24'), 'IPv4 route advertisement');
        await eventualPing(b, '198.18.240.1');
        const evidence = ping(b, '198.18.240.1');
        await request('PATCH', memberPath(a), { proxy_cidrs: [] });
        await waitFor(async () => !(await runtimeConfig(a)).proxy_cidrs?.length, 'proxy clear applied');
        return evidence;
    });
    const portal = { enabled: true, wireguard_listen: '0.0.0.0:15820', wireguard_private_key: docker(['wg', 'genkey']), clients: [{ name: 'valid-client', virtual_ip: '10.88.99.210/24', groups: [] }] };
    await step(['F02'], 'valid WireGuard client accepted and applied', async () => {
        await setOverride(a, { ...baseOverride(a), vpn_portal_config: portal });
        const runtime = await waitFor(async () => {
            const result = await rpc(a, network.network_id, 'get_vpn_portal_info', 'api.instance.VpnPortalRpcService');
            return result.vpn_portal_info?.clients?.[0]?.client_config ? result.vpn_portal_info : false;
        }, 'valid WireGuard portal');
        await eventualPing(a, b.vip);
        return { clients: runtime.clients.map(client => ({ name: client.name, virtual_ip: client.virtual_ip })), ping: ping(a, b.vip) };
    });
    const validClient = portal.clients[0];
    const invalidClients = [
        ['duplicate IP', [validClient, { ...validClient, name: 'second-client' }]],
        ['duplicate name', [validClient, { ...validClient, virtual_ip: '10.88.99.211/24' }]],
        ['invalid IP', [{ ...validClient, virtual_ip: 'not-an-ip' }]],
        ['network address', [{ ...validClient, virtual_ip: '10.88.99.0/24' }]],
        ['broadcast address', [{ ...validClient, virtual_ip: '10.88.99.255/24' }]],
        ['host address', [{ ...validClient, virtual_ip: `${a.vip}/24` }]],
        ['unknown ACL group', [{ ...validClient, groups: ['not-declared'] }]],
    ];
    for (const [label, clients] of invalidClients) {
        await step(['F02'], `WireGuard ${label} rejected without disrupting active network`, () => rejectWithoutMutation('PUT', `${memberPath(a)}/config`, { config: { ...baseOverride(a), vpn_portal_config: { ...portal, clients } } }));
    }
    await step(['F02'], 'WireGuard client clearing accepted and applied', async () => {
        await setOverride(a, { ...baseOverride(a), vpn_portal_config: { ...portal, clients: [] } });
        await waitFor(async () => {
            const result = await rpc(a, network.network_id, 'get_vpn_portal_info', 'api.instance.VpnPortalRpcService');
            return result.vpn_portal_info && !(result.vpn_portal_info.clients?.length);
        }, 'WireGuard client clear');
        await eventualPing(a, b.vip);
        return { config: await request('GET', `${memberPath(a)}/config`), ping: ping(a, b.vip) };
    });
} catch (error) {
    results.push({ ids: [], name: 'suite setup or infrastructure', status: 'FAIL', error: error.stack });
    console.error(error);
} finally {
    await browser?.close();
    for (const p of [...processes].reverse()) await stop(p);
    for (const name of namespaces) docker(['ip', 'netns', 'delete', name], { allowFailure: true });
    if (bridgeCreated) docker(['ip', 'link', 'delete', bridge], { allowFailure: true });
    await writeFile(join(output, 'results.json'), JSON.stringify(results, null, 2));
    console.log(`RESULTS=${join(output, 'results.json')}`);
}
process.exitCode = results.some(r => r.status === 'FAIL') ? 1 : 0;
