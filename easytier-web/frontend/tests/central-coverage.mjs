// Real central-management coverage. Requires built Web (embed), Core and CLI
// binaries and the privileged `rust` container with the shared /data mount.
// Results and process logs are retained in .test-env/central-e2e-* for diagnosis.
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
const output = join(repo, '.test-env', `central-e2e-${run}`);
await mkdir(output, { recursive: true });
console.log(`ARTIFACTS=${output}`);
const webBin = join(repo, 'target/debug/easytier-web');
const coreBin = join(repo, 'target/debug/easytier-core');
const username = `audit-${run}`;
const password = 'e2e-password';
const passwordHash = '$argon2id$v=19$m=4096,t=3,p=1$ZWFzeXRpZXItZTJlLXNhbHQ$FHbDjVElaTXuArgEEQrQrO4AdsnqNOcXGA5PFY8cG/s';
const database = join(output, 'web.db');
const results = [];
const processes = [];
const namespaces = [];
const bridge = `ce${run}`;
const subnet = `10.245.${170 + Math.floor(Math.random() * 50)}`;
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
        if (network && context) for (const node of nodes.slice(0, 3)) {
            const config = await runtimeConfig(node).catch(() => null);
            const evidence = {
                proxy_cidrs: config?.proxy_cidrs,
                grants: config?.managed_credentials?.map(c => ({ credential_id: c.credential_id, allowed_proxy_cidrs: c.allowed_proxy_cidrs })),
                routes: await rpc(node, network.network_id, 'list_route').catch(() => null),
            };
            await writeFile(join(output, `failure-${results.length}-${node.name}-routes.json`), JSON.stringify(evidence, null, 2));
        }
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
async function runningInfo(node, id = network.network_id) { return (await rpc(node, id, 'show_node_info')).node_info; }
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
async function updateNetwork(settings, extra = {}) {
    network = await request('PATCH', `/networks/${network.network_id}`, { settings: { ...network, ...settings }, ...extra });
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
async function policy(value) { await request('PUT', `/networks/${network.network_id}/acl-policy`, value); await delay(2000); }
function rule(id, sources, destinations, protocols, action = 'allow') { return { id, name: id, enabled: true, action, sources, destinations, protocols: protocols.map(p => ({ stateful: false, ports: [], ...p })) }; }

try {
    docker(['ip', 'link', 'add', bridge, 'type', 'bridge']); bridgeCreated = true;
    docker(['ip', 'addr', 'add', `${gatewayIp}/24`, 'dev', bridge]);
    docker(['ip', 'link', 'set', bridge, 'up']);
    for (const [i, name] of ['a', 'b', 'c', 'wg'].entries()) {
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
    const [a, b, c, wg] = nodes;
    await step(['D01'], 'enroll three real managed Cores', async () => { for (const n of [a, b, c]) await startNode(n); return request('GET', '/machines'); });
    await step(['N01', 'M01'], 'secure Gateway with three real members and TUN devices', async () => {
        network = await createNetwork('gateway'); await addNodes([a, b, c]);
        for (const n of [a, b, c]) await setOverride(n, baseOverride(n));
        const current = await waitFor(async () => { const current = await members(); return current.length === 3 && current.every(m => m.runtime_virtual_ipv4) ? current : false; }, 'member IPv4 addresses');
        for (const n of [a, b, c]) n.vip = current.find(m => m.device_id === n.id).runtime_virtual_ipv4.split("/")[0];
        await eventualPing(a, b.vip); return { members: current, ping: ping(a, b.vip) };
    });
    await step(['REG-DIRECT'], 'direct enabled and disabled networks survive central deletion and Web restart', async () => {
        const directIds = [randomUUID(), randomUUID()];
        for (const id of directIds) await request('POST', `/machines/${a.id}/networks`, { save: true, config: { instance_id: id, network_name: id, networking_method: 'Standalone', no_tun: true, disable_ipv6: true, multi_thread: false } });
        await request('PUT', `/machines/${a.id}/networks/${directIds[1]}`, { disabled: true });
        const extra = await createNetwork('direct-coexist', { networking_method: 'Standalone', virtual_cidr: null });
        await addNodes([a], extra.network_id);
        await request('DELETE', `/networks/${extra.network_id}`, undefined, 204);
        await delay(6500);
        await stop(web); web = startWeb(); await waitFor(async () => (await fetch(`${base}/api_meta.js`)).ok, 'Web restart with direct configs'); await login();
        await waitFor(async () => (await members()).find(m => m.device_id === a.id)?.online, 'direct device reconnected');
        await delay(6500);
        const db = new DatabaseSync(database);
        try {
            for (const [index, id] of directIds.entries()) {
                const stored = db.prepare('SELECT disabled FROM user_running_network_configs WHERE device_id = ? AND network_instance_id = ?').get(a.id, id);
                assert.ok(stored, 'direct row retained');
                assert.equal(stored.disabled, index);
            }
            assert.equal(db.prepare('SELECT COUNT(*) AS n FROM user_running_network_configs WHERE network_instance_id = ?').get(extra.network_id).n, 0);
        } finally { db.close(); }
        const state = await request('GET', `/machines/${a.id}/networks`);
        assert.ok(state.running_inst_ids.some(id => JSON.stringify(id) === JSON.stringify(protoUuid(directIds[0]))));
        assert.ok(!state.running_inst_ids.some(id => JSON.stringify(id) === JSON.stringify(protoUuid(directIds[1]))));
        for (const id of directIds) await request('DELETE', `/machines/${a.id}/networks/${id}`);
    });
    await step(['D03'], 'device alias set, clear and length validation', async () => {
        await request('PUT', `/machines/${a.id}/alias`, { alias: 'Audit Alias' }, 204);
        assert.ok((await request('GET', '/machines')).machines.some(m => m.alias === 'Audit Alias'));
        await request('PUT', `/machines/${a.id}/alias`, { alias: 'x'.repeat(65) }, 400);
        await request('PUT', `/machines/${a.id}/alias`, { alias: '' }, 204);
        await request('PUT', `/machines/${a.id}/alias`, { alias: 'Persisted Alias' }, 204);
    });
    await step(['M02'], 'member hostname and static address updates and rejections', async () => {
        await request('PATCH', memberPath(a), { hostname_override: 'member-a', virtual_ipv4: '10.88.99.101' });
        await waitFor(async () => (await runningInfo(a)).hostname === 'member-a', 'hostname update');
        await request('PATCH', memberPath(b), { virtual_ipv4: '10.88.99.101' }, 400);
        await request('PATCH', memberPath(b), { virtual_ipv4: '10.99.0.1' }, 400);
        await request('PATCH', memberPath(a), { hostname_override: '', virtual_ipv4: '' });
        await waitFor(async () => (await members()).find(m => m.device_id === a.id).runtime_virtual_ipv4?.split("/")[0] === a.vip, 'address restored');
        await eventualPing(a, b.vip);
        return ping(a, b.vip);
    });
    await step(['M04', 'M05'], 'advanced overrides and protected central identity', async () => {
        await setOverride(a, { ...baseOverride(a), mtu: 1300, instance_id: randomUUID(), network_name: 'hijack', network_secret: 'hijack', dhcp: true, virtual_ipv4: '1.2.3.4', peer_urls: ['tcp://127.0.0.1:9'] });
        await waitFor(async () => (await runtimeConfig(a)).mtu === 1300, 'MTU override');
        const actual = await runtimeConfig(a);
        assert.equal(actual.network_name, network.network_name); assert.equal(actual.instance_id, network.network_id); assert.equal(actual.virtual_ipv4, a.vip);
        assert.notEqual(actual.network_secret, 'hijack');
        await request('DELETE', `${memberPath(a)}/config`, undefined, 204);
        assert.deepEqual(await request('GET', `${memberPath(a)}/config`), {});
        await setOverride(a, baseOverride(a));
        return { identity: actual.network_name, mtu: actual.mtu };
    });
    await step(['M07'], 'concurrent member changes preserve both updates', async () => {
        await Promise.all([request('PATCH', memberPath(a), { hostname_override: 'concurrent-a' }), request('PATCH', memberPath(b), { hostname_override: 'concurrent-b' })]);
        const current = await members();
        assert.equal(current.find(m => m.device_id === a.id).hostname_override, 'concurrent-a');
        assert.equal(current.find(m => m.device_id === b.id).hostname_override, 'concurrent-b');
        return current;
    });
    await step(['R01', 'R02'], 'runtime details and device logger round trip', async () => {
        const routes = await waitFor(async () => { const v = await rpc(a, network.network_id, 'list_route'); return v.routes?.length ? v : false; }, 'route snapshot');
        const peers = await waitFor(async () => { const v = await rpc(a, network.network_id, 'list_peer'); return v.peer_infos?.length ? v : false; }, 'peer snapshot');
        const info = await waitFor(() => runningInfo(a), 'runtime snapshot after member update');
        assert.ok(routes.routes.length); assert.ok(peers.peer_infos.length); assert.ok(info.config.includes(network.network_name));
        const service = 'api.logger.LoggerRpcService';
        const before = await rpc(a, null, 'get_logger_config', service);
        await rpc(a, null, 'set_logger_config', service, { level: 2 });
        assert.equal((await rpc(a, null, 'get_logger_config', service)).level, 'WARNING');
        await rpc(a, null, 'set_logger_config', service, { level: before.level ?? 0 });
        return { peerCount: peers.peer_infos.length, routeCount: routes.routes.length };
    });
    await step(['L02'], 'ACL default deny blocks actual ICMP and default allow restores it', async () => {
        await policy({ default_action: 'deny', rules: [] }); ping(a, b.vip, false);
        await policy({ default_action: 'allow', rules: [] }); await eventualPing(a, b.vip); return ping(a, b.vip);
    });
    await step(['L03', 'L06'], 'ACL authenticated member selection and counters', async () => {
        const current = await members();
        const select = n => ({ type: 'member', member_id: current.find(m => m.device_id === n.id).member_id });
        await policy({ default_action: 'deny', rules: [rule('icmp-a-b', [select(a)], [select(b)], [{ protocol: 'icmp' }])] });
        await eventualPing(a, b.vip); ping(c, b.vip, false);
        const stats = await rpc(b, network.network_id, 'get_acl_stats', 'api.instance.AclManageRpcService');
        assert.ok(JSON.stringify(stats).includes('icmp-a-b'));
        await policy({ default_action: 'allow', rules: [] }); return stats;
    });
    await step(['L04'], 'TCP and UDP port policy with real socket traffic', async () => {
        const echo = join(output, 'echo.py');
        await writeFile(echo, `import socket,threading
def udp(port):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(("0.0.0.0",port))
 while True:
  d,a=s.recvfrom(1024);s.sendto(d,a)
def tcp(port):
 s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(("0.0.0.0",port));s.listen()
 while True:
  c,a=s.accept();c.sendall(c.recv(1024));c.close()
for port in [18080,18082]: threading.Thread(target=tcp,args=(port,),daemon=True).start()
for port in [18081,18082,18083]: threading.Thread(target=udp,args=(port,),daemon=True).start()
threading.Event().wait()
`);
        await dockerProcess('echo-b', ['ip', 'netns', 'exec', b.ns, 'python3', echo]);
        const probe = (proto, port) => ns(a, ['python3', '-c', `import socket;s=socket.socket(socket.AF_INET,socket.${proto === 'tcp' ? 'SOCK_STREAM' : 'SOCK_DGRAM'});s.settimeout(2);s.connect(('${b.vip}',${port}));s.send(b'audit');assert s.recv(1024)==b'audit'`], { allowFailure: true, timeout: 5000 }).status === 0;
        await policy({ default_action: 'allow', rules: [] });
        for (const port of [18080, 18082]) assert.ok(probe('tcp', port));
        for (const port of [18081, 18082, 18083]) assert.ok(probe('udp', port));
        await policy({ default_action: 'deny', rules: [rule('tcp-only', [{ type: 'all' }], [{ type: 'all' }], [{ protocol: 'tcp', ports: ['18080'], stateful: true }])] });
        assert.ok(probe('tcp', 18080)); assert.equal(probe('tcp', 18082), false); assert.equal(probe('udp', 18081), false);
        await policy({ default_action: 'deny', rules: [rule('udp-range', [{ type: 'all' }], [{ type: 'all' }], [{ protocol: 'udp', ports: ['18081-18082'] }])] });
        assert.ok(probe('udp', 18081)); assert.ok(probe('udp', 18082));
        assert.equal(probe('udp', 18083), false); assert.equal(probe('tcp', 18080), false);
        await policy({ default_action: 'allow', rules: [] });
    });
    await step(['M03', 'L05'], 'proxy CIDR advertisement and real subnet ICMP under ACL', async () => {
        ns(b, ['ip', 'addr', 'add', '198.18.240.1/24', 'dev', 'lo']);
        await request('PATCH', memberPath(b), { proxy_cidrs: ['198.18.240.0/24'] });
        await waitFor(async () => JSON.stringify(await rpc(a, network.network_id, 'list_route')).includes('198.18.240.0/24'), 'proxy route advertised');
        await eventualPing(a, '198.18.240.1');
        const current = await members(); const bid = current.find(m => m.device_id === b.id).member_id;
        await policy({ default_action: 'deny', rules: [rule('proxy-ping', [{ type: 'all' }], [{ type: 'subnet', member_id: bid, cidrs: ['198.18.240.0/24'] }], [{ protocol: 'icmp' }])] });
        await eventualPing(a, '198.18.240.1'); ping(a, b.vip, false);
        await policy({ default_action: 'allow', rules: [] });
        return rpc(a, network.network_id, 'list_route');
    });
    await step(['REG-PROXY'], 'temporary member mapped proxy routes are granted through PATCH and PUT', async () => {
        ns(c, ['ip', 'addr', 'add', '198.18.241.1/24', 'dev', 'lo']);
        for (const [method, subnet] of [['PATCH', 242], ['PUT', 243]]) {
            // Configure each fresh credential while its proxy is offline. Live
            // grant updates have a separate preexisting Core route-cache race.
            await stop(c.process);
            await request('DELETE', memberPath(c), undefined, 204);
            await request('POST', `/networks/${network.network_id}/members`, { device_ids: [c.id], temporary: true, ttl_seconds: 600 }, 204);
            const proxy_cidrs = [`198.18.241.0/24->198.18.${subnet}.0/24`];
            await setOverride(c, baseOverride(c));
            if (method === 'PATCH') await request('PATCH', memberPath(c), { proxy_cidrs });
            else await setOverride(c, { ...baseOverride(c), proxy_cidrs });
            for (const permanent of [a, b]) await waitFor(async () => (await runtimeConfig(permanent)).managed_credentials?.some(grant => grant.allowed_proxy_cidrs?.includes(`198.18.${subnet}.0/24`)), `${method} mapped CIDR grant`);
            await startNode(c);
            await waitFor(async () => JSON.stringify(await rpc(a, network.network_id, 'list_route')).includes(`198.18.${subnet}.0/24`), `${method} mapped proxy route`);
            await eventualPing(a, `198.18.${subnet}.1`);
        }
        await request('DELETE', memberPath(c), undefined, 204);
        await addNodes([c]); await setOverride(c, baseOverride(c));
    });
    await step(['REG-SUBNET'], 'changing the subnet reallocates automatic addresses without member edits', async () => {
        await updateNetwork({ virtual_cidr: '10.89.98.0/24' });
        await waitFor(async () => (await members()).every(m => m.runtime_virtual_ipv4?.startsWith('10.89.98.')), 'automatic subnet migration');
        const migrated = await members();
        assert.ok(migrated.every(m => m.virtual_ipv4 === null && m.allocated_ipv4?.startsWith('10.89.98.')));
        await eventualPing(a, migrated.find(m => m.device_id === b.id).allocated_ipv4);
        await updateNetwork({ virtual_cidr: '10.88.99.0/24' });
        await waitFor(async () => (await members()).every(m => m.runtime_virtual_ipv4?.startsWith('10.88.99.')), 'subnet restored');
        for (const n of [a, b, c]) n.vip = (await members()).find(m => m.device_id === n.id).runtime_virtual_ipv4.split('/')[0];
    });
    await step(['N05', 'N06'], 'network identity, secret and secure-mode updates converge', async () => {
        await updateNetwork({ display_name: 'Renamed audit', network_name: `${username}-renamed` }, { network_secret: 'audit-rotated-secret' });
        await waitFor(async () => (await runtimeConfig(b)).network_name === network.network_name && (await runtimeConfig(b)).network_secret === 'audit-rotated-secret', 'identity rotated');
        await eventualPing(a, b.vip);
        await updateNetwork({ secure_mode: false });
        await waitFor(async () => !(await runtimeConfig(b)).secure_mode?.enabled, 'secure disabled'); await eventualPing(a, b.vip);
        await updateNetwork({ secure_mode: true });
        await waitFor(async () => (await runtimeConfig(b)).secure_mode?.enabled, 'secure restored'); await eventualPing(a, b.vip);
    });
    await step(['N02', 'N03', 'N04', 'N07'], 'Gateway to Manual, PublicServer, Standalone and back', async () => {
        await updateNetwork({ networking_method: 'Manual', peer_urls: [`tcp://${a.ip}:11010`] }); await eventualPing(b, a.vip);
        assert.equal((await runtimeConfig(b)).peer_urls[0], `tcp://${a.ip}:11010`);
        await updateNetwork({ networking_method: 'PublicServer', public_server_url: `tcp://${a.ip}:11010` }); await eventualPing(b, a.vip);
        await waitFor(async () => (await runtimeConfig(b)).peer_urls?.includes(`tcp://${a.ip}:11010`), 'public server applied');
        await updateNetwork({ networking_method: 'Standalone', peer_urls: [] });
        await waitFor(async () => !(await runtimeConfig(b)).peer_urls?.length, 'standalone applied');
        assert.deepEqual((await runtimeConfig(b)).peer_urls ?? [], []);
        await updateNetwork({ networking_method: 'Gateway', peer_urls: ['tcp://invalid:9'] });
        await waitFor(async () => (await runtimeConfig(b)).peer_urls.includes(peerUrl), 'Gateway restored'); await eventualPing(a, b.vip);
    });
    await step(['N10'], 'one device in two networks retains the other on deletion', async () => {
        const second = await createNetwork('second', { networking_method: 'Standalone', virtual_cidr: '10.89.99.0/24' });
        await addNodes([a], second.network_id);
        let state = await request('GET', `/machines/${a.id}/networks`); assert.equal(state.running_inst_ids.length, 2);
        await request('DELETE', `/networks/${second.network_id}`, undefined, 204);
        await waitFor(async () => (await request('GET', `/machines/${a.id}/networks`)).running_inst_ids.length === 1, 'secondary instance gone');
        return runtimeConfig(a);
    });
    await step(['R03', 'R04'], 'all-DHCP network obtains distinct addresses and retains survivor address', async () => {
        await updateNetwork({ virtual_cidr: null });
        const current = await waitFor(async () => { const m = await members(); return m.every(x => x.runtime_virtual_ipv4) && new Set(m.map(x => x.runtime_virtual_ipv4)).size === 3 && m.every(x => x.runtime_virtual_ipv4.startsWith('10.126.126.')) ? m : false; }, 'distinct DHCP addresses', 60000);
        const aa = current.find(m => m.device_id === a.id).runtime_virtual_ipv4;
        const bb = current.find(m => m.device_id === b.id).runtime_virtual_ipv4.split('/')[0];
        await eventualPing(a, bb);
        await stop(b.process); await stop(c.process); await delay(16000);
        assert.equal((await members()).find(m => m.device_id === a.id).runtime_virtual_ipv4, aa);
        await startNode(b); await startNode(c);
        await updateNetwork({ virtual_cidr: '10.88.99.0/24' });
        await waitFor(async () => (await members()).every(m => m.runtime_virtual_ipv4?.startsWith('10.88.99.')), 'static addresses restored');
        for (const n of [a, b, c]) n.vip = (await members()).find(m => m.device_id === n.id).runtime_virtual_ipv4.split('/')[0];
        return current;
    });
    await step(['P01', 'P02', 'D04', 'M06'], 'offline update, Web restart and Core reconnect use latest intent', async () => {
        await stop(b.process);
        await request('PATCH', memberPath(b), { hostname_override: 'offline-latest' });
        await stop(web); web = startWeb(); await waitFor(async () => (await fetch(`${base}/api_meta.js`)).ok, 'Web restart'); await login();
        await startNode(b);
        await waitFor(async () => (await runningInfo(b)).hostname === 'offline-latest', 'offline desired config replay');
        await eventualPing(a, b.vip);
        assert.ok((await request('GET', '/machines')).machines.some(m => m.alias === 'Persisted Alias'));
        return { members: await members(), configFiles: docker(['ls', b.config]) };
    });
    await step(['W01', 'W03'], 'real native WireGuard handshake and ping to managed member', async () => {
        const privateKey = docker(['wg', 'genkey']);
        a.portal = { enabled: true, wireguard_listen: '0.0.0.0:15820', wireguard_private_key: privateKey, clients: [{ name: 'audit-wg', virtual_ip: '10.88.99.210/24', groups: [] }] };
        await setOverride(a, { ...baseOverride(a), vpn_portal_config: a.portal });
        const portal = await waitFor(async () => { const p = await rpc(a, network.network_id, 'get_vpn_portal_info', 'api.instance.VpnPortalRpcService'); return p.vpn_portal_info?.clients?.[0]?.client_config ? p.vpn_portal_info : false; }, 'WireGuard portal');
        const config = portal.clients[0].client_config.replace(/^Endpoint\s*=.*$/m, `Endpoint = ${a.ip}:15820`);
        await writeFile(join(output, 'wg-client.conf'), config);
        const stripped = config.split('\n').filter(line => !/^\s*(Address|DNS|MTU|Table|PreUp|PostUp|PreDown|PostDown)\s*=/.test(line)).join('\n');
        await writeFile(join(output, 'wg-client-stripped.conf'), stripped);
        ns(wg, ['ip', 'link', 'add', 'wgaudit', 'type', 'wireguard']);
        ns(wg, ['wg', 'setconf', 'wgaudit', join(output, 'wg-client-stripped.conf')]);
        ns(wg, ['ip', 'addr', 'add', '10.88.99.210/24', 'dev', 'wgaudit']); ns(wg, ['ip', 'link', 'set', 'wgaudit', 'up']);
        await eventualPing(wg, b.vip);
        const handshake = ns(wg, ['wg', 'show', 'wgaudit', 'latest-handshakes']); assert.ok(!handshake.endsWith('\t0'));
        return { handshake, ping: ping(wg, b.vip) };
    });
    await step(['W01', 'W05'], 'WireGuard disable preserves config, re-enable and restart recover', async () => {
        assert.ok(a.portal);
        await setOverride(a, { ...baseOverride(a), vpn_portal_config: { ...a.portal, enabled: false } });
        await delay(3000); ping(wg, b.vip, false);
        const stored = await request('GET', `${memberPath(a)}/config`); assert.equal(stored.vpn_portal_config.wireguard_private_key, a.portal.wireguard_private_key); assert.equal(stored.vpn_portal_config.clients.length, 1);
        await setOverride(a, { ...baseOverride(a), vpn_portal_config: a.portal }); await eventualPing(wg, b.vip);
        await stop(a.process); await startNode(a); await eventualPing(wg, b.vip);
        return { clientsRetained: stored.vpn_portal_config.clients.length };
    });
    await step(['W02', 'W05'], 'removed WireGuard client loses access', async () => {
        assert.ok(a.portal);
        await eventualPing(wg, b.vip);
        await setOverride(a, { ...baseOverride(a), vpn_portal_config: { ...a.portal, clients: [] } });
        await delay(3000); ping(wg, b.vip, false);
    });
    await step(['R06'], 'Gateway relay-data off blocks forced relay; on restores traffic', async () => {
        for (const n of [a, b]) await setOverride(n, { ...baseOverride(n), disable_p2p: true });
        await eventualPing(a, b.vip);
        await stop(web); web = startWeb(false); await waitFor(async () => (await fetch(`${base}/api_meta.js`)).ok, 'Web relay off'); await login();
        await waitFor(async () => (await members()).filter(m => [a.id, b.id].includes(m.device_id)).every(m => m.running), 'nodes reconnected');
        await delay(3000); ping(a, b.vip, false);
        await stop(web); web = startWeb(true); await waitFor(async () => (await fetch(`${base}/api_meta.js`)).ok, 'Web relay on'); await login(); await eventualPing(a, b.vip);
    });
    await step(['D05', 'D06'], 'device ban rejects reconnect, unban reenrolls without old memberships', async () => {
        await waitFor(async () => (await members()).some(m => m.device_id === c.id && m.online && m.running), 'member online before ban');
        await waitFor(async () => ns(c, ['ip', 'link', 'show', 'dev', 'etc'], { allowFailure: true }).status === 0, 'member TUN before ban');
        await request('DELETE', `/machines/${c.id}?block=true`, undefined, 204);
        assert.notEqual(ns(c, ['ip', 'link', 'show', 'dev', 'etc'], { allowFailure: true }).status, 0, 'deleted device TUN is gone before DELETE returns');
        await waitFor(async () => (await request('GET', '/blocked-devices')).blocked.some(d => d.id === c.id && d.attempt_count > 0), 'blocked reconnect attempt', 45000);
        assert.ok(!(await members()).some(m => m.device_id === c.id));
        await request('DELETE', `/blocked-devices/${c.id}`, undefined, 204);
        await waitFor(async () => (await request('GET', '/machines')).machines.some(m => m.info?.hostname === 'audit-c' && m.online), 'unban reenroll');
        assert.ok(!(await members()).some(m => m.device_id === c.id));
        await stop(c.process);
        await request('DELETE', `/machines/${c.id}`, undefined, 204);
        await startNode(c);
    });
    await step(['N08'], 'delete final network removes online and offline Core configurations', async () => {
        await stop(b.process);
        await request('DELETE', `/networks/${network.network_id}`, undefined, 204);
        await waitFor(async () => (await request('GET', `/machines/${a.id}/networks`)).running_inst_ids.length === 0, 'online instance deletion');
        await stop(web); web = startWeb(); await waitFor(async () => (await fetch(`${base}/api_meta.js`)).ok, 'Web restart after delete'); await login(); await startNode(b);
        await waitFor(async () => (await request('GET', `/machines/${b.id}/networks`)).running_inst_ids.length === 0, 'offline instance deletion');
        assert.deepEqual((await request('GET', '/networks')).networks, []);
        assert.ok(!docker(['ls', b.config]).includes(network.network_id));
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
