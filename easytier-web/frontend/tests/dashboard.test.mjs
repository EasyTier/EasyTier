import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { spawn } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';

const base = process.env.WEB_TEST_URL || 'http://127.0.0.1:5198';
const screenshotDir = process.env.WEB_SCREENSHOT_DIR;
let browser;
let server;

before(async () => {
    if (!process.env.WEB_TEST_URL) {
        server = spawn(process.execPath, ['node_modules/vite/bin/vite.js', 'preview', '--host', '127.0.0.1', '--port', '5198', '--strictPort'], { stdio: 'pipe' });
        for (let i = 0; i < 100; i++) {
            if (server.exitCode !== null) throw new Error('Vite exited before starting');
            if (await fetch(base).then(r => r.ok).catch(() => false)) break;
            await delay(100);
        }
    }
    browser = await chromium.launch({ headless: true });
    if (screenshotDir) await mkdir(screenshotDir, { recursive: true });
});

after(async () => {
    await browser?.close();
    server?.kill();
});

const uuid = n => ({ part1: 0, part2: 0, part3: 0, part4: n });
const id = n => `00000000-0000-0000-0000-${n.toString(16).padStart(12, '0')}`;

function fixture() {
    const machines = ['Amsterdam gateway', 'Build server', 'Office workstation', 'Storage node', 'Travel laptop', 'Windows desktop'].map((hostname, i) => ({
        client_url: `tcp://192.0.2.${i + 10}:11010`,
        info: { hostname, machine_id: uuid(i + 1), easytier_version: '2.4.5', report_time: '2026-09-13 12:00:00', running_network_instances: i === 0 ? [uuid(100)] : [] },
        location: { country: 'Netherlands', region: '', city: 'Amsterdam' },
        networks: [],
    }));
    const networks = ['Engineering', 'Home lab', 'Office network'].map((display_name, i) => ({
        network_id: `network-${i}`, display_name, network_name: `team-${i}`, networking_method: i === 0 ? 'Gateway' : 'Manual',
        online_member_count: 1, member_count: 2, network_secret: 'test-secret', peer_urls: i === 0 ? [] : ['tcp://192.0.2.1:11010'],
    }));
    const members = [{ member_id: id(101), device_id: id(1), hostname: 'Amsterdam gateway', hostname_override: null, virtual_ipv4: '10.126.126.1', online: true, running: true, version: '2.4.5', error_msg: null, runtime_virtual_ipv4: '10.126.126.1' }];
    return { machines, networks, members, memberConfig: {}, aclPolicy: { default_action: 'allow', rules: [] }, credentials: [], temporaryPeers: [], nodeRoutes: [], nodePeers: [], nodeAclStats: [], loggerConfig: { level: 'INFO' }, writes: [], requests: [], failures: new Set(), gatewayDelay: 0, gatewayEnabled: true };
}

async function open(t, route = '/h', options = {}, configure = () => {}) {
    const state = fixture();
    configure(state);
    const context = await browser.newContext({ viewport: { width: 1440, height: 960 }, ...options });
    t.after(() => context.close());
    await context.addInitScript(() => localStorage.setItem('lang', 'en'));
    if (state.noRandomUUID) {
        await context.addInitScript(() => {
            // Remote HTTP exposes getRandomValues but not randomUUID.
            Object.defineProperty(crypto, 'randomUUID', { value: undefined });
            const getRandomValues = crypto.getRandomValues.bind(crypto);
            window.secureRandomCalls = 0;
            crypto.getRandomValues = values => {
                window.secureRandomCalls++;
                return getRandomValues(values);
            };
        });
    }
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    t.after(() => assert.deepEqual(errors, [], 'no uncaught browser errors'));
    await page.route('**/api_meta.js', route => route.fulfill({
        contentType: 'text/javascript',
        body: `window.apiMeta = ${JSON.stringify({ api_host: state.apiHost ?? '' })};`,
    }));
    await page.route('**/api/v1/**', async route => {
        const request = route.request();
        const path = new URL(request.url()).pathname.replace('/api/v1', '');
        const method = request.method();
        const payload = request.postDataJSON();
        state.requests.push({ path, method });
        if (method !== 'GET') state.writes.push({ path, method, payload });
        if (state.failures.has(path)) return route.fulfill({ status: 503, json: { message: 'Test unavailable' } });
        let result = {};
        if (path === '/summary') result = { device_count: state.machines.length };
        else if (path === '/console-info') result = { username: 'test-user', config_server_protocol: 'udp', config_server_port: 22020, webhook_auth: state.externalConsole ?? false };
        else if (path === '/machines') result = { machines: state.machines };
        else if (path === '/networks/gateway-info') {
            await delay(state.gatewayDelay);
            result = { enabled: state.gatewayEnabled, peer_url: 'tcp://192.0.2.1:11010', relay_data: true };
        } else if (path === '/networks') {
            if (method === 'POST') {
                result = { ...payload.settings, network_id: `created-${state.networks.length}`, network_secret: 'new-secret', member_count: 0, online_member_count: 0 };
                state.networks.push(result);
            } else result = { networks: state.networks };
        } else if (/^\/networks\/[^/]+$/.test(path)) {
            const network = state.networks.find(n => n.network_id === path.split('/')[2]);
            if (method === 'PATCH') Object.assign(network, payload.settings, payload.network_secret ? { network_secret: payload.network_secret } : {});
            if (method === 'DELETE') state.networks = state.networks.filter(n => n !== network);
            result = network ?? {};
        } else if (path.endsWith('/acl-policy')) {
            if (method === 'PUT') state.aclPolicy = payload;
            result = { policy: state.aclPolicy };
        } else if (/^\/networks\/[^/]+\/members$/.test(path)) {
            if (method === 'POST') payload.device_ids.forEach(device_id => state.members.push({ device_id, hostname: 'Added device', online: true }));
            result = { members: state.members, temporary_peers: state.temporaryPeers };
        } else if (/^\/networks\/[^/]+\/members\/[^/]+\/config$/.test(path)) {
            if (method === 'PUT') state.memberConfig = payload.config;
            result = method === 'GET' ? state.memberConfig : state.members[0];
        } else if (/^\/networks\/[^/]+\/members\//.test(path)) {
            const member = state.members.find(m => m.device_id === path.split('/').at(-1));
            if (method === 'PATCH') Object.assign(member, payload);
            if (method === 'DELETE') state.members = state.members.filter(m => m !== member);
            result = member ?? {};
        } else if (/^\/networks\/[^/]+\/credentials$/.test(path)) {
            result = { credentials: state.credentials };
        } else if (path.endsWith('/proxy-rpc')) {
            if (payload.method_name === 'list_route') result = { routes: state.nodeRoutes };
            else if (payload.method_name === 'list_peer') result = { peer_infos: state.nodePeers };
            else if (payload.method_name === 'get_acl_stats') result = { acl_stats: { rules: state.nodeAclStats } };
            else if (payload.method_name === 'get_logger_config') result = state.loggerConfig;
            else if (payload.method_name === 'set_logger_config') state.loggerConfig = { level: ['DISABLED', 'ERROR', 'WARNING', 'INFO', 'DEBUG', 'TRACE'][payload.payload.level] };
            else if (payload.method_name === 'show_node_info') result = { node_info: { config: '[instance]\nname = "Engineering"' } };
        } else if (/\/machines\/[^/]+\/networks$/.test(path)) result = { running_inst_ids: [uuid(100)], disabled_inst_ids: [] };
        else if (path.endsWith('/networks/metas')) result = { metas: { [id(100)]: { network_name: 'Engineering', config_permission: 7 } } };
        else if (path.includes('/networks/info/')) result = { info: { map: { [id(100)]: { error_msg: 'Test device is reconnecting' } } } };
        else if (path.includes('/networks/config/')) result = { instance_id: id(100), network_name: 'Engineering', hostname: 'Amsterdam gateway', networking_method: 'Standalone' };
        await route.fulfill({ json: result });
    });
    await page.goto(`${base}/#${route}`);
    await page.locator('.console-page').waitFor();
    return { page, state, context };
}

async function refresh(page) {
    await page.getByRole('button', { name: 'Refresh', exact: true }).click();
}

test('overview uses real counts and recovers from partial refresh failures', async t => {
    const { page, state } = await open(t);
    await page.waitForFunction(() => document.querySelectorAll('.summary-value')[2]?.textContent.trim() === '3');
    assert.deepEqual(await page.locator('.summary-value').allTextContents().then(values => values.map(s => s.trim())), ['6', '0', '3', '1']);
    state.machines[0].online = true;
    await refresh(page);
    await page.waitForFunction(() => document.querySelectorAll('.summary-value')[1]?.textContent.trim() === '1');
    assert.equal(await page.locator('.overview-columns section').first().locator('.preview-row').count(), 5);
    state.failures.add('/networks');
    state.machines.pop();
    await refresh(page);
    await page.getByText('Unable to refresh data.', { exact: false }).waitFor();
    assert.equal((await page.locator('.summary-value').nth(2).textContent()).trim(), '3');
    await page.waitForFunction(() => document.querySelector('.summary-value')?.textContent.trim() === '5');
    state.failures.clear();
    state.networks.pop();
    await page.waitForFunction(() => document.querySelectorAll('.summary-value')[2]?.textContent.trim() === '2');
    assert.equal(await page.getByText('Unable to refresh data.', { exact: false }).count(), 0);
});

test('enrollment command uses the console info response', async t => {
    const { page } = await open(t);
    await page.getByRole('button', { name: 'Device Enrollment', exact: true }).click();
    await page.getByText('easytier-core --config-server udp://127.0.0.1:22020/test-user').waitFor();
});

for (const [apiHost, hostname] of [
    ['https://api.example.test:8443/', 'api.example.test'],
    ['http://[2001:db8::1]:8848/', '[2001:db8::1]'],
    ['.', '127.0.0.1'],
]) {
    test(`enrollment command uses the configured API hostname for ${apiHost}`, async t => {
        const { page } = await open(t, '/h', {}, state => { state.apiHost = apiHost; });
        await page.getByRole('button', { name: 'Device Enrollment', exact: true }).click();
        await page.getByText(`easytier-core --config-server udp://${hostname}:22020/test-user`).waitFor();
    });
}

test('device search, sort, expansion and routed drawer survive reload and history', async t => {
    const { page } = await open(t, '/h/deviceList');
    const table = page.locator('.desktop-list');
    await table.getByRole('button', { name: 'Amsterdam gateway', exact: true }).waitFor();
    await page.getByRole('textbox', { name: 'Search name or address' }).fill('192.0.2.10');
    assert.equal(await table.locator('tbody > tr').count(), 1);
    await page.getByRole('textbox', { name: 'Search name or address' }).fill('');
    // 无静态 sortField：离线排最后的预排序是默认视图；点击 hostname 列头一次升序、再点一次降序
    await page.getByRole('columnheader', { name: 'Hostname' }).click(); // 升序
    await page.getByRole('columnheader', { name: 'Hostname' }).click(); // 降序
    assert.match(await table.locator('tbody > tr').first().textContent(), /Windows desktop/);
    await table.locator('tbody > tr').first().getByRole('button').first().click();
    await table.locator('.device-details').waitFor();
    await table.getByRole('button', { name: 'Amsterdam gateway', exact: true }).click();
    await page.locator('.console-device-drawer').waitFor();
    assert.ok(page.url().endsWith(`/device/${id(1)}/${id(100)}`));
    await page.reload();
    await page.locator('.console-device-drawer h2').filter({ hasText: 'Amsterdam gateway' }).waitFor();
    await page.keyboard.press('Escape');
    await page.waitForURL('**/#/h/deviceList');
    await page.goBack();
    await page.locator('.console-device-drawer').waitFor();
});

test('device list card view toggle renders cards and persists across reload', async t => {
    const { page } = await open(t, '/h/deviceList');
    const table = page.locator('.desktop-list');
    await table.getByRole('button', { name: 'Amsterdam gateway', exact: true }).waitFor();
    assert.equal(await page.locator('.device-card').count(), 0);
    await page.locator('.view-toggle .pi-th-large').click();
    await page.locator('.device-card').first().waitFor();
    assert.equal(await page.locator('.device-card').count(), 6);
    assert.equal(await table.count(), 0);
    await page.reload();
    await page.locator('.device-card').first().waitFor();
    assert.equal(await page.locator('.device-card').count(), 6);
    await page.locator('.view-toggle .pi-table').click();
    await table.getByRole('button', { name: 'Amsterdam gateway', exact: true }).waitFor();
    assert.equal(await table.locator('tbody > tr').count(), 6);
});

test('network creation retains gateway and advanced standalone modes', async t => {
    const { page, state } = await open(t, '/h/networks');
    await page.locator('.desktop-list').getByRole('button', { name: 'Engineering', exact: true }).waitFor();
    await page.getByRole('textbox', { name: 'Search networks' }).fill('no-match');
    await page.getByText('No matching results', { exact: true }).waitFor();
    await page.getByRole('button', { name: 'Clear search' }).click();
    await page.getByRole('button', { name: 'Create Network', exact: true }).click();
    await page.getByRole('dialog').getByText('Secure Mode', { exact: true }).waitFor();
    await page.getByRole('dialog').locator('label[for="create-secure-mode"] + .pi-question-circle').hover();
    await page.getByText('Noise encrypted handshakes with identity verification; enables temporary credentials. Member instances restart on change').waitFor();
    await page.locator('#network-display-name').fill('Research');
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm', exact: true }).click();
    await page.waitForURL('**/networks/created-*');
    assert.equal(state.writes.find(w => w.path === '/networks')?.payload.settings.networking_method, 'Gateway');
    await page.getByRole('button', { name: 'Back to networks' }).click();
    await page.getByRole('button', { name: 'Create Network', exact: true }).click();
    await page.getByRole('dialog').getByRole('button', { name: /Advanced/ }).click();
    await page.getByRole('dialog').locator('.p-button-danger:visible').click();
    await page.locator('#network-display-name').fill('Isolated lab');
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm', exact: true }).click();
    await page.waitForURL('**/networks/created-*');
    assert.equal(state.writes.filter(w => w.path === '/networks').at(-1).payload.settings.networking_method, 'Standalone');
});

test('PublicServer settings retain discovery mode when renamed or edited to the gateway URL', async t => {
    const { page, state } = await open(t, '/h/networks/network-0', {}, state => {
        Object.assign(state.networks[0], {
            networking_method: 'PublicServer',
            public_server_url: 'tcp://public.example:11010',
        });
    });
    await page.getByRole('tab', { name: 'Settings', exact: true }).click();
    await page.locator('#settings-display-name').fill('Public network');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByRole('heading', { name: 'Public network', exact: true }).waitFor();
    let settings = state.writes.filter(w => w.method === 'PATCH').at(-1).payload.settings;
    assert.equal(settings.networking_method, 'PublicServer');
    assert.equal(settings.public_server_url, 'tcp://public.example:11010');
    assert.deepEqual(settings.peer_urls, []);

    await page.locator('#settings-initial-nodes .url-input-full input.grow').fill('192.0.2.1');
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await page.waitForResponse(response => response.request().method() === 'GET' && response.url().endsWith('/networks/network-0'));
    settings = state.writes.filter(w => w.method === 'PATCH').at(-1).payload.settings;
    assert.equal(settings.networking_method, 'PublicServer');
    assert.equal(settings.public_server_url, 'tcp://192.0.2.1:11010');
    assert.deepEqual(settings.peer_urls, []);
});

test('network tabs preserve gateway settings and unsaved input across polling', async t => {
    const { page, state } = await open(t, '/h/networks/network-0');
    await page.getByRole('tab', { name: 'Settings', exact: true }).click();
    await page.locator('#settings-display-name').fill('Engineering draft');
    const count = state.requests.filter(r => r.path === '/networks/network-0').length;
    for (let i = 0; i < 50 && state.requests.filter(r => r.path === '/networks/network-0').length <= count; i++) await delay(100);
    assert.ok(state.requests.filter(r => r.path === '/networks/network-0').length > count, 'polling continues');
    assert.equal(await page.locator('#settings-display-name').inputValue(), 'Engineering draft');
    await page.getByRole('tab', { name: 'Members', exact: true }).click();
    await page.locator('.desktop-list').getByText('Running', { exact: true }).waitFor();
    await page.getByRole('tab', { name: 'Settings', exact: true }).click();
    assert.equal(await page.locator('#settings-display-name').inputValue(), 'Engineering draft');
    await page.locator('#regenerate-secret').check();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByRole('heading', { name: 'Engineering draft' }).waitFor();
    const saved = state.writes.find(w => w.method === 'PATCH');
    assert.equal(saved.payload.settings.networking_method, 'Gateway');
    assert.match(saved.payload.network_secret, /^[0-9a-f-]{36}$/);
    await page.getByRole('button', { name: 'Delete Network', exact: true }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    assert.equal(state.writes.some(w => w.method === 'DELETE'), false);
    await page.getByRole('button', { name: 'Delete Network', exact: true }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Confirm', exact: true }).click();
    await page.waitForURL('**/#/h/networks');
    assert.equal(state.networks.length, 2);
});

test('ACL rules and network secrets use secure randomness without randomUUID', async t => {
    const { page, state } = await open(t, '/h/networks/network-0', {}, state => { state.noRandomUUID = true; });
    assert.equal(await page.evaluate(() => typeof crypto.randomUUID), 'undefined');
    await page.getByRole('tab', { name: 'Access Control', exact: true }).click();
    await page.getByRole('button', { name: 'Add Rule', exact: true }).click();
    const editor = page.getByRole('complementary').filter({ has: page.locator('#acl-rule-name') });
    await editor.locator('#acl-rule-name').fill('Allow ping');
    for (const select of ['Search and choose the members that initiate access', 'Search and choose target members or subnets']) {
        await editor.getByText(select, { exact: true }).click();
        await page.getByRole('option', { name: 'All members', exact: true }).click();
        await page.keyboard.press('Escape');
    }
    await editor.getByRole('checkbox', { name: 'ICMP', exact: true }).check();
    await editor.getByRole('button', { name: 'Save Rule', exact: true }).click();
    await editor.waitFor({ state: 'detached' });
    await page.getByRole('button', { name: 'Save Policy', exact: true }).click();
    await page.getByText('Access policy saved', { exact: true }).waitFor();
    assert.match(state.aclPolicy.rules[0].id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

    await page.getByRole('tab', { name: 'Settings', exact: true }).click();
    const randomCalls = await page.evaluate(() => window.secureRandomCalls);
    await page.locator('#regenerate-secret').check();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByText('Config Saved', { exact: true }).waitFor();
    const saved = state.writes.find(write => write.method === 'PATCH');
    assert.match(saved.payload.network_secret, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    assert.ok(await page.evaluate(() => window.secureRandomCalls) > randomCalls);
});

test('a late member configuration response cannot overwrite the next member', async t => {
    const { page, state } = await open(t, '/h/networks/network-0', {}, state => {
        state.members.push({ ...state.members[0], member_id: id(102), device_id: id(2), hostname: 'Build server' });
    });
    let releaseFirst;
    const firstResponse = new Promise(resolve => { releaseFirst = resolve; });
    t.after(() => releaseFirst());
    const firstPath = `/networks/network-0/members/${id(1)}/config`;
    await page.route('**/networks/network-0/members/*/config', async route => {
        if (route.request().method() !== 'GET') return route.fallback();
        const first = route.request().url().endsWith(firstPath);
        if (first) await firstResponse;
        await route.fulfill({ json: { hostname: first ? 'configuration-a' : 'configuration-b' } });
    });
    const firstRequested = page.waitForRequest(request => request.url().endsWith(firstPath));
    await page.getByRole('row').filter({ hasText: 'Amsterdam gateway' }).getByRole('button', { name: 'Edit Member' }).click();
    await firstRequested;
    await page.getByRole('dialog').getByRole('button', { name: 'Cancel', exact: true }).click();
    await page.getByRole('dialog').waitFor({ state: 'detached' });
    await page.getByRole('row').filter({ hasText: 'Build server' }).getByRole('button', { name: 'Edit Member' }).click();
    await page.getByRole('dialog').getByRole('tab', { name: 'Advanced Config' }).click();
    await page.getByRole('dialog').getByRole('button', { name: 'Advanced Settings', exact: true }).click();
    await page.locator('#hostname').waitFor();
    assert.equal(await page.locator('#hostname').inputValue(), 'configuration-b');
    const lateResponse = page.waitForResponse(response => response.url().endsWith(firstPath));
    releaseFirst();
    await (await lateResponse).finished();
    await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(await page.locator('#hostname').inputValue(), 'configuration-b');
    await page.getByRole('dialog').getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByRole('dialog').waitFor({ state: 'detached' });
    const saved = state.writes.find(write => write.method === 'PUT' && write.path.endsWith('/config'));
    assert.equal(saved.path, `/networks/network-0/members/${id(2)}/config`);
    assert.equal(saved.payload.config.hostname, 'configuration-b');
});

test('settings wait for gateway discovery before exposing the save action', async t => {
    const { page, state } = await open(t, '/h/networks/network-0', {}, state => { state.gatewayDelay = 1500; });
    await page.getByRole('tab', { name: 'Settings', exact: true }).click();
    assert.equal(await page.getByRole('button', { name: 'Save', exact: true }).count(), 0);
    await page.locator('#settings-display-name').waitFor();
    await page.getByRole('button', { name: 'Save', exact: true }).click();
    for (let i = 0; i < 50 && !state.writes.some(w => w.method === 'PATCH'); i++) await delay(100);
    assert.equal(state.writes.find(w => w.method === 'PATCH').payload.settings.networking_method, 'Gateway');
});

test('editing an automatic member address keeps automatic assignment', async t => {
    const { page, state } = await open(t, '/h/networks/network-0', {}, state => {
        state.networks[0].virtual_cidr = '10.126.0.0/16';
        Object.assign(state.members[0], { virtual_ipv4: null, allocated_ipv4: '10.126.126.7', runtime_virtual_ipv4: null, online: false, running: false });
    });
    await page.locator('.desktop-list').getByText('10.126.126.7/16', { exact: true }).waitFor();
    await page.getByRole('row').filter({ hasText: 'Amsterdam gateway' }).getByRole('button', { name: 'Edit Member' }).click();
    assert.equal(await page.locator('#edit-virtual-ipv4').inputValue(), '');
    await page.locator('#edit-hostname-override').fill('automatic-member');
    await page.getByRole('dialog').getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByRole('dialog').waitFor({ state: 'detached' });
    assert.equal(state.writes.find(write => write.method === 'PATCH').payload.virtual_ipv4, '');
});

test('member editing, adding and removal keep existing request semantics', async t => {
    const { page, state } = await open(t, '/h/networks/network-0');
    await page.getByRole('row').filter({ hasText: 'Amsterdam gateway' }).getByRole('button', { name: 'Edit Member' }).click();
    await page.locator('#edit-hostname-override').fill('gateway-west');
    await page.locator('#edit-virtual-ipv4').fill('10.126.126.20');
    await page.getByRole('dialog').getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByRole('row').filter({ hasText: 'gateway-west' }).waitFor();
    assert.equal(state.members[0].virtual_ipv4, '10.126.126.20');
    await page.getByRole('button', { name: 'Add Devices' }).click();
    await page.getByRole('dialog').getByRole('row').filter({ hasText: 'Build server' }).getByRole('checkbox').check();
    await page.getByRole('dialog').getByRole('button', { name: 'Confirm', exact: true }).click();
    await page.getByRole('row').filter({ hasText: 'Added device' }).waitFor();
    assert.deepEqual(state.writes.find(w => w.method === 'POST' && w.path.endsWith('/members')).payload.device_ids, [id(2)]);
    await page.getByRole('row').filter({ hasText: 'Added device' }).getByRole('button', { name: 'Remove Device' }).click();
    await page.getByRole('alertdialog').getByRole('button', { name: 'Confirm', exact: true }).click();
    await page.getByRole('row').filter({ hasText: 'Added device' }).waitFor({ state: 'detached' });
    assert.equal(state.members.length, 1);
});

test('central member WireGuard clients stay editable through the member configuration', async t => {
    const { page, state } = await open(t, '/h/networks/network-0', {}, state => {
        state.memberConfig = {
            proxy_cidrs: ['192.168.20.0/24'],
            vpn_portal_config: {
                enabled: true,
                wireguard_listen: '0.0.0.0:22022',
                wireguard_private_key: 'KioqKioqKioqKioqKioqKioqKioqKioqKioqKioqKio=',
                clients: [{ name: 'phone', virtual_ip: '10.126.126.2/24', groups: [] }],
            },
        };
    });
    const key = state.memberConfig.vpn_portal_config.wireguard_private_key;
    const edit = async () => {
        await page.getByRole('button', { name: 'Edit Member' }).click();
        await page.getByRole('dialog').getByRole('tab', { name: 'Advanced Config' }).click();
        await page.getByRole('dialog').getByRole('button', { name: 'Advanced Settings', exact: true }).click();
        await page.locator('#vpn_portal_client_name_0').waitFor();
    };
    await edit();
    await page.getByRole('dialog').getByRole('button', { name: 'Add device', exact: true }).click();
    await page.locator('#vpn_portal_client_virtual_ip_1').fill('10.126.126.3/24');
    const generatedName = await page.locator('#vpn_portal_client_name_1').inputValue();
    assert.match(generatedName, /^device-[a-f0-9]{8}$/);
    await page.getByRole('dialog').getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByRole('dialog').waitFor({ state: 'detached' });
    assert.equal(state.memberConfig.vpn_portal_config.clients.length, 2);
    assert.equal(state.memberConfig.vpn_portal_config.wireguard_private_key, key);
    assert.deepEqual(state.memberConfig.proxy_cidrs, ['192.168.20.0/24']);

    await edit();
    await page.getByRole('dialog').getByRole('button', { name: 'Delete device', exact: true }).first().click();
    await page.getByRole('dialog').getByRole('button', { name: 'Save', exact: true }).click();
    await page.getByRole('dialog').waitFor({ state: 'detached' });
    assert.deepEqual(state.memberConfig.vpn_portal_config.clients.map(client => client.name), [generatedName]);
    assert.equal(state.writes.filter(write => write.method === 'PUT' && write.path.endsWith('/config')).length, 2);
    assert.equal(state.writes.some(write => write.path.endsWith('/vpn-portal-clients') || write.payload?.method_name === 'patch_config'), false);
});

test('credentials tab and temporary devices render', async t => {
    const { page } = await open(t, '/h/networks/network-0', {}, state => {
        state.networks[0].secure_mode = true;
        const peers = [
            {
                peer_id: 42, credential_id: 'cred-1234567890abcdef', credential_expiry_unix: 1893456000,
                hostname: 'Visitor laptop', ipv4: '10.126.126.50', version: '2.4.5',
            },
            {
                peer_id: 99, credential_id: 'cred-1234567890abcdef', credential_expiry_unix: 1893456000,
                hostname: 'Visitor phone', ipv4: '10.126.126.51', version: '2.4.5',
            },
        ];
        state.credentials = [{
            credential_id: 'cred-1234567890abcdef', credential_secret: 'test-credential-secret',
            expiry_unix: 1893456000, reusable: true, online_peers: peers,
        }];
        state.temporaryPeers = peers;
    });
    await page.getByRole('tab', { name: 'Credentials', exact: true }).click();
    await page.getByRole('cell', { name: /cred-1234/ }).waitFor();
    await page.getByText('Visitor laptop').waitFor();
    await page.getByText('Visitor phone').waitFor();
    await page.getByRole('tab', { name: 'Members', exact: true }).click();
    await page.getByText('Temporary Devices').waitFor();
    await page.getByRole('cell', { name: /Visitor laptop/ }).waitFor();
    await page.getByRole('cell', { name: /Visitor phone/ }).waitFor();
});

test('PublicServer credential exports use the configured public server', async t => {
    const peer = 'tcp://public.example.test:11010';
    const { page } = await open(t, '/h/networks/network-0', {}, state => {
        Object.assign(state.networks[0], {
            secure_mode: true, networking_method: 'PublicServer', public_server_url: peer,
            peer_urls: [],
        });
        state.credentials = [{
            credential_id: 'cred-1234567890abcdef', credential_secret: 'test-credential-secret',
            expiry_unix: 1893456000, reusable: true, online_peers: [],
        }];
    });
    await page.getByRole('tab', { name: 'Credentials', exact: true }).click();
    await page.getByRole('button', { name: 'Show join command', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: 'Temporary device join command' });
    assert.equal(await dialog.locator('pre').textContent(),
        `easytier-core --network-name team-0 --secure-mode --credential test-credential-secret -p ${peer}`);
    await dialog.getByRole('button', { name: 'Config file', exact: true }).click();
    assert.equal(await dialog.locator('pre').textContent(), [
        '[network_identity]', 'network_name = "team-0"', '',
        '[[peer]]', `uri = "${peer}"`, '',
        '[secure_mode]', 'enabled = true', 'local_private_key = "test-credential-secret"',
    ].join('\n'));
});

test('node detail gives empty peers a clear home and keeps actions separate', async t => {
    const { page, state } = await open(t, `/h/networks/${id(100)}`, {}, state => { state.networks[0].network_id = id(100); });
    await page.getByRole('button', { name: 'Node Detail' }).click();
    const drawer = page.locator('.console-node-drawer');
    await drawer.getByText('No other nodes yet').waitFor();
    await page.waitForFunction(() => Math.abs(document.querySelector('.console-node-drawer').getBoundingClientRect().right - innerWidth) < 1);
    assert.equal(await drawer.getByRole('columnheader').count(), 0);
    assert.ok(await drawer.locator('.node-drawer-empty').evaluate(el => el.getBoundingClientRect().height < 60));
    assert.ok(await drawer.locator('.node-drawer-summary').evaluate(el => el.getBoundingClientRect().height < 60));
    assert.deepEqual(await drawer.locator('.node-drawer-metric strong').allTextContents().then(values => values.map(s => s.trim())), ['Running', '0', '0', '0']);
    assert.equal(await drawer.locator('.node-drawer-title').textContent(), 'Amsterdam gateway');
    assert.equal(await drawer.locator('.node-drawer-title').count(), 1);
    if (screenshotDir) await drawer.screenshot({ path: `${screenshotDir}/node-detail-empty.png`, animations: 'disabled' });
    await drawer.getByRole('tab', { name: 'Settings & actions' }).click();
    await drawer.getByText('Log Level', { exact: true }).waitFor();
    await drawer.getByRole('button', { name: 'Export Config' }).click();
    await page.getByText('[instance]', { exact: false }).waitFor();
    assert.ok(state.requests.some(r => r.path.endsWith('/proxy-rpc')));
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.reload();
    await page.getByRole('button', { name: 'Switch language' }).click();
    await page.getByRole('button', { name: '节点详情' }).click();
    await drawer.getByText('暂无其他节点').waitFor();
    await page.waitForFunction(() => Math.abs(document.querySelector('.console-node-drawer').getBoundingClientRect().right - innerWidth) < 1);
    if (screenshotDir) await drawer.screenshot({ path: `${screenshotDir}/node-detail-empty-cn-dark.png`, animations: 'disabled' });
});

test('logger levels decode protobuf responses, persist selections and translate labels', async t => {
    const labels = ['Disabled', 'Error', 'Warning', 'Info', 'Debug', 'Trace'];
    const { page, state } = await open(t, `/h/networks/${id(100)}`, {}, state => { state.networks[0].network_id = id(100); });
    const drawer = page.locator('.console-node-drawer');
    const select = drawer.getByRole('combobox');
    const openSettings = async () => {
        await page.getByRole('button', { name: 'Node Detail', exact: true }).click();
        await drawer.getByRole('tab', { name: 'Settings & actions', exact: true }).click();
    };
    // Disabled is omitted by protobuf JSON; named and numeric values are valid.
    for (const [level, label] of [[undefined, 'Disabled'], ...labels.map(label => [label.toUpperCase(), label]), [3, 'Info']]) {
        state.loggerConfig = level === undefined ? {} : { level };
        await openSettings();
        await select.getByText(label, { exact: true }).waitFor();
        await page.keyboard.press('Escape');
        await drawer.waitFor({ state: 'hidden' });
    }
    await openSettings();
    for (const [level, label] of labels.entries()) {
        await select.click();
        assert.deepEqual(await page.getByRole('option').allTextContents(), labels);
        await page.getByRole('option', { name: label, exact: true }).click();
        await page.waitForFunction(() => !document.querySelector('.console-node-drawer .p-select').classList.contains('p-disabled'));
        assert.equal(state.writes.filter(write => write.payload?.method_name === 'set_logger_config').at(-1).payload.payload.level, level);
        await select.getByText(label, { exact: true }).waitFor();
        await page.reload();
        await openSettings();
        await select.getByText(label, { exact: true }).waitFor();
    }
    await page.keyboard.press('Escape');
    await drawer.waitFor({ state: 'hidden' });
    await page.getByRole('button', { name: 'Switch language', exact: true }).click();
    await page.getByRole('button', { name: '节点详情', exact: true }).click();
    await drawer.getByRole('tab').nth(1).click();
    await select.getByText('跟踪', { exact: true }).waitFor();
    await select.click();
    assert.deepEqual(await page.getByRole('option').allTextContents(), ['禁用', '错误', '警告', '信息', '调试', '跟踪']);
});

test('node detail groups populated peers, routes, connections and ACL stats', async t => {
    const { page } = await open(t, `/h/networks/${id(100)}`, { viewport: { width: 390, height: 844 }, colorScheme: 'dark' }, state => {
        state.networks[0].network_id = id(100);
        state.nodeRoutes = [{ peer_id: 2, hostname: 'Build server', ipv4_addr: { address: { addr: 175005442 }, network_length: 24 }, cost: 1, path_latency: 8, proxy_cidrs: [], version: '2.4.5', next_hop_peer_id: 2 }];
        state.nodePeers = [{ peer_id: 2, conns: [{ conn_id: 'conn-1', tunnel: { tunnel_type: 'tcp', remote_addr: { url: 'tcp://192.0.2.11:11010' } }, stats: { latency_us: 8000, rx_bytes: 1024, tx_bytes: 2048 }, loss_rate: 0 }] }];
        state.nodeAclStats = [{ rule: { name: 'Allow build server' }, stat: { packet_count: 42, byte_count: 4096 } }];
    });
    await page.locator('.mobile-list').getByRole('button', { name: 'Node Detail' }).click();
    const drawer = page.locator('.console-node-drawer');
    await drawer.locator('.node-drawer-mobile-peer').getByText('Build server').waitFor();
    await page.waitForFunction(() => Math.abs(document.querySelector('.console-node-drawer').getBoundingClientRect().right - innerWidth) < 1);
    assert.deepEqual(await drawer.locator('.node-drawer-metric strong').allTextContents().then(values => values.map(s => s.trim())), ['Running', '1', '1', '1']);
    assert.equal(await drawer.getByRole('tab').count(), 2);
    const drawerWidth = await drawer.evaluate(el => ({ drawer: el.getBoundingClientRect().width, viewport: innerWidth }));
    assert.ok(drawerWidth.drawer <= drawerWidth.viewport + 1, JSON.stringify(drawerWidth));
    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    if (screenshotDir) await drawer.screenshot({ path: `${screenshotDir}/node-detail-populated-mobile-dark.png`, animations: 'disabled' });
    await page.setViewportSize({ width: 1024, height: 844 });
    await drawer.getByRole('cell', { name: 'Build server' }).waitFor();
    await drawer.locator('details').filter({ hasText: 'Routes' }).locator('summary').click();
    await drawer.getByText('10.110.95.2/24').first().waitFor();
    await drawer.locator('details').filter({ hasText: 'Connections' }).locator('summary').click();
    await drawer.locator('details').filter({ hasText: 'ACL Stats' }).locator('summary').click();
    await drawer.getByRole('cell', { name: 'Allow build server' }).waitFor();
});

test('empty and failed lists recover without presenting an empty result as success', async t => {
    const { page, state } = await open(t, '/h/deviceList');
    state.machines = [];
    await refresh(page);
    await page.getByRole('heading', { name: 'No devices yet' }).waitFor();
    state.failures.add('/machines');
    await page.reload();
    await page.getByRole('button', { name: 'Retry', exact: true }).waitFor();
    assert.equal(await page.getByRole('heading', { name: 'No devices yet' }).count(), 0);
    state.failures.clear();
    await page.getByRole('button', { name: 'Retry', exact: true }).click();
    await page.getByRole('heading', { name: 'No devices yet' }).waitFor();
});

test('responsive layouts, localization, dark mode and mobile drawer', async t => {
    const { page, state } = await open(t);
    const workspaceMenu = page.locator('.console-sidebar').getByRole('menu', { name: 'Navigation' });
    await workspaceMenu.focus();
    await page.keyboard.press('ArrowDown'); // Dashboard -> Device List
    await page.keyboard.press('Enter');
    await page.waitForURL('**/#/h/deviceList');
    await workspaceMenu.locator('[aria-current="page"]', { hasText: 'Device List' }).waitFor();
    assert.equal(await workspaceMenu.locator('[aria-current="page"]').textContent(), 'Device List');
    const networkMenu = page.locator('.console-sidebar').getByRole('menu', { name: 'Networks' });
    await networkMenu.focus();
    await page.keyboard.press('ArrowDown'); // Networks overview -> Engineering (first nav-child)
    await page.keyboard.press('Enter');
    await page.waitForURL('**/networks/network-0');
    await networkMenu.locator('[aria-current="page"]', { hasText: 'Engineering' }).waitFor();
    for (const colorScheme of ['light', 'dark']) {
        await page.emulateMedia({ colorScheme });
        for (const width of [1440, 1024, 390]) {
            await page.setViewportSize({ width, height: 960 });
            for (const language of ['en', 'cn']) {
                for (const [name, route] of [['overview', '/h'], ['devices', '/h/deviceList'], ['networks', '/h/networks'], ['members', '/h/networks/network-0']]) {
                    await page.goto(`${base}/#${route}`);
                    await page.locator('.console-page').waitFor();
                    if (await page.evaluate(() => localStorage.getItem('lang')) !== language) {
                        await page.getByRole('button', { name: /Switch language|切换语言/ }).click();
                    }
                    await page.locator('.p-skeleton').first().waitFor({ state: 'detached' });
                    assert.equal(await page.locator('.web-console').evaluate(el => getComputedStyle(el).backgroundColor), colorScheme === 'light' ? 'rgb(247, 248, 249)' : 'rgb(16, 23, 30)');
                    assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), `${name} ${width} ${colorScheme} must not overflow`);
                    if (screenshotDir) await page.screenshot({ path: `${screenshotDir}/${name}-${language}-${colorScheme}-${width}.png`, fullPage: true, animations: 'disabled' });
                }
            }
        }
    }
    state.machines[0].info.hostname = 'A-very-long-device-hostname-that-must-wrap-without-breaking-the-layout.example.internal';
    await page.setViewportSize({ width: 390, height: 960 });
    await page.goto(`${base}/#/h/deviceList`);
    await page.locator('.mobile-list .entity-link').first().click();
    await page.locator('.console-device-drawer').waitFor();
    await page.waitForFunction(() => Math.abs(document.querySelector('.console-device-drawer').getBoundingClientRect().left) < 1);
    assert.ok(await page.locator('.console-device-drawer').evaluate(el => el.getBoundingClientRect().width <= innerWidth));
    if (screenshotDir) await page.screenshot({ path: `${screenshotDir}/device-drawer-mobile.png`, animations: 'disabled' });
    await page.keyboard.press('Escape');
    await page.locator('.mobile-nav-toggle').click();
    await page.locator('.console-mobile-nav').getByRole('menu', { name: '导航' }).waitFor();
    await page.locator('.console-mobile-nav').getByRole('link', { name: '设备列表', exact: true }).click();
    await page.locator('.console-mobile-nav').waitFor({ state: 'detached' });
    await page.locator('.mobile-nav-toggle').click();
    await page.locator('.console-mobile-nav').getByRole('link').first().click();
    await page.locator('.console-mobile-nav').waitFor({ state: 'detached' });
});


test('external Console keeps the device dashboard without central requests or navigation', async t => {
    const { page, state } = await open(t, '/h', {}, state => {
        state.externalConsole = true;
        state.failures.add('/networks');
    });
    await page.getByText('Amsterdam gateway', { exact: true }).waitFor();
    await delay(2500);
    assert.equal(state.requests.some(request => request.path.startsWith('/networks')), false);
    assert.equal(await page.locator('a[href*="/networks"]').count(), 0);
    assert.equal(await page.locator('.p-message-warn').count(), 0);
});
