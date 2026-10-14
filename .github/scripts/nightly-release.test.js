const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { prepare, publish, releaseNotes } = require('./nightly-release.js');

const repository = { owner: 'EasyTier', repo: 'EasyTier' };
const core = { info() {} };
const notFound = () => Object.assign(new Error('Not found'), { status: 404 });

function fixture() {
  const calls = [];
  const state = {
    release: null,
    ancestry: 'ahead',
    publishedComparison: 'ahead',
    tagExists: false,
    releases: [
      { tag_name: 'v2.6.4', published_at: '2026-05-12', html_url: 'stable' },
      { tag_name: 'v2.7.0', published_at: '2026-10-06', prerelease: true, html_url: 'version' },
      { tag_name: 'v2.8.0', published_at: '2026-10-12', draft: true },
    ],
    runs: Object.fromEntries(['core', 'gui', 'mobile', 'test'].map((name, index) => [name, {
      id: index + 1, name, head_sha: 'built', head_branch: 'main',
      event: 'workflow_dispatch', conclusion: 'success', html_url: `run/${index + 1}`,
    }])),
    artifacts: {
      1: [{ id: 10, name: 'easytier-linux-x86_64' }, { id: 11, name: 'Easytier-Magisk' },
        { id: 12, name: 'signpath-unsigned-windows-x86_64' }],
      2: [{ id: 20, name: 'easytier-gui-windows-x86_64' }],
      3: [{ id: 30, name: 'easytier-mobile-android-aarch64' }],
    },
    assets: [],
  };
  const repos = {
    async getBranch() { return { data: { commit: { sha: 'main-head' } } }; },
    async compareCommitsWithBasehead(request) {
      calls.push(['compare', request.basehead]);
      return { data: { status: request.basehead.startsWith('nightly...') ? state.publishedComparison : state.ancestry } };
    },
    listReleases() {},
    listReleaseAssets() {},
    async createRelease(request) {
      calls.push(['create', request]);
      state.release = { id: 100, draft: true, html_url: 'nightly' };
      return { data: state.release };
    },
    async deleteReleaseAsset(request) { calls.push(['delete', request.asset_id]); },
    async uploadReleaseAsset(request) {
      calls.push(['upload', request.name]);
      if (state.uploadFails) throw new Error('Upload failed');
    },
    async updateRelease(request) {
      calls.push(['update', request]);
      Object.assign(state.release, request);
    },
  };
  const actions = {
    async listWorkflowRuns(request) {
      assert.equal(request.branch, 'main');
      assert.equal(request.event, 'workflow_dispatch');
      assert.equal(request.status, 'success');
      const run = state.runs[request.workflow_id.replace('.yml', '')];
      return { data: { workflow_runs: run ? [run] : [] } };
    },
    listWorkflowRunArtifacts() {},
  };
  const github = {
    rest: {
      repos, actions,
      git: {
        async getRef() { if (!state.tagExists) throw notFound(); },
        async createRef(request) { calls.push(['createTag', request.sha]); state.tagExists = true; },
        async updateRef(request) { calls.push(['updateTag', request.sha]); },
      },
    },
    async paginate(method, request, map) {
      if (method === repos.listReleases) {
        return state.releases.concat(state.release ? [{ tag_name: 'nightly', ...state.release }] : []);
      }
      if (method === repos.listReleaseAssets) return state.assets;
      if (method === actions.listWorkflowRunArtifacts) return state.artifacts[request.run_id];
      if (method === repos.compareCommitsWithBasehead) {
        calls.push(['changelog', request.basehead]);
        assert.equal(request.per_page, 100);
        // Exercise the response mapper used to collect every comparison page.
        return map({ data: { commits: [commit('old', '2026-10-10T12:00:00Z')] } })
          .concat(map({ data: { commits: [commit('new', '2026-10-12T12:00:00Z')] } }));
      }
      throw new Error('Unexpected API call');
    },
  };
  const context = { repo: repository, payload: { workflow_run: { head_sha: 'built' } } };
  return { state, calls, github, context, core };
}

function commit(sha, date) {
  return { sha, html_url: `commit/${sha}`, commit: { committer: { date }, message: `${sha} change\n\nDetails` } };
}

test('nightly selects one main commit and uses the last published version, including prereleases', async () => {
  const f = fixture();
  f.state.release = { id: 99, published_at: '2026-10-13' };
  const build = await prepare(f);
  assert.equal(build.sha, 'built');
  assert.deepEqual(build.runs, { core: 1, gui: 2, mobile: 3, test: 4 });
  assert.deepEqual(build.artifacts.core.map(a => a.id), [10, 11]);
  assert.ok(f.calls.some(call => call[0] === 'changelog' && call[1] === 'v2.7.0...built'));
  assert.match(build.body, /Changes since \[v2.7.0\]/);
  assert.ok(build.body.indexOf('2026-10-12') < build.body.indexOf('2026-10-10'));
});

test('nightly waits for every component and the full test run', async () => {
  for (const workflow of ['core', 'gui', 'mobile', 'test']) {
    const f = fixture();
    delete f.state.runs[workflow];
    assert.equal(await prepare(f), null);
  }
});

test('nightly rejects a mismatched commit, branch, event or failed result', async () => {
  for (const field of ['head_sha', 'head_branch', 'event', 'conclusion']) {
    const f = fixture();
    f.state.runs.gui[field] = 'different';
    assert.equal(await prepare(f), null);
  }
});

test('nightly accepts successful failed-job reruns without requiring a new run ID', async () => {
  const f = fixture();
  f.state.runs.gui.run_attempt = 2;
  assert.equal((await prepare(f)).runs.gui, 2);
});

test('nightly refuses missing or expired artifacts before changing a release', async () => {
  for (const artifacts of [[], [{ id: 20, name: 'easytier-gui-windows-x86_64', expired: true }]]) {
    const f = fixture();
    f.state.artifacts[2] = artifacts;
    await assert.rejects(prepare(f), /missing or expired/);
  }
});

test('an older completed run cannot replace a newer nightly or a removed main commit', async () => {
  const f = fixture();
  f.state.ancestry = 'diverged';
  assert.equal(await prepare(f), null);
  f.state.ancestry = 'ahead';
  f.state.release = { id: 100 };
  for (const status of ['behind', 'diverged']) {
    f.state.publishedComparison = status;
    assert.equal(await prepare(f), null);
  }
});

test('duplicate completion events skip a fully published commit', async () => {
  const f = fixture();
  f.state.release = { id: 100, body: 'Commit: [built](url)' };
  f.state.publishedComparison = 'identical';
  assert.equal(await prepare(f), null);
});

test('nightly can resume an initial draft or an interrupted release-note update', async () => {
  const f = fixture();
  f.state.release = { id: 100, draft: true };
  assert.ok(await prepare(f));
  assert.ok(!f.calls.some(call => call[1] === 'nightly...built'));
  f.state.release.draft = false;
  f.state.release.body = 'Commit: [old](url)';
  f.state.publishedComparison = 'identical';
  assert.ok(await prepare(f));
});

test('manual publication checks the current main commit', async () => {
  const f = fixture();
  f.context.payload = {};
  for (const run of Object.values(f.state.runs)) run.head_sha = 'main-head';
  assert.equal((await prepare(f)).sha, 'main-head');
});

test('scheduled publication uses the completed commit even after main advances', async () => {
  const f = fixture();
  f.context.payload = {};
  const build = await prepare({ ...f, sha: 'built' });
  assert.equal(build.sha, 'built');
  assert.ok(f.calls.some(call => call[0] === 'compare' && call[1] === 'built...main-head'));
  assert.deepEqual(build.runs, { core: 1, gui: 2, mobile: 3, test: 4 });
});

test('nightly requires a published version baseline and a mutable release', async () => {
  const f = fixture();
  f.state.releases = [];
  await assert.rejects(prepare(f), /No published version/);
  f.state.release = { immutable: true };
  await assert.rejects(prepare(f), /must allow asset and tag updates/);
});

test('notes date every entry in UTC and sort by timestamp, not input order', () => {
  const notes = releaseNotes(repository, { tag_name: 'v2.7.0', html_url: 'version' }, 'built', [
    commit('middle', '2026-10-12T15:00:00Z'),
    commit('oldest', '2026-10-12T01:00:00+08:00'),
    commit('newest', '2026-10-12T19:00:00Z'),
  ], []);
  assert.match(notes, /2026-10-11 — oldest change/);
  assert.ok(notes.indexOf('newest change') < notes.indexOf('middle change'));
  assert.ok(notes.indexOf('middle change') < notes.indexOf('oldest change'));
  assert.ok(!notes.includes('Details'));
});

async function packageFiles(t, f) {
  const build = await prepare(f);
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'easytier-nightly-test-'));
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  for (const artifact of Object.values(build.artifacts).flat()) {
    await fs.writeFile(path.join(directory, `${artifact.name}.zip`), 'test archive');
  }
  return { ...f, build, directory };
}

test('reruns publish only the newest artifact for each name, ignoring expired older attempts', async t => {
  const f = fixture();
  f.state.artifacts[1].push(
    { id: 13, name: 'easytier-linux-x86_64' },
    { id: 9, name: 'easytier-linux-x86_64', expired: true },
  );
  const args = await packageFiles(t, f);
  assert.deepEqual(args.build.artifacts.core.map(a => a.id), [13, 11]);
  await publish(args);
  assert.equal(f.calls.filter(call => call[0] === 'upload' && call[1] === 'easytier-linux-x86_64.zip').length, 1);
});

test('first publication creates one draft, uploads assets and then publishes a prerelease', async t => {
  const f = fixture();
  await publish(await packageFiles(t, f));
  const creation = f.calls.find(call => call[0] === 'create')[1];
  assert.equal(creation.draft, true);
  assert.equal(creation.prerelease, true);
  assert.equal(creation.make_latest, 'false');
  const update = f.calls.at(-1);
  assert.equal(update[0], 'update');
  assert.equal(update[1].release_id, 100);
  assert.equal(update[1].draft, false);
  assert.equal(update[1].make_latest, 'false');
  assert.ok(f.calls.some(call => call[0] === 'createTag'));
});

test('updates keep the release ID and remove obsolete assets only after uploads finish', async t => {
  const f = fixture();
  f.state.release = { id: 99, draft: false, target_commitish: 'first-build' };
  f.state.tagExists = true;
  f.state.assets = [
    { id: 50, name: 'easytier-linux-x86_64.zip' },
    { id: 51, name: 'retired-platform.zip' },
  ];
  await publish(await packageFiles(t, f));
  assert.ok(!f.calls.some(call => call[0] === 'create' || call[0] === 'createTag'));
  assert.equal(f.calls.at(-1)[1].release_id, 99);
  assert.equal(f.state.release.target_commitish, 'built');
  const lastUpload = f.calls.findLastIndex(call => call[0] === 'upload');
  assert.ok(f.calls.findIndex(call => call[0] === 'delete' && call[1] === 51) > lastUpload);
});

test('incomplete packaging cannot mutate the published release', async t => {
  const f = fixture();
  const args = await packageFiles(t, f);
  await fs.unlink(path.join(args.directory, 'Easytier-Magisk.zip'));
  await assert.rejects(publish(args), /do not match/);
  assert.ok(!f.calls.some(call => ['create', 'delete', 'upload', 'update'].includes(call[0])));
});

test('a failed upload does not advance the tag, notes or draft publication', async t => {
  const f = fixture();
  const args = await packageFiles(t, f);
  f.state.uploadFails = true;
  await assert.rejects(publish(args), /Upload failed/);
  assert.equal(f.state.release.draft, true);
  assert.ok(!f.calls.some(call => ['createTag', 'updateTag', 'update'].includes(call[0])));
});

test('a retry resumes the initial draft after an upload failure without creating another release', async t => {
  const f = fixture();
  const args = await packageFiles(t, f);
  f.state.uploadFails = true;
  await assert.rejects(publish(args), /Upload failed/);
  f.state.uploadFails = false;
  const retry = await prepare(f);
  assert.equal(retry.release_id, 100);
  await publish({ ...args, build: retry });
  assert.equal(f.calls.filter(call => call[0] === 'create').length, 1);
  assert.equal(f.state.release.draft, false);
});

test('publication stops if the release was replaced during artifact downloads', async t => {
  const f = fixture();
  const args = await packageFiles(t, f);
  f.state.release = { id: 999 };
  await assert.rejects(publish(args), /changed during preparation/);
});
