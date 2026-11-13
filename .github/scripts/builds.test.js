const assert = require('node:assert/strict');
const { test } = require('node:test');
const dispatch = require('./nightly-build.js');
const validate = require('./validate-release-builds.js');

const context = { repo: { owner: 'EasyTier', repo: 'EasyTier' } };
const core = { info() {} };
const workflows = ['core.yml', 'gui.yml', 'mobile.yml', 'test.yml'];

function nightly(branches, successfulRuns = {}) {
  const f = { dispatched: [], retried: [], responses: {}, inspected: [], sleeps: 0 };
  const github = {
    paginate: async () => branches,
    rest: {
      repos: { listBranches() {} },
      actions: {
        async listWorkflowRuns(request) {
          assert.equal(request.event, 'workflow_dispatch');
          assert.equal(request.status, 'success');
          const sha = successfulRuns[`${request.branch}/${request.workflow_id}`];
          return { data: { workflow_runs: sha ? [{ head_sha: sha }] : [] } };
        },
        async createWorkflowDispatch(request) {
          assert.equal(request.headers['X-GitHub-Api-Version'], '2026-03-10');
          f.dispatched.push(request);
          return { data: { workflow_run_id: f.dispatched.length, html_url: `run/${f.dispatched.length}` } };
        },
        async getWorkflowRun({ run_id }) {
          const workflow = f.dispatched[run_id - 1].workflow_id;
          f.inspected.push({ workflow, dispatched: f.dispatched.length });
          return { data: {
            head_sha: branches.find(branch => branch.name === 'main').commit.sha,
            status: 'completed', conclusion: 'success', run_attempt: 1,
            ...f.responses[workflow]?.shift(),
          } };
        },
        async reRunWorkflowFailedJobs({ run_id }) {
          f.retried.push(run_id);
        },
      },
    },
  };
  f.run = () => dispatch({ github, context, core, sleep: async delay => {
    assert.equal(delay, 60_000);
    assert.ok(++f.sleeps < 10, 'nightly should eventually finish');
  } });
  return f;
}

test('first nightly builds every workflow on an existing main branch', async () => {
  const f = nightly([{ name: 'main', commit: { sha: 'new' } }]);
  assert.equal(await f.run(), 'new');
  assert.deepEqual(f.dispatched.map(run => run.workflow_id), workflows);
  assert.ok(f.dispatched.every(run => run.ref === 'main'));
  assert.deepEqual(f.dispatched[0].inputs, { sign_windows: false });
  assert.ok(f.dispatched.slice(1).every(run => !run.inputs));
  assert.deepEqual(f.inspected.map(run => run.workflow), workflows);
  assert.ok(f.inspected.every(run => run.dispatched === 4));
});

test('unchanged branches skip builds and unmonitored branches are ignored', async () => {
  const successfulRuns = Object.fromEntries(workflows.map(workflow => [`main/${workflow}`, 'same']));
  const f = nightly([
    { name: 'main', commit: { sha: 'same' } },
    { name: 'feature', commit: { sha: 'new' } },
  ], successfulRuns);
  assert.equal(await f.run(), 'same');
  assert.deepEqual(f.dispatched, []);
  assert.equal(f.sleeps, 0);
});

test('nightly retries a failed component using its last successful commit', async () => {
  const successfulRuns = Object.fromEntries(workflows.map(workflow => [`main/${workflow}`, 'new']));
  successfulRuns['main/gui.yml'] = 'old';
  const f = nightly([{ name: 'main', commit: { sha: 'new' } }], successfulRuns);
  assert.equal(await f.run(), 'new');
  assert.deepEqual(f.dispatched.map(run => run.workflow_id), ['gui.yml']);
});

test('nightly only builds main even when other branches exist', async () => {
  const f = nightly([
    { name: 'main', commit: { sha: 'new' } },
    { name: 'develop', commit: { sha: 'new' } },
    { name: 'feature', commit: { sha: 'new' } },
  ]);
  await f.run();
  assert.deepEqual(f.dispatched.map(run => run.workflow_id), workflows);
  assert.ok(f.dispatched.every(run => run.ref === 'main'));
});

test('nightly waits for every dispatched build before allowing publication', async () => {
  const f = nightly([{ name: 'main', commit: { sha: 'new' } }]);
  f.responses['core.yml'] = [{ status: 'queued' }, { status: 'in_progress' }, {}];
  f.responses['test.yml'] = [{ status: 'in_progress' }, {}];
  assert.equal(await f.run(), 'new');
  assert.equal(f.sleeps, 2);
  assert.deepEqual(f.inspected.map(run => run.workflow), [
    ...workflows, 'core.yml', 'test.yml', 'core.yml',
  ]);
});

test('nightly retries failed jobs once and waits for the new attempt', async () => {
  const f = nightly([{ name: 'main', commit: { sha: 'new' } }]);
  f.responses['gui.yml'] = [
    { conclusion: 'failure' },
    { conclusion: 'failure' }, // The API still returns the first attempt.
    { status: 'in_progress', run_attempt: 2 },
    { run_attempt: 2 },
  ];
  assert.equal(await f.run(), 'new');
  assert.deepEqual(f.retried, [2]);
  assert.equal(f.sleeps, 3);
});

test('nightly fails instead of publishing if a retried build fails again', async () => {
  const f = nightly([{ name: 'main', commit: { sha: 'new' } }]);
  f.responses['mobile.yml'] = [{ conclusion: 'failure' }, { conclusion: 'failure', run_attempt: 2 }];
  await assert.rejects(f.run(), /mobile.yml: run 3 finished with failure/);
  assert.deepEqual(f.retried, [3]);
});

test('nightly does not retry cancelled or timed-out builds', async () => {
  for (const conclusion of ['cancelled', 'timed_out']) {
    const f = nightly([{ name: 'main', commit: { sha: 'new' } }]);
    f.responses['test.yml'] = [{ conclusion }];
    await assert.rejects(f.run(), new RegExp(`test.yml: run 4 finished with ${conclusion}`));
    assert.deepEqual(f.retried, []);
  }
});

test('nightly rejects a dispatch that races with a new main commit', async () => {
  const f = nightly([{ name: 'main', commit: { sha: 'new' } }]);
  f.responses['gui.yml'] = [{ head_sha: 'newer', status: 'queued' }];
  await assert.rejects(f.run(), /main changed while dispatching/);
  assert.deepEqual(f.retried, []);
});

process.env.CORE_RUN_ID = '1';
process.env.GUI_RUN_ID = '2';
process.env.MOBILE_RUN_ID = '3';

function releaseRuns() {
  return ['core.yml', 'gui.yml', 'mobile.yml'].map(workflow => ({
    path: `.github/workflows/${workflow}`,
    conclusion: 'success',
    event: 'workflow_dispatch',
    head_branch: 'main',
    head_sha: 'same',
  }));
}

async function release(runs) {
  const github = {
    rest: {
      actions: {
        async getWorkflowRun({ run_id }) {
          return { data: runs[run_id - 1] };
        },
      },
    },
  };
  return validate({ github, context, core });
}

test('release accepts successful full builds from one commit', async () => {
  await release(releaseRuns());
});

test('release accepts full builds triggered by a release branch push', async () => {
  const runs = releaseRuns();
  runs[0].event = 'push';
  runs[0].head_branch = 'releases/2.7';
  runs[1].event = 'push';
  runs[1].head_branch = 'releases/2.7';
  await release(runs);
});

test('release rejects PR builds and regular branch pushes', async () => {
  for (const event of ['pull_request', 'push']) {
    const runs = releaseRuns();
    runs[0].event = event;
    await assert.rejects(release(runs), /successful full build/);
  }
});

test('release rejects failed and cancelled builds', async () => {
  for (const conclusion of ['failure', 'cancelled']) {
    const runs = releaseRuns();
    runs[1].conclusion = conclusion;
    await assert.rejects(release(runs), /successful full build/);
  }
});

test('release rejects run IDs from the wrong workflow', async () => {
  const runs = releaseRuns();
  runs[1].path = runs[0].path;
  await assert.rejects(release(runs), /successful full build/);
});

test('release rejects builds from different commits', async () => {
  const runs = releaseRuns();
  runs[2].head_sha = 'different';
  await assert.rejects(release(runs), /same commit/);
});
