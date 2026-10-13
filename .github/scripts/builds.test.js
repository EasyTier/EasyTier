const assert = require('node:assert/strict');
const { test } = require('node:test');
const dispatch = require('./nightly-build.js');
const validate = require('./validate-release-builds.js');

const context = { repo: { owner: 'EasyTier', repo: 'EasyTier' } };
const core = { info() {} };
const workflows = ['core.yml', 'gui.yml', 'mobile.yml', 'test.yml'];

async function nightly(branches, successfulRuns = {}) {
  const dispatched = [];
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
          dispatched.push(request);
        },
      },
    },
  };
  await dispatch({ github, context, core });
  return dispatched;
}

test('first nightly builds every workflow on an existing main branch', async () => {
  const runs = await nightly([{ name: 'main', commit: { sha: 'new' } }]);
  assert.deepEqual(runs.map(run => run.workflow_id), workflows);
  assert.ok(runs.every(run => run.ref === 'main'));
  assert.deepEqual(runs[0].inputs, { sign_windows: false });
  assert.ok(runs.slice(1).every(run => !run.inputs));
});

test('unchanged branches skip builds and unmonitored branches are ignored', async () => {
  const successfulRuns = Object.fromEntries(workflows.map(workflow => [`main/${workflow}`, 'same']));
  const runs = await nightly([
    { name: 'main', commit: { sha: 'same' } },
    { name: 'feature', commit: { sha: 'new' } },
  ], successfulRuns);
  assert.deepEqual(runs, []);
});

test('nightly retries a failed component using its last successful commit', async () => {
  const successfulRuns = Object.fromEntries(workflows.map(workflow => [`main/${workflow}`, 'new']));
  successfulRuns['main/gui.yml'] = 'old';
  const runs = await nightly([{ name: 'main', commit: { sha: 'new' } }], successfulRuns);
  assert.deepEqual(runs.map(run => run.workflow_id), ['gui.yml']);
});

test('nightly only builds main even when other branches exist', async () => {
  const runs = await nightly([
    { name: 'main', commit: { sha: 'new' } },
    { name: 'develop', commit: { sha: 'new' } },
    { name: 'feature', commit: { sha: 'new' } },
  ]);
  assert.deepEqual(runs.map(run => run.workflow_id), workflows);
  assert.ok(runs.every(run => run.ref === 'main'));
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
