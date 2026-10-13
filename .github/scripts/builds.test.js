const assert = require('node:assert/strict');
const { test } = require('node:test');
const validate = require('./validate-release-builds.js');

const context = { repo: { owner: 'EasyTier', repo: 'EasyTier' } };
const core = { info() {} };
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

test('release accepts the same successful main nightly for all components', async () => {
  for (const event of ['schedule', 'workflow_dispatch']) {
    const runs = releaseRuns();
    for (const run of runs) {
      run.path = '.github/workflows/nightly.yml';
      run.event = event;
    }
    await release(runs);
  }
});

test('release rejects nightly builds from another branch or event', async () => {
  for (const changes of [{ head_branch: 'feature' }, { event: 'pull_request' }]) {
    const runs = releaseRuns();
    Object.assign(runs[0], { path: '.github/workflows/nightly.yml' }, changes);
    await assert.rejects(release(runs), /successful full build/);
  }
});
